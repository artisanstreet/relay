// Shared dev-only harness for browser integration tests.
// Stands up the production-shape stack on loopback, mirroring
// integration/forge-smoke.test.ts (which stays untouched):
//   real Core Hono app + PGlite (core tests helpers) with the BUILT web
//   bundle as its asset backend (so the REAL Core CSP applies),
//   real Miniflare/workerd Relay bound at Core's JWKS/revocations endpoints
//   with RELAY_PORTAL_ORIGIN set to the portal under test,
//   production Rust forge-smoke binary as the Forge (isolated Hub/Store).
// Used only by test files in this directory. No production imports:
// sibling references are test-harness/build only.

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { setupRig, api } from "../../core/tests/helpers.ts";
import type { TestRig } from "../../core/tests/helpers.ts";

const te = new TextEncoder();
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const CORE_WEB_DIST = join(root, "..", "core", "web", "dist");
const EDITOR_DIR = join(root, "..", "editor");
const SMOKE_DIR = join(root, "interop", "forge-smoke");
const SMOKE_BIN = join(EDITOR_DIR, "target", "debug", "forge-smoke");

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".map": "application/json",
  ".txt": "text/plain; charset=utf-8",
  ".ico": "image/x-icon",
  ".webp": "image/webp",
};

function b64u(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 8192) s += String.fromCharCode(...b.subarray(i, i + 8192));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function sha256Hex(data: string): string {
  return [...sha256(te.encode(data))].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export interface BrowserHarness {
  rig: TestRig;
  /** Same-origin portal serving the built SPA with Core's real CSP. */
  portalBase: string;
  relayBase: string;
  relayWsBase: string;
  accountId: string;
  machineId: string;
  forgeSk: Uint8Array;
  /** Session cookie for the harness account (owns machineId) — use for grants. */
  sessionCookie: string;
  harnessEmail: string;
  close(): Promise<void>;
}

export async function setupBrowserHarness(email = "browser-smoke@example.invalid"): Promise<BrowserHarness> {
  if (!existsSync(join(CORE_WEB_DIST, "index.html"))) {
    throw new Error(`core/web/dist is missing: run \`npm run build\` in core/web first (got ${CORE_WEB_DIST})`);
  }

  // Portal origin first: the SPA shell, the mailed confirm URLs, and the
  // Relay's portal allowlist all key off it.
  const distFiles = new Map<string, { body: Buffer; type: string }>();
  {
    const { readdirSync, statSync, readFileSync: readSync } = await import("node:fs");
    const walk = (dir: string, base: string): void => {
      for (const e of readdirSync(dir)) {
        const full = join(dir, e);
        const rel = `${base}/${e}`;
        if (statSync(full).isDirectory()) walk(full, rel);
        else distFiles.set(rel, { body: readSync(full), type: MIME[extname(e)] ?? "application/octet-stream" });
      }
    };
    walk(CORE_WEB_DIST, "");
  }

  const assets = {
    fetch: async (req: Request): Promise<Response> => {
      const u = new URL(req.url);
      const p = u.pathname === "/" ? "/index.html" : decodeURIComponent(u.pathname);
      const hit = distFiles.get(p);
      if (!hit) return new Response("not found", { status: 404 });
      return new Response(new Uint8Array(hit.body).slice().buffer as ArrayBuffer, {
        status: 200,
        headers: { "content-type": hit.type, "cache-control": p === "/index.html" ? "no-store" : "public, max-age=31536000, immutable" },
      });
    },
  };

  // Portal: a thin same-origin front for the REAL Core app. Every request
  // (API and app shell alike) forwards to rig.app, so the browser
  // exercises Core's real routes, real cookies, and real shell CSP.
  // The forwarded URL uses portalBase as its origin so the server's
  // same-origin Origin check (sessionForMutation) sees matching
  // Origin vs request URL for browser cookie-auth mutations.
  const rigRef: { app?: TestRig["app"]; base?: string } = {};
  const portal = createServer(async (req, res) => {
    try {
      const u = new URL(req.url ?? "/", "http://portal");
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === "string") headers[k] = v;
        else if (Array.isArray(v)) headers[k] = v.join(", ");
      }
      const base = rigRef.base ?? "http://localhost";
      const r = await rigRef.app!.request(`${base}${u.pathname}${u.search}`, {
        method: req.method,
        headers,
        body: chunks.length > 0 ? Buffer.concat(chunks) : undefined,
      });
      const text = await r.text();
      const outHeaders: Record<string, string> = {};
      r.headers.forEach((v, k) => {
        outHeaders[k] = v;
      });
      res.writeHead(r.status, outHeaders);
      res.end(text);
    } catch (e) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(e) }));
    }
  });
  await new Promise<void>((r) => portal.listen(0, "127.0.0.1", () => r()));
  const portalPort = (portal.address() as AddressInfo).port;
  const portalBase = `http://127.0.0.1:${portalPort}`;

  const rig = await setupRig({
    vars: {
      CORE_PUBLIC_BASE_URL: portalBase,
      CORE_SPA_APPROVE_PATH: "/#/approve",
    },
    assets,
  });
  rigRef.app = rig.app;
  rigRef.base = portalBase;

  // The machine enrollment needs an account first (Node-side magic flow;
  // the browser test performs its OWN login later against the same rig).
  const q1 = await api(rig.app, "POST", "/v1/auth/magic/request", { body: { email } });
  if (q1.status !== 200) throw new Error(`request failed: ${q1.text}`);
  const { requestId, requestSecret } = q1.json as { requestId: string; requestSecret: string };
  const token = rig.tokenForEmail(email);
  const q2 = await api(rig.app, "POST", "/v1/auth/magic/consume", { body: { token } });
  if (q2.status !== 200) throw new Error(`consume failed: ${q2.text}`);
  const q3 = await api(rig.app, "POST", "/v1/auth/magic/finalize", { body: { requestId, requestSecret } });
  if (q3.status !== 200) throw new Error(`finalize failed: ${q3.text}`);
  const accountId = (q3.json as { accountId: string }).accountId;
  const sessionCookie = ((q3.headers.get("set-cookie") ?? "").split(";")[0] ?? "") as string;

  const forgeSk = ed25519.utils.randomSecretKey();
  const forgeX = b64u(ed25519.getPublicKey(forgeSk));
  const label = "browser-smoke-forge";
  const ts = Math.floor(Date.now() / 1000);
  const proof = b64u(ed25519.sign(te.encode(`enrollment-request\n${forgeX}\n${label}\n${ts}`), forgeSk));
  const start = await api(rig.app, "POST", "/v1/machines/enrollments", {
    body: { publicKey: { kty: "OKP", crv: "Ed25519", x: forgeX }, label, timestamp: ts, proof },
  });
  if (start.status !== 201) throw new Error(`enroll failed: ${start.text}`);
  const { enrollmentId, code } = start.json as { enrollmentId: string; code: string };
  const claim = await api(rig.app, "POST", "/v1/machines/enrollments/claim", {
    headers: { cookie: sessionCookie, origin: "http://localhost" },
    body: { code },
  });
  if (claim.status !== 200) throw new Error(`claim failed: ${claim.text}`);
  const statusPath = `/v1/machines/enrollments/${enrollmentId}/status`;
  const machineHeaders = async (subjectId: string, method: string, pathAndQuery: string, rawBody: string) => {
    const t = String(Math.floor(Date.now() / 1000));
    const nonce = b64u(randomBytes(16));
    const canonical = `${t}\n${nonce}\n${method}\n${pathAndQuery}\n${sha256Hex(rawBody)}`;
    return {
      "x-ast-machine": subjectId,
      "x-ast-timestamp": t,
      "x-ast-nonce": nonce,
      authorization: `AST-Machine ${b64u(ed25519.sign(te.encode(canonical), forgeSk))}`,
    };
  };
  const st = await api(rig.app, "GET", statusPath, {
    headers: await machineHeaders(enrollmentId, "GET", statusPath, ""),
  });
  if (st.status !== 200) throw new Error(`status failed: ${st.text}`);
  const confirmation = b64u(
    ed25519.sign(te.encode(`enrollment-confirm\n${enrollmentId}\n${accountId}\n${forgeX}`), forgeSk),
  );
  const confirmPath = "/v1/machines/enrollments/confirm";
  const cbody = JSON.stringify({ enrollmentId, accountId, confirmation });
  const done = await api(rig.app, "POST", confirmPath, {
    headers: await machineHeaders(enrollmentId, "POST", confirmPath, cbody),
    rawBody: cbody,
  });
  if (done.status !== 201) throw new Error(`confirm failed: ${done.text}`);
  const machineId = (done.json as { machineId: string }).machineId;

  await build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["workerd", "worker", "browser"],
    outfile: "dist/worker.mjs",
    allowOverwrite: true,
    logLevel: "warning",
  });
  const mf = new Miniflare({
    modules: true,
    scriptPath: "dist/worker.mjs",
    durableObjects: { MACHINE_ROOM: "MachineRoom" },
    bindings: {
      CORE_JWKS_URL: `${portalBase}/.well-known/jwks.json`,
      CORE_ISS: "http://test.invalid",
      RELAY_AUD: "ast-relay",
      GRANT_MAX_TTL_S: "300",
      CORE_REVOCATIONS_URL: `${portalBase}/v1/grants/revocations`,
      REVOCATION_POLL_MS: "2000",
      RELAY_PORTAL_ORIGIN: portalBase,
    },
  });
  const relayBase = String(await mf.ready);
  const relayWsBase = relayBase.replace("http", "ws");
  // Core's CSP allowlist points at the real Relay origin (set once the
  // Miniflare URL is known; per-request reads pick it up).
  rig.setVar("CORE_RELAY_ORIGIN", relayBase);

  // Production Rust Forge binary (shared editor/target). Build fails LOUDLY.
  const pinnedToolchain = (() => {
    try {
      const text = readFileSync(join(EDITOR_DIR, "rust-toolchain.toml"), "utf8");
      const m = text.match(/channel\s*=\s*"([^"]+)"/);
      return m?.[1] ?? null;
    } catch {
      return null;
    }
  })();
  try {
    execFileSync("cargo", ["build", "--offline"], {
      cwd: SMOKE_DIR,
      env: {
        ...process.env,
        CARGO_TARGET_DIR: join(EDITOR_DIR, "target"),
        ...(pinnedToolchain ? { RUSTUP_TOOLCHAIN: pinnedToolchain } : {}),
      },
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 300_000,
    });
  } catch (e) {
    const out = (e as { stderr?: Buffer }).stderr?.toString() ?? String(e);
    throw new Error(`forge-smoke build failed (editor tree mid-edit? rerun when stable):\n${out.split("\n").slice(-30).join("\n")}`);
  }
  const dataDir = mkdtempSync(join(tmpdir(), "browser-smoke-"));
  const smoke: ChildProcess = spawn(
    SMOKE_BIN,
    [],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const lines: string[] = [];
  smoke.stdout?.on("data", (d: Buffer) => {
    for (const line of d.toString().split("\n")) if (line.trim()) lines.push(line);
  });
  const nextLine = async (): Promise<string> => {
    const deadline = Date.now() + 60_000;
    for (;;) {
      const line = lines.shift();
      if (line !== undefined) return line;
      if (Date.now() > deadline) throw new Error("timeout waiting for forge-smoke output");
      await new Promise((r) => setTimeout(r, 50));
    }
  };
  smoke.stdin?.write(
    `${JSON.stringify({
      ws_url: `${relayWsBase}/v1/route/${accountId}/${machineId}`,
      core_base_url: portalBase,
      machine_id: machineId,
      account_id: accountId,
      machine_secret_hex: Buffer.from(forgeSk).toString("hex"),
      expected_iss: "http://test.invalid",
      data_dir: dataDir,
    })}\n`,
  );
  const hello = JSON.parse(await nextLine()) as Record<string, unknown>;
  if (!hello["ready"]) throw new Error(`forge-smoke failed to start: ${JSON.stringify(hello)}`);

  return {
    rig,
    portalBase,
    relayBase,
    relayWsBase,
    accountId,
    machineId,
    forgeSk,
    sessionCookie,
    harnessEmail: email,
    close: async () => {
      try {
        smoke.stdin?.write(`${JSON.stringify({ shutdown: true })}\n`);
      } catch { /* ignore */ }
      await new Promise((r) => setTimeout(r, 1000));
      try {
        if (smoke.exitCode === null) smoke.kill("SIGTERM");
      } catch { /* ignore */ }
      await new Promise((r) => setTimeout(r, 3000));
      try {
        if (smoke.exitCode === null) smoke.kill("SIGKILL");
      } catch { /* ignore */ }
      await mf?.dispose().catch(() => undefined);
      await new Promise<void>((r) => portal.close(() => r()));
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}
