// Shared dev-only harness for browser integration tests.
// Stands up the production-shape stack on loopback, mirroring
// tests/integration/forge.test.ts:
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
import { bytesToHex as bytes_to_hex } from "@noble/hashes/utils.js";
import { randomBytes as random_bytes } from "@noble/hashes/utils.js";
import { b64u_encode as b64u } from "../../src/b64u.ts";
import { setup_rig, api } from "../../../core/tests/helpers/http.ts";
import type { TestRig } from "../../../core/tests/helpers/http.ts";

const te = new TextEncoder();
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CORE_WEB_DIST = join(root, "..", "core", "web", "dist");
const EDITOR_DIR = join(root, "..", "editor");
const FORGE_SMOKE_DIR = join(root, "interop", "forge-smoke");
const FORGE_SMOKE_BIN = join(EDITOR_DIR, "target", "debug", "forge-smoke");

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

function sha256_hex(data: string): string {
  return bytes_to_hex(sha256(te.encode(data)));
}

export interface BrowserHarness {
  rig: TestRig;
  /** Same-origin portal serving the built SPA with Core's real CSP. */
  portal_base: string;
  relay_base: string;
  relay_ws_base: string;
  account_id: string;
  machine_id: string;
  forge_sk: Uint8Array;
  /** Session cookie for the harness account (owns machine_id) — use for grants. */
  session_cookie: string;
  harness_email: string;
  close(): Promise<void>;
}

export async function setup_browser_harness(email = "browser-interop@example.invalid"): Promise<BrowserHarness> {
  if (!existsSync(join(CORE_WEB_DIST, "index.html"))) {
    throw new Error(`core/web/dist is missing: run \`npm run build\` in core/web first (got ${CORE_WEB_DIST})`);
  }

  // Portal origin first: the SPA shell, the mailed confirm URLs, and the
  // Relay's portal allowlist all key off it.
  const dist_files = new Map<string, { body: Buffer; type: string }>();
  {
    const { readdirSync, statSync, readFileSync: read_sync } = await import("node:fs");
    const walk = (dir: string, base: string): void => {
      for (const e of readdirSync(dir)) {
        const full = join(dir, e);
        const rel = `${base}/${e}`;
        if (statSync(full).isDirectory()) walk(full, rel);
        else dist_files.set(rel, { body: read_sync(full), type: MIME[extname(e)] ?? "application/octet-stream" });
      }
    };
    walk(CORE_WEB_DIST, "");
  }

  const assets = {
    fetch: async (req: Request): Promise<Response> => {
      const u = new URL(req.url);
      const p = u.pathname === "/" ? "/index.html" : decodeURIComponent(u.pathname);
      const hit = dist_files.get(p);
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
  // The forwarded URL uses portal_base as its origin so the server's
  // same-origin Origin check (sessionForMutation) sees matching
  // Origin vs request URL for browser cookie-auth mutations.
  const rig_ref: { app?: TestRig["app"]; base?: string } = {};
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
      const base = rig_ref.base ?? "http://localhost";
      const r = await rig_ref.app!.request(`${base}${u.pathname}${u.search}`, {
        method: req.method,
        headers,
        body: chunks.length > 0 ? Buffer.concat(chunks) : undefined,
      });
      const text = await r.text();
      const out_headers: Record<string, string> = {};
      r.headers.forEach((v, k) => {
        out_headers[k] = v;
      });
      res.writeHead(r.status, out_headers);
      res.end(text);
    } catch (e) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(e) }));
    }
  });
  await new Promise<void>((r) => portal.listen(0, "127.0.0.1", () => r()));
  const portal_port = (portal.address() as AddressInfo).port;
  const portal_base = `http://127.0.0.1:${portal_port}`;

  const rig = await setup_rig({
    vars: {
      CORE_PUBLIC_BASE_URL: portal_base,
      CORE_SPA_APPROVE_PATH: "/#/approve",
    },
    assets,
  });
  rig_ref.app = rig.app;
  rig_ref.base = portal_base;

  // The machine enrollment needs an account first (Node-side magic flow;
  // the browser test performs its OWN login later against the same rig).
  const q1 = await api(rig.app, "POST", "/v1/auth/magic/request", { body: { email } });
  if (q1.status !== 200) throw new Error(`request failed: ${q1.text}`);
  const { requestId: request_id, requestSecret: request_secret } = q1.json as { requestId: string; requestSecret: string };
  const token = rig.token_for_email(email);
  const q2 = await api(rig.app, "POST", "/v1/auth/magic/consume", { body: { token } });
  if (q2.status !== 200) throw new Error(`consume failed: ${q2.text}`);
  const q3 = await api(rig.app, "POST", "/v1/auth/magic/finalize", { body: { requestId: request_id, requestSecret: request_secret } });
  if (q3.status !== 200) throw new Error(`finalize failed: ${q3.text}`);
  const account_id = (q3.json as { accountId: string }).accountId;
  const session_cookie = ((q3.headers.get("set-cookie") ?? "").split(";")[0] ?? "") as string;

  const forge_sk = ed25519.utils.randomSecretKey();
  const forge_x = b64u(ed25519.getPublicKey(forge_sk));
  const label = "interop-forge";
  const ts = Math.floor(Date.now() / 1000);
  const proof = b64u(ed25519.sign(te.encode(`enrollment-request\n${forge_x}\n${label}\n${ts}`), forge_sk));
  const start = await api(rig.app, "POST", "/v1/machines/enrollments", {
    body: { publicKey: { kty: "OKP", crv: "Ed25519", x: forge_x }, label, timestamp: ts, proof },
  });
  if (start.status !== 201) throw new Error(`enroll failed: ${start.text}`);
  const { enrollmentId: enrollment_id, code } = start.json as { enrollmentId: string; code: string };
  const claim = await api(rig.app, "POST", "/v1/machines/enrollments/claim", {
    headers: { cookie: session_cookie, origin: "http://localhost" },
    body: { code },
  });
  if (claim.status !== 200) throw new Error(`claim failed: ${claim.text}`);
  const status_path = `/v1/machines/enrollments/${enrollment_id}/status`;
  const machine_headers = async (subject_id: string, method: string, path_and_query: string, raw_body: string) => {
    const t = String(Math.floor(Date.now() / 1000));
    const nonce = b64u(random_bytes(16));
    const canonical = `${t}\n${nonce}\n${method}\n${path_and_query}\n${sha256_hex(raw_body)}`;
    return {
      "x-ast-machine": subject_id,
      "x-ast-timestamp": t,
      "x-ast-nonce": nonce,
      authorization: `AST-Machine ${b64u(ed25519.sign(te.encode(canonical), forge_sk))}`,
    };
  };
  const st = await api(rig.app, "GET", status_path, {
    headers: await machine_headers(enrollment_id, "GET", status_path, ""),
  });
  if (st.status !== 200) throw new Error(`status failed: ${st.text}`);
  const confirmation = b64u(
    ed25519.sign(te.encode(`enrollment-confirm\n${enrollment_id}\n${account_id}\n${forge_x}`), forge_sk),
  );
  const confirm_path = "/v1/machines/enrollments/confirm";
  const cbody = JSON.stringify({ enrollmentId: enrollment_id, accountId: account_id, confirmation });
  const done = await api(rig.app, "POST", confirm_path, {
    headers: await machine_headers(enrollment_id, "POST", confirm_path, cbody),
    raw_body: cbody,
  });
  if (done.status !== 201) throw new Error(`confirm failed: ${done.text}`);
  const machine_id = (done.json as { machineId: string }).machineId;

  await build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["workerd", "worker", "browser"],
    outfile: "dist/worker-harness.mjs",
    allowOverwrite: true,
    logLevel: "warning",
  });
  const mf = new Miniflare({
    modules: true,
    scriptPath: "dist/worker-harness.mjs",
    durableObjects: { MACHINE_ROOM: "MachineRoom" },
    bindings: {
      CORE_JWKS_URL: `${portal_base}/.well-known/jwks.json`,
      CORE_ISS: "http://test.invalid",
      RELAY_AUD: "ast-relay",
      GRANT_MAX_TTL_S: "300",
      CORE_REVOCATIONS_URL: `${portal_base}/v1/grants/revocations`,
      REVOCATION_POLL_MS: "2000",
      RELAY_PORTAL_ORIGIN: portal_base,
    },
  });
  const relay_base = String(await mf.ready);
  const relay_ws_base = relay_base.replace("http", "ws");
  // Core's CSP allowlist points at the real Relay origin (set once the
  // Miniflare URL is known; per-request reads pick it up).
  rig.set_var("CORE_RELAY_ORIGIN", relay_base);

  // Production Rust Forge binary (shared editor/target). Build fails LOUDLY.
  const pinned_toolchain = (() => {
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
      cwd: FORGE_SMOKE_DIR,
      env: {
        ...process.env,
        CARGO_TARGET_DIR: join(EDITOR_DIR, "target"),
        ...(pinned_toolchain ? { RUSTUP_TOOLCHAIN: pinned_toolchain } : {}),
      },
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 300_000,
    });
  } catch (e) {
    const out = (e as { stderr?: Buffer }).stderr?.toString() ?? String(e);
    throw new Error(`forge-smoke build failed (editor tree mid-edit? rerun when stable):\n${out.split("\n").slice(-30).join("\n")}`);
  }
  const data_dir = mkdtempSync(join(tmpdir(), "relay-interop-"));
  const forge_proc: ChildProcess = spawn(
    FORGE_SMOKE_BIN,
    [],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const lines: string[] = [];
  forge_proc.stdout?.on("data", (d: Buffer) => {
    for (const line of d.toString().split("\n")) if (line.trim()) lines.push(line);
  });
  const next_line = async (): Promise<string> => {
    const deadline = Date.now() + 60_000;
    for (;;) {
      const line = lines.shift();
      if (line !== undefined) return line;
      if (Date.now() > deadline) throw new Error("timeout waiting for forge output");
      await new Promise((r) => setTimeout(r, 50));
    }
  };
  forge_proc.stdin?.write(
    `${JSON.stringify({
      ws_url: `${relay_ws_base}/v1/route/${account_id}/${machine_id}`,
      core_base_url: portal_base,
      machine_id: machine_id,
      account_id: account_id,
      machine_secret_hex: Buffer.from(forge_sk).toString("hex"),
      expected_iss: "http://test.invalid",
      data_dir: data_dir,
    })}\n`,
  );
  const hello = JSON.parse(await next_line()) as Record<string, unknown>;
  if (!hello["ready"]) throw new Error(`forge failed to start: ${JSON.stringify(hello)}`);

  return {
    rig,
    portal_base,
    relay_base,
    relay_ws_base,
    account_id,
    machine_id,
    forge_sk,
    session_cookie,
    harness_email: email,
    close: async () => {
      try {
        forge_proc.stdin?.write(`${JSON.stringify({ shutdown: true })}\n`);
      } catch { /* ignore */ }
      await new Promise((r) => setTimeout(r, 1000));
      try {
        if (forge_proc.exitCode === null) forge_proc.kill("SIGTERM");
      } catch { /* ignore */ }
      await new Promise((r) => setTimeout(r, 3000));
      try {
        if (forge_proc.exitCode === null) forge_proc.kill("SIGKILL");
      } catch { /* ignore */ }
      await mf?.dispose().catch(() => undefined);
      await new Promise<void>((r) => portal.close(() => r()));
      rmSync(data_dir, { recursive: true, force: true });
    },
  };
}
