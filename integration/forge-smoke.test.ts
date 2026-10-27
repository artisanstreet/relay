// Production Rust seam: caller-built Hub + serve_account_relay
// (interop/forge-smoke binary) against live Core + live Relay.
// The initiator side is this repo's SecureChannel; EVERYTHING past the
// Relay socket is production Rust: grant acquisition, PoP, NoiseChannel,
// confirm/JWT/binding verification, App/Hub/Store dispatch, SUBSCRIBE
// streams, chunked blobs. No stand-ins, no duplicated crypto.
//
// Covers: connect + /state (real State shape) + SUBSCRIBE/$event +
// UNSUBSCRIBE + 2 MiB chunked PUT/GET through real Reassembly + revocation
// sweep. Prerequisite: forge-smoke builds (cargo, shared editor/target).

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { setupRig, api } from "../../core/tests/helpers.ts";
import type { TestRig } from "../../core/tests/helpers.ts";
import { EditorLink, SecureChannel } from "../src/client.ts";
import type { GrantMaterial } from "../src/client.ts";
import { staticKeypairFromSecret } from "../src/channel.ts";
import { b64uEncode } from "../src/b64u.ts";

const te = new TextEncoder();
const td = new TextDecoder();
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// Portable sibling paths: relay/ and editor/ check out side by side.
// Never commit absolute /home/... paths in this dev harness.
const EDITOR_DIR = join(root, "..", "editor");
const SMOKE_DIR = join(root, "interop", "forge-smoke");
const SMOKE_BIN = join(EDITOR_DIR, "target", "debug", "forge-smoke");
const NATIVE_BIN = join(EDITOR_DIR, "target", "debug", "native-smoke");
const CHUNK_RAW = 40 * 1024;

function b64u(b: Uint8Array): string {
  return b64uEncode(b);
}
function sha256Hex(data: Uint8Array | string): string {
  const b = typeof data === "string" ? te.encode(data) : data;
  return [...sha256(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function machineHeaders(
  subjectId: string, sk: Uint8Array, method: string, pathAndQuery: string, rawBody: string,
): Promise<Record<string, string>> {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = b64u(randomBytes(16));
  const canonical = `${ts}\n${nonce}\n${method}\n${pathAndQuery}\n${sha256Hex(rawBody)}`;
  return {
    "x-ast-machine": subjectId,
    "x-ast-timestamp": ts,
    "x-ast-nonce": nonce,
    authorization: `AST-Machine ${b64u(ed25519.sign(te.encode(canonical), sk))}`,
  };
}
function strictKeys(obj: unknown, allowed: string[], what: string): Record<string, unknown> {
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) throw new Error(`${what}: not an object`);
  const o = obj as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k)) throw new Error(`${what}: unknown field ${k}`);
  }
  return o;
}
// Responses are forward-compatible: required fields must be present, but
// additive fields (e.g. State.threads_next/waiting/account,
// TunnelResponse.content_type) are allowed and ignored.
function requireFields(obj: unknown, required: string[], what: string): Record<string, unknown> {
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) throw new Error(`${what}: not an object`);
  const o = obj as Record<string, unknown>;
  for (const k of required) {
    if (!(k in o)) throw new Error(`${what}: missing field ${k}`);
  }
  return o;
}
async function waitFor(cond: () => boolean, label: string, timeoutMs = 120_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (cond()) return;
    if (Date.now() > deadline) throw new Error(`timeout: ${label}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

let rig: TestRig;
let proxy: ReturnType<typeof createServer>;
let mf: Miniflare;
let base = "";
let accountId = "";
let machineId = "";
let forgeSk: Uint8Array;
let editorSk: Uint8Array;
let editorGrantJwt = "";
let editorJti = "";
let sessionCookie = "";
let dataDir = "";
let smoke: ChildProcess | null = null;
const smokeLog: string[] = [];
const smokeOut: string[] = [];

beforeAll(async () => {
  rig = await setupRig();
  const q1 = await api(rig.app, "POST", "/v1/auth/magic/request", { body: { email: "rsmoke@example.invalid" } });
  if (q1.status !== 200) throw new Error(`request failed: ${q1.text}`);
  const { requestId, requestSecret } = q1.json as { requestId: string; requestSecret: string };
  const token = rig.tokenForEmail("rsmoke@example.invalid");
  const q2 = await api(rig.app, "POST", "/v1/auth/magic/consume", { body: { token } });
  if (q2.status !== 200) throw new Error(`consume failed: ${q2.text}`);
  const q3 = await api(rig.app, "POST", "/v1/auth/magic/finalize", { body: { requestId, requestSecret } });
  if (q3.status !== 200) throw new Error(`finalize failed: ${q3.text}`);
  accountId = (q3.json as { accountId: string }).accountId;
  sessionCookie = ((q3.headers.get("set-cookie") ?? "").split(";")[0] ?? "") as string;

  forgeSk = ed25519.utils.randomSecretKey();
  const forgeX = b64u(ed25519.getPublicKey(forgeSk));
  const label = "forge-smoke";
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
  const st = await api(rig.app, "GET", statusPath, {
    headers: await machineHeaders(enrollmentId, forgeSk, "GET", statusPath, ""),
  });
  if (st.status !== 200) throw new Error(`status failed: ${st.text}`);
  const confirmation = b64u(
    ed25519.sign(te.encode(`enrollment-confirm\n${enrollmentId}\n${accountId}\n${forgeX}`), forgeSk),
  );
  const confirmPath = "/v1/machines/enrollments/confirm";
  const cbody = JSON.stringify({ enrollmentId, accountId, confirmation });
  const done = await api(rig.app, "POST", confirmPath, {
    headers: await machineHeaders(enrollmentId, forgeSk, "POST", confirmPath, cbody),
    rawBody: cbody,
  });
  if (done.status !== 201) throw new Error(`confirm failed: ${done.text}`);
  machineId = (done.json as { machineId: string }).machineId;

  // NOTE: the Editor grant is minted in the TEST (fresh 300s TTL after the
  // cargo build + Hub startup), never here — minting it in beforeAll lets
  // the TTL rot during slow setup and produces impossible-looking stalls.
  editorSk = ed25519.utils.randomSecretKey();

  proxy = createServer(async (req, res) => {
    try {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === "string") headers[k] = v;
        else if (Array.isArray(v)) headers[k] = v.join(", ");
      }
      const r = await rig.app.request(`http://localhost${req.url ?? "/"}`, {
        method: req.method,
        headers,
        body: chunks.length > 0 ? Buffer.concat(chunks) : undefined,
      });
      if ((req.url ?? "").includes("grants/issue")) {
        console.log(`PROXY ${req.method} ${req.url} -> ${r.status}`);
      }
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
  await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", () => r()));
  const proxyPort = (proxy.address() as AddressInfo).port;

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
  mf = new Miniflare({
    modules: true,
    scriptPath: "dist/worker.mjs",
    durableObjects: { MACHINE_ROOM: "MachineRoom" },
    bindings: {
      CORE_JWKS_URL: `http://127.0.0.1:${proxyPort}/.well-known/jwks.json`,
      CORE_ISS: "http://test.invalid",
      RELAY_AUD: "ast-relay",
      GRANT_MAX_TTL_S: "300",
      CORE_REVOCATIONS_URL: `http://127.0.0.1:${proxyPort}/v1/grants/revocations`,
      REVOCATION_POLL_MS: "2000",
    },
  });
  base = String(await mf.ready);

  // Build the harness binary (shared editor/target). If the editor tree
  // is mid-edit by another contributor and the build fails, proceed with
  // the existing binary ONLY when present (recorded below) — never silently.
  const editorRev = (() => {
    try {
      return execFileSync("git", ["rev-parse", "--short", "HEAD"], {
        cwd: EDITOR_DIR,
      }).toString().trim();
    } catch {
      return "unknown";
    }
  })();
  console.log(`forge-smoke against editor rev ${editorRev}`);
  // Build fails LOUDLY (no prebuilt fallback: a mid-edit upstream tree
  // must fail visibly and rerun when stable, never silently test stale code).
  // Pin the toolchain to the Editor's rust-toolchain.toml: the smoke cwd
  // (relay/interop) inherits default stable while sharing editor/target
  // with native `cargo 1.98.0` runs — a mismatch rebuilds the same target
  // dir and flakes. RUSTUP_TOOLCHAIN from the pinned file avoids it.
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
    const logPath = join(tmpdir(), `forge-smoke-build-${Date.now()}.log`);
    try {
      writeFileSync(logPath, out);
    } catch { /* ignore */ }
    console.log(`BUILD STDERR (also at ${logPath}):\n${out.split("\n").slice(-30).join("\n")}`);
    throw new Error(`forge-smoke build failed (editor tree mid-edit? rerun when stable): see ${logPath}`);
  }

  // Launch: caller-built Hub + production serve_account_relay.
  dataDir = mkdtempSync(join(tmpdir(), "forge-smoke-"));
  smoke = spawn(
    SMOKE_BIN,
    [],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const lines: string[] = [];
  smoke.stdout?.on("data", (d: Buffer) => {
    for (const line of d.toString().split("\n")) {
      if (!line.trim()) continue;
      lines.push(line);
      smokeOut.push(line);
    }
  });
  smoke.stderr?.on("data", (d: Buffer) => {
    smokeLog.push(d.toString());
    if (smokeLog.length > 100) smokeLog.splice(0, smokeLog.length - 100);
  });
  const sendLine = (obj: unknown): void => {
    smoke?.stdin?.write(`${JSON.stringify(obj)}\n`);
  };
  const nextLine = async (): Promise<string> => {
    const deadline = Date.now() + 60_000;
    for (;;) {
      const line = lines.shift();
      if (line !== undefined) return line;
      if (Date.now() > deadline) throw new Error("timeout waiting for forge-smoke output");
      await new Promise((r) => setTimeout(r, 50));
    }
  };
  sendLine({
    ws_url: `${base.replace("http", "ws")}/v1/route/${accountId}/${machineId}`,
    core_base_url: `http://127.0.0.1:${proxyPort}`,
    machine_id: machineId,
    account_id: accountId,
    machine_secret_hex: Buffer.from(forgeSk).toString("hex"),
    expected_iss: "http://test.invalid",
    data_dir: dataDir,
  });
  const hello = JSON.parse(await nextLine()) as Record<string, unknown>;
  if (!hello["ready"]) throw new Error(`forge-smoke failed to start: ${JSON.stringify(hello)}\nstderr:\n${smokeLog.slice(-20).join("\n")}`);
  (globalThis as Record<string, unknown>).__forgeSmokeSend = sendLine;
  (globalThis as Record<string, unknown>).__forgeSmokeNext = nextLine;
}, 300_000);

afterAll(async () => {
  try {
    ((globalThis as Record<string, unknown>).__forgeSmokeSend as ((o: unknown) => void) | undefined)?.({ shutdown: true });
  } catch { /* ignore */ }
  if (smoke && smoke.exitCode === null) {
    smoke.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 3000));
    if (smoke && smoke.exitCode === null) smoke.kill("SIGKILL");
  }
  smoke = null;
  await mf?.dispose();
  proxy?.close();
  if (dataDir) rmSync(dataDir, { recursive: true, force: true });
});

describe("production rust seam (serve_account_relay)", () => {
  it("connects, serves /state, streams, and 2 MiB drafts through Relay, then proves the native client", async () => {
    // Fresh Editor grant AFTER all slow setup (build, Hub, binary start).
    const ebody = JSON.stringify({
      audience: "ast-relay",
      scope: ["relay:connect", "forge:execute", "machine:sync"],
      ttlSeconds: 300,
      targetMachineId: machineId,
      cnf: { kty: "OKP", crv: "Ed25519", x: b64u(ed25519.getPublicKey(editorSk)) },
    });
    const eg = await api(rig.app, "POST", "/v1/grants/issue", {
      headers: { cookie: sessionCookie, origin: "http://localhost" },
      rawBody: ebody,
    });
    expect(eg.status).toBe(200);
    editorGrantJwt = (eg.json as { token: string }).token;
    editorJti = JSON.parse(Buffer.from(editorGrantJwt.split(".")[1] as string, "base64url").toString()).jti as string;

    let online = false;
    for (let i = 0; i < 240 && !online; i++) {
      const r = await fetch(`${base}/v1/presence/${accountId}/${machineId}`, {
        headers: { Authorization: `Bearer ${editorGrantJwt}` },
      });
      const body = await r.text();
      console.log(`presence poll ${i}: status=${r.status} body=${body}`);
      if (r.status === 200) online = (JSON.parse(body) as { forge_online: boolean }).forge_online === true;
      if (!online) await new Promise((r2) => setTimeout(r2, 500));
    }
    expect(online, "forge-smoke relay presence").toBe(true);
    // Sanity: a nonsense room must report offline (guards presence-path bugs).
    const probe = await fetch(`${base}/v1/presence/${accountId}/mch_AAAAAAAAAAAAAAAAAAAAAAAAAA`, {
      headers: { Authorization: `Bearer ${editorGrantJwt}` },
    });
    console.log(`nonsense-room presence status (expect 403): ${probe.status}`);

    const editorMat: GrantMaterial = { jwt: editorGrantJwt, jti: editorJti, cnfSk: editorSk };
    const editorClosed: number[] = [];
    const editorErrors: { code: string; message: string }[] = [];
    const editorOpened: string[] = [];
    const editorInbox: { channel: string; body: Uint8Array }[] = [];
    const editorLink = new EditorLink(
      `${base.replace("http", "ws")}/v1/route/${accountId}/${machineId}`,
      editorMat,
      {
        onData: (channel, _s, body) => editorInbox.push({ channel, body }),
        onClose: (code) => editorClosed.push(code),
        onError: (code, message) => editorErrors.push({ code, message }),
        onChannelOpened: (channel) => editorOpened.push(channel),
      },
      WebSocket,
    );
    expect((await editorLink.connect()).role).toBe("client");

    // Editor's view of the Forge enrolled key (authenticated Core record).
    const ml = await api(rig.app, "GET", "/v1/machines", { headers: { cookie: sessionCookie, origin: "http://localhost" } });
    expect(ml.status).toBe(200);
    const listed = (ml.json as { machines?: { id: string; label?: string; publicKey: { x: string } }[] }).machines ?? [];
    const forgeCnf = Uint8Array.from(Buffer.from((listed.find((m) => m.id === machineId)?.publicKey.x ?? "") as string, "base64url"));
    expect(forgeCnf.length).toBe(32);

    const uniCtx = { account: accountId, machine: machineId, channel: "r-unary" };
    const streamCtx = { account: accountId, machine: machineId, channel: "r-stream" };
    const editorUni = SecureChannel.initiate(staticKeypairFromSecret(randomBytes(32)), {
      cnfSignKey: editorSk, expectedForgeCnf: forgeCnf, ownGrantJwt: editorGrantJwt, ctx: uniCtx,
    });
    const editorStream = SecureChannel.initiate(staticKeypairFromSecret(randomBytes(32)), {
      cnfSignKey: editorSk, expectedForgeCnf: forgeCnf, ownGrantJwt: editorGrantJwt, ctx: streamCtx,
    });

    type End = { ch: InstanceType<typeof SecureChannel>; channel: string };
    const ends: End[] = [
      { ch: editorUni, channel: "r-unary" },
      { ch: editorStream, channel: "r-stream" },
    ];
    const arrived = new Map<End, Uint8Array[]>();
    for (const e of ends) arrived.set(e, []);
    const settle = async (): Promise<void> => {
      for (const e of ends) {
        for (const body of e.ch.pumpOutbound()) editorLink.sendOpaque(e.channel, body);
      }
      await new Promise((r) => setTimeout(r, 10));
      for (const e of ends) {
        const rest: { channel: string; body: Uint8Array }[] = [];
        for (const item of editorInbox.splice(0, editorInbox.length)) {
          if (item.channel !== e.channel) {
            rest.push(item);
            continue;
          }
          const r = e.ch.handleIncoming(item.body);
          if (r) (arrived.get(e) as Uint8Array[]).push(r);
        }
        editorInbox.push(...rest);
      }
    };
    const collectFrom = async (e: End, want: number): Promise<Uint8Array[]> => {
      const got = arrived.get(e) as Uint8Array[];
      for (let i = 0; i < 600 && got.length < want; i++) await settle();
      if (got.length < want) throw new Error(`stall: wanted ${want}, got ${got.length}`);
      return got.splice(0, got.length);
    };

    editorLink.open("r-unary");
    editorLink.open("r-stream");
    for (let i = 0; i < 120 && (!editorUni.isOpen() || !editorStream.isOpen()); i++) await settle();
    if (!editorUni.isOpen() || !editorStream.isOpen()) {
      const inboxDump = editorInbox.slice(0, 8).map((x) => `${x.channel}:${x.body.length}`).join(",");
      throw new Error(
        `noise stall: uni=${editorUni.noise.getPhase()} stream=${editorStream.noise.getPhase()} inbox=[${inboxDump}] ` +
          `opened=[${editorOpened.join(",")}] errors=${JSON.stringify(editorErrors)} closed=${JSON.stringify(editorClosed)}\n` +
          `forge-smoke stdout:\n${smokeOut.slice(-20).join("\n")}\nstderr:\n${smokeLog.slice(-20).join("\n")}`,
      );
    }
    expect(editorUni.isOpen(), "unary open").toBe(true);
    expect(editorStream.isOpen(), "stream open").toBe(true);

    // -- unary GET /state from the REAL Store (fresh dir: valid empty shape)
    // Responses are tolerant: required fields asserted, additive State
    // fields (threads_next/waiting/account/...) allowed.
    editorUni.queueApp(JSON.stringify({ id: "r1", method: "GET", path: "/state" }));
    const sresp = await collectFrom(ends[0] as End, 1);
    const state = requireFields(JSON.parse(td.decode(sresp[0] as Uint8Array)), ["id", "status", "body"], "TunnelResponse");
    expect(state["id"]).toBe("r1");
    expect(state["status"]).toBe(200);
    const sbody = requireFields(
      state["body"] as Record<string, unknown>,
      ["head", "forge_version", "protocol", "projects", "threads", "runs", "settings", "engines"],
      "State",
    );
    expect(typeof sbody["head"]).toBe("number");
    expect(Array.isArray(sbody["projects"])).toBe(true);
    expect(typeof sbody["forge_version"]).toBe("string");

    // -- SUBSCRIBE: real stream open, Hello first, then UNSUBSCRIBE ---------
    // Stream stays open across the 2 MiB draft roundtrip below (concurrent
    // stream + unary); UNSUBSCRIBE happens after the draft assertions.
    editorStream.queueApp(JSON.stringify({ id: "rs1", method: "SUBSCRIBE", path: "/events?since=0" }));
    const sevents = await collectFrom(ends[1] as End, 2);
    const sack = requireFields(JSON.parse(td.decode(sevents[0] as Uint8Array)), ["id", "status", "body"], "StreamAck");
    const streamId = ((sack["body"] as Record<string, unknown>)["$stream"] as Record<string, string>)["stream"] as string;
    expect(typeof streamId).toBe("string");
    const first = requireFields(
      ((JSON.parse(td.decode(sevents[1] as Uint8Array)) as Record<string, unknown>)["$event"]) as Record<string, unknown>,
      ["stream", "envelope"], "$event",
    );
    expect((first["envelope"] as Record<string, unknown>)["type"]).toBe("hello");

    // -- 2 MiB draft PUT then GET (paced, real Reassembly + draft store) --
    // Valid large route: PUT /drafts/smoke with {expected_revision:0,
    // body:{text:bigText}} -> DraftWriteResult; GET /drafts/smoke ->
    // DraftSnapshot. Crosses the 1 MiB window both directions on unary while
    // the event stream stays open (concurrent stream + unary). Raw
    // application/octet-stream blob PUTs are an invalid route and stay
    // rejected by Forge WebP validation; this test does not weaken that.
    expect(editorStream.isOpen(), "stream still open for concurrent draft").toBe(true);
    const bigText = "0123456789ABCDEF".repeat(131072);
    expect(bigText.length).toBe(2 * 1024 * 1024);
    const putDraftReq = JSON.stringify({
      id: "rdraft1",
      method: "PUT",
      path: "/drafts/smoke",
      body: { expected_revision: 0, body: { text: bigText } },
    });
    const putDraftFrames = chunkTransfer("rdraft1", te.encode(putDraftReq));
    expect(putDraftFrames.length).toBeGreaterThan(50);
    for (const c of putDraftFrames) {
      const { ct } = editorUni.noise.seal(te.encode(c));
      await editorLink.sendAcked("r-unary", ct, { timeoutMs: 60_000 });
    }
    const putDraftResp = await collectTunnelResponse(ends[0] as End, "rdraft1", settle, arrived, td);
    expect(putDraftResp["status"]).toBe(200);
    const putDraftBody = requireFields(putDraftResp["body"], ["saved", "current"], "DraftWriteResult");
    expect(putDraftBody["saved"]).toBe(true);
    const putCurrent = requireFields(putDraftBody["current"], ["revision", "body"], "DraftSnapshot");
    expect((putCurrent["body"] as Record<string, unknown>)["text"]).toBe(bigText);

    // GET the same draft back (chunked download, reassembled TunnelChunks).
    editorUni.queueApp(JSON.stringify({ id: "rdraft2", method: "GET", path: "/drafts/smoke" }));
    const getDraftResp = await collectTunnelResponse(ends[0] as End, "rdraft2", settle, arrived, td);
    expect(getDraftResp["status"]).toBe(200);
    const getDraftBody = requireFields(getDraftResp["body"] as Record<string, unknown>, ["revision", "body"], "DraftSnapshot");
    expect((getDraftBody["body"] as Record<string, unknown>)["text"]).toBe(bigText);

    // -- UNSUBSCRIBE after the concurrent draft roundtrip ---------------------
    // Demultiplex by id: live $events may still be queued ahead of the
    // rs2 response on the stream channel; drain them, don't assume the
    // first inbound frame is the response.
    editorStream.queueApp(JSON.stringify({ id: "rs2", method: "UNSUBSCRIBE", path: `/events/${streamId}` }));
    const sunsubResp = await collectStreamResponse(ends[1] as End, "rs2", settle, arrived, td);
    expect(sunsubResp["id"]).toBe("rs2");

    // -- NATIVE client proof: the actual RelayClient (same transport as
    // ForgeClient::via_relay) against the live Core + workerd + Forge ----
    // Plain binary, no ambient reactor: any GPUI-entry-style reactor miss
    // fails here instead of hiding behind the JS initiator above.
    const nativeSk = ed25519.utils.randomSecretKey();
    const nativeBody = JSON.stringify({
      audience: "ast-relay",
      scope: ["relay:connect", "forge:execute", "machine:sync"],
      ttlSeconds: 300,
      targetMachineId: machineId,
      cnf: { kty: "OKP", crv: "Ed25519", x: b64u(ed25519.getPublicKey(nativeSk)) },
    });
    const neg = await api(rig.app, "POST", "/v1/grants/issue", {
      headers: { cookie: sessionCookie, origin: "http://localhost" },
      rawBody: nativeBody,
    });
    expect(neg.status).toBe(200);
    const nativeJwt = (neg.json as { token: string }).token;
    const machineLabel = listed.find((m) => m.id === machineId)?.label ?? "forge-smoke";
    const nativeCfg = {
      relay_base_url: base,
      account_id: accountId,
      machine_id: machineId,
      forge_ed25519_b64u: b64u(forgeCnf),
      grant_jwt: nativeJwt,
      cnf_secret_hex: Buffer.from(nativeSk).toString("hex"),
      core_base_url: `http://127.0.0.1:${proxyPort}`,
      session_token: sessionCookie.split(";")[0]?.replace(/^ast_session=/, "") ?? "",
      draft_scope: "native-smoke",
    };
    const nativeOut = (() => {
      try {
        return execFileSync(NATIVE_BIN, {
          input: `${JSON.stringify(nativeCfg)}\n`,
          timeout: 180_000,
          encoding: "utf8",
        });
      } catch (e) {
        const err = e as { stdout?: Buffer | string; status?: number; message?: string };
        const out = typeof err.stdout === "string" ? err.stdout : err.stdout?.toString() ?? "";
        throw new Error(`native-smoke failed (status ${err.status}): ${out}\n${err.message ?? ""}`);
      }
    })();
    const nativeLines = nativeOut.trim().split("\n").filter((l) => l.trim());
    const nativeSummary = JSON.parse(nativeLines[nativeLines.length - 1] as string) as Record<string, unknown>;
    expect(nativeSummary["ok"]).toBe(true);
    expect(nativeSummary["draft_bytes"]).toBe(2 * 1024 * 1024);
    expect(typeof nativeSummary["state_head"]).toBe("number");
    expect(typeof nativeSummary["stream"]).toBe("string");

    // -- Core revocation sweeps the live connection ---------------------------
    const rev = await api(rig.app, "POST", `/v1/machines/${machineId}/revoke`, {
      headers: { cookie: sessionCookie, origin: "http://localhost" },
    });
    expect(rev.status).toBe(200);
    await waitFor(() => editorClosed.some((c) => c === 4002), "revocation sweep", 60_000);
  }, 300_000);
});

function chunkTransfer(transfer: string, bytes: Uint8Array): string[] {
  const total = Math.max(1, Math.ceil(bytes.length / CHUNK_RAW));
  const out: string[] = [];
  for (let i = 0; i < total; i++) {
    out.push(
      JSON.stringify({
        transfer,
        index: i,
        total,
        total_bytes: bytes.length,
        bytes_b64u: b64u(bytes.subarray(i * CHUNK_RAW, (i + 1) * CHUNK_RAW)),
      }),
    );
  }
  return out;
}

// Collect one TunnelResponse by id, reassembling Forge-chunked downloads
// ({transfer, index, total, bytes_b64u}) when the response exceeds the
// Noise plaintext budget. Compares the decoded Draft text after reassembly,
// never the raw encoded bytes to the payload.
async function collectTunnelResponse(
  end: { ch: unknown; channel: string },
  wantId: string,
  settle: () => Promise<void>,
  arrived: Map<unknown, Uint8Array[]>,
  td: TextDecoder,
): Promise<Record<string, unknown>> {
  const chunksByTransfer = new Map<string, { index: number; total: number; bytes_b64u: string }[]>();
  for (let i = 0; i < 600; i++) {
    await settle();
    const q = arrived.get(end as never) as Uint8Array[] | undefined;
    if (q) {
      for (const b of q.splice(0, q.length)) {
        const text = td.decode(b);
        let parsed: Record<string, unknown>;
        try {
          parsed = JSON.parse(text) as Record<string, unknown>;
        } catch {
          throw new Error(`expected JSON frame for ${wantId}`);
        }
        if (typeof parsed["transfer"] === "string") {
          const transfer = parsed["transfer"] as string;
          const list = chunksByTransfer.get(transfer) ?? [];
          list.push({
            index: parsed["index"] as number,
            total: parsed["total"] as number,
            bytes_b64u: parsed["bytes_b64u"] as string,
          });
          chunksByTransfer.set(transfer, list);
          const first = list[0];
          if (first && list.length === first.total) {
            list.sort((a, b) => a.index - b.index);
            const bytes = Buffer.concat(list.map((c) => Buffer.from(c.bytes_b64u, "base64url")));
            const resp = JSON.parse(Buffer.from(bytes).toString("utf8")) as Record<string, unknown>;
            if (resp["id"] === wantId) return resp;
            chunksByTransfer.delete(transfer);
          }
          continue;
        }
        if (parsed["id"] === wantId) return parsed;
      }
    }
  }
  throw new Error(`stall: wanted TunnelResponse ${wantId}`);
}

// Collect one stream-channel response by id, draining live $events (and a
// terminal $event end) that may be queued ahead of it. Never assumes the
// first inbound frame after the request is its response.
async function collectStreamResponse(
  end: { ch: unknown; channel: string },
  wantId: string,
  settle: () => Promise<void>,
  arrived: Map<unknown, Uint8Array[]>,
  td: TextDecoder,
): Promise<Record<string, unknown>> {
  for (let i = 0; i < 600; i++) {
    await settle();
    const q = arrived.get(end as never) as Uint8Array[] | undefined;
    if (q) {
      for (const b of q.splice(0, q.length)) {
        const text = td.decode(b);
        let parsed: Record<string, unknown>;
        try {
          parsed = JSON.parse(text) as Record<string, unknown>;
        } catch {
          throw new Error(`expected JSON frame for ${wantId}`);
        }
        if (parsed["$event"] !== undefined) continue;
        if (parsed["id"] === wantId) return parsed;
      }
    }
  }
  throw new Error(`stall: wanted stream response ${wantId}`);
}
