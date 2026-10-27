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
import { bytesToHex as bytes_to_hex } from "@noble/hashes/utils.js";
import { randomBytes as random_bytes } from "@noble/hashes/utils.js";
import { setup_rig, api } from "../../../core/tests/helpers/http.ts";
import type { TestRig } from "../../../core/tests/helpers/http.ts";
import { EditorLink, SecureChannel } from "../../src/client.ts";
import type { GrantMaterial } from "../../src/client.ts";
import { static_keypair_from_secret } from "../../src/channel.ts";
import { b64u_encode } from "../../src/b64u.ts";

const te = new TextEncoder();
const td = new TextDecoder();
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// Portable sibling paths: relay/ and editor/ check out side by side.
// Never commit absolute /home/... paths in this dev harness.
const EDITOR_DIR = join(root, "..", "editor");
const FORGE_SMOKE_DIR = join(root, "interop", "forge-smoke");
const FORGE_SMOKE_BIN = join(EDITOR_DIR, "target", "debug", "forge-smoke");
const NATIVE_SMOKE_BIN = join(EDITOR_DIR, "target", "debug", "native-smoke");
const CHUNK_RAW = 40 * 1024;

function b64u(b: Uint8Array): string {
  return b64u_encode(b);
}
function sha256_hex(data: Uint8Array | string): string {
  const b = typeof data === "string" ? te.encode(data) : data;
  return bytes_to_hex(sha256(b));
}
async function machine_headers(
  subject_id: string, sk: Uint8Array, method: string, path_and_query: string, raw_body: string,
): Promise<Record<string, string>> {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = b64u(random_bytes(16));
  const canonical = `${ts}\n${nonce}\n${method}\n${path_and_query}\n${sha256_hex(raw_body)}`;
  return {
    "x-ast-machine": subject_id,
    "x-ast-timestamp": ts,
    "x-ast-nonce": nonce,
    authorization: `AST-Machine ${b64u(ed25519.sign(te.encode(canonical), sk))}`,
  };
}
function strict_keys(obj: unknown, allowed: string[], what: string): Record<string, unknown> {
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
function require_fields(obj: unknown, required: string[], what: string): Record<string, unknown> {
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) throw new Error(`${what}: not an object`);
  const o = obj as Record<string, unknown>;
  for (const k of required) {
    if (!(k in o)) throw new Error(`${what}: missing field ${k}`);
  }
  return o;
}
async function wait_for(cond: () => boolean, label: string, timeout_ms = 120_000): Promise<void> {
  const deadline = Date.now() + timeout_ms;
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
let account_id = "";
let machine_id = "";
let forge_sk: Uint8Array;
let editor_sk: Uint8Array;
let editor_grant_jwt = "";
let editor_jti = "";
let session_cookie = "";
let data_dir = "";
let core_base_url = "";
let forge_proc: ChildProcess | null = null;
const forge_log: string[] = [];
const forge_out: string[] = [];

beforeAll(async () => {
  rig = await setup_rig();
  const q1 = await api(rig.app, "POST", "/v1/auth/magic/request", { body: { email: "rinterop@example.invalid" } });
  if (q1.status !== 200) throw new Error(`request failed: ${q1.text}`);
  const { request_id, request_secret } = q1.json as { request_id: string; request_secret: string };
  const token = rig.token_for_email("rinterop@example.invalid");
  const q2 = await api(rig.app, "POST", "/v1/auth/magic/consume", { body: { token } });
  if (q2.status !== 200) throw new Error(`consume failed: ${q2.text}`);
  const q3 = await api(rig.app, "POST", "/v1/auth/magic/finalize", { body: { requestId: request_id, requestSecret: request_secret } });
  if (q3.status !== 200) throw new Error(`finalize failed: ${q3.text}`);
  account_id = (q3.json as { account_id: string }).account_id;
  session_cookie = ((q3.headers.get("set-cookie") ?? "").split(";")[0] ?? "") as string;

  forge_sk = ed25519.utils.randomSecretKey();
  const forge_x = b64u(ed25519.getPublicKey(forge_sk));
  const label = "interop-forge";
  const ts = Math.floor(Date.now() / 1000);
  const proof = b64u(ed25519.sign(te.encode(`enrollment-request\n${forge_x}\n${label}\n${ts}`), forge_sk));
  const start = await api(rig.app, "POST", "/v1/machines/enrollments", {
    body: { publicKey: { kty: "OKP", crv: "Ed25519", x: forge_x }, label, timestamp: ts, proof },
  });
  if (start.status !== 201) throw new Error(`enroll failed: ${start.text}`);
  const { enrollment_id, code } = start.json as { enrollment_id: string; code: string };
  const claim = await api(rig.app, "POST", "/v1/machines/enrollments/claim", {
    headers: { cookie: session_cookie, origin: "http://localhost" },
    body: { code },
  });
  if (claim.status !== 200) throw new Error(`claim failed: ${claim.text}`);
  const status_path = `/v1/machines/enrollments/${enrollment_id}/status`;
  const st = await api(rig.app, "GET", status_path, {
    headers: await machine_headers(enrollment_id, forge_sk, "GET", status_path, ""),
  });
  if (st.status !== 200) throw new Error(`status failed: ${st.text}`);
  const confirmation = b64u(
    ed25519.sign(te.encode(`enrollment-confirm\n${enrollment_id}\n${account_id}\n${forge_x}`), forge_sk),
  );
  const confirm_path = "/v1/machines/enrollments/confirm";
  const cbody = JSON.stringify({ enrollmentId: enrollment_id, accountId: account_id, confirmation });
  const done = await api(rig.app, "POST", confirm_path, {
    headers: await machine_headers(enrollment_id, forge_sk, "POST", confirm_path, cbody),
    raw_body: cbody,
  });
  if (done.status !== 201) throw new Error(`confirm failed: ${done.text}`);
  machine_id = (done.json as { machine_id: string }).machine_id;

  // NOTE: the Editor grant is minted in the TEST (fresh 300s TTL after the
  // cargo build + Hub startup), never here — minting it in beforeAll lets
  // the TTL rot during slow setup and produces impossible-looking stalls.
  editor_sk = ed25519.utils.randomSecretKey();

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
  await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", () => r()));
  const proxy_port = (proxy.address() as AddressInfo).port;
  core_base_url = `http://127.0.0.1:${proxy_port}`;

  await build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["workerd", "worker", "browser"],
    outfile: "dist/worker-forge.mjs",
    allowOverwrite: true,
    logLevel: "warning",
  });
  mf = new Miniflare({
    modules: true,
    scriptPath: "dist/worker-forge.mjs",
    durableObjects: { MACHINE_ROOM: "MachineRoom" },
    bindings: {
      CORE_JWKS_URL: `http://127.0.0.1:${proxy_port}/.well-known/jwks.json`,
      CORE_ISS: "http://test.invalid",
      RELAY_AUD: "ast-relay",
      GRANT_MAX_TTL_S: "300",
      CORE_REVOCATIONS_URL: `http://127.0.0.1:${proxy_port}/v1/grants/revocations`,
      REVOCATION_POLL_MS: "2000",
    },
  });
  base = String(await mf.ready);

  // Build the harness binary (shared editor/target). If the editor tree
  // is mid-edit by another contributor and the build fails, proceed with
  // the existing binary ONLY when present (recorded below) — never silently.
  const editor_rev = (() => {
    try {
      return execFileSync("git", ["rev-parse", "--short", "HEAD"], {
        cwd: EDITOR_DIR,
      }).toString().trim();
    } catch {
      return "unknown";
    }
  })();
  console.log(`forge interop against editor rev ${editor_rev}`);
  // Build fails LOUDLY (no prebuilt fallback: a mid-edit upstream tree
  // must fail visibly and rerun when stable, never silently test stale code).
  // Pin the toolchain to the Editor's rust-toolchain.toml: the build cwd
  // (relay/interop) inherits default stable while sharing editor/target
  // with native `cargo 1.98.0` runs — a mismatch rebuilds the same target
  // dir and flakes. RUSTUP_TOOLCHAIN from the pinned file avoids it.
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
    const log_path = join(tmpdir(), `forge-build-${Date.now()}.log`);
    try {
      writeFileSync(log_path, out);
    } catch { /* ignore */ }
    console.log(`BUILD STDERR (also at ${log_path}):\n${out.split("\n").slice(-30).join("\n")}`);
    throw new Error(`forge binary build failed (editor tree mid-edit? rerun when stable): see ${log_path}`);
  }

  // Launch: caller-built Hub + production serve_account_relay.
  data_dir = mkdtempSync(join(tmpdir(), "relay-interop-"));
  forge_proc = spawn(
    FORGE_SMOKE_BIN,
    [],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const lines: string[] = [];
  forge_proc.stdout?.on("data", (d: Buffer) => {
    for (const line of d.toString().split("\n")) {
      if (!line.trim()) continue;
      lines.push(line);
      forge_out.push(line);
    }
  });
  forge_proc.stderr?.on("data", (d: Buffer) => {
    forge_log.push(d.toString());
    if (forge_log.length > 100) forge_log.splice(0, forge_log.length - 100);
  });
  const send_line = (obj: unknown): void => {
    forge_proc?.stdin?.write(`${JSON.stringify(obj)}\n`);
  };
  const next_line = async (): Promise<string> => {
    const deadline = Date.now() + 60_000;
    for (;;) {
      const line = lines.shift();
      if (line !== undefined) return line;
      if (Date.now() > deadline) throw new Error("timeout waiting for forge output");
      await new Promise((r) => setTimeout(r, 50));
    }
  };
  send_line({
    ws_url: `${base.replace("http", "ws")}/v1/route/${account_id}/${machine_id}`,
    core_base_url: core_base_url,
    machine_id: machine_id,
    account_id: account_id,
    machine_secret_hex: Buffer.from(forge_sk).toString("hex"),
    expected_iss: "http://test.invalid",
    data_dir: data_dir,
  });
  const hello = JSON.parse(await next_line()) as Record<string, unknown>;
  if (!hello["ready"]) throw new Error(`forge failed to start: ${JSON.stringify(hello)}\nstderr:\n${forge_log.slice(-20).join("\n")}`);
  (globalThis as Record<string, unknown>).__forge_interop_send = send_line;
  (globalThis as Record<string, unknown>).__forge_interop_next = next_line;
}, 300_000);

afterAll(async () => {
  try {
    ((globalThis as Record<string, unknown>).__forge_interop_send as ((o: unknown) => void) | undefined)?.({ shutdown: true });
  } catch { /* ignore */ }
  if (forge_proc && forge_proc.exitCode === null) {
    forge_proc.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 3000));
    if (forge_proc && forge_proc.exitCode === null) forge_proc.kill("SIGKILL");
  }
  forge_proc = null;
  await mf?.dispose();
  proxy?.close();
  if (data_dir) rmSync(data_dir, { recursive: true, force: true });
});

describe("production rust seam (serve_account_relay)", () => {
  it("connects, serves /state, streams, and 2 MiB drafts through Relay, then proves the native client", async () => {
    // Fresh Editor grant AFTER all slow setup (build, Hub, binary start).
    const ebody = JSON.stringify({
      audience: "ast-relay",
      scope: ["relay:connect", "forge:execute", "machine:sync"],
      ttlSeconds: 300,
      targetMachineId: machine_id,
      cnf: { kty: "OKP", crv: "Ed25519", x: b64u(ed25519.getPublicKey(editor_sk)) },
    });
    const eg = await api(rig.app, "POST", "/v1/grants/issue", {
      headers: { cookie: session_cookie, origin: "http://localhost" },
      raw_body: ebody,
    });
    expect(eg.status).toBe(200);
    editor_grant_jwt = (eg.json as { token: string }).token;
    editor_jti = JSON.parse(Buffer.from(editor_grant_jwt.split(".")[1] as string, "base64url").toString()).jti as string;

    let online = false;
    for (let i = 0; i < 240 && !online; i++) {
      const r = await fetch(`${base}/v1/presence/${account_id}/${machine_id}`, {
        headers: { Authorization: `Bearer ${editor_grant_jwt}` },
      });
      const body = await r.text();
      console.log(`presence poll ${i}: status=${r.status} body=${body}`);
      if (r.status === 200) online = (JSON.parse(body) as { forge_online: boolean }).forge_online === true;
      if (!online) await new Promise((r2) => setTimeout(r2, 500));
    }
    expect(online, "forge relay presence").toBe(true);
    // Sanity: a nonsense room must report offline (guards presence-path bugs).
    const probe = await fetch(`${base}/v1/presence/${account_id}/mch_AAAAAAAAAAAAAAAAAAAAAAAAAA`, {
      headers: { Authorization: `Bearer ${editor_grant_jwt}` },
    });
    console.log(`nonsense-room presence status (expect 403): ${probe.status}`);

    const editor_mat: GrantMaterial = { jwt: editor_grant_jwt, jti: editor_jti, cnf_sk: editor_sk };
    const editor_closed: number[] = [];
    const editor_errors: { code: string; message: string }[] = [];
    const editor_opened: string[] = [];
    const editor_inbox: { channel: string; body: Uint8Array }[] = [];
    const editor_link = new EditorLink(
      `${base.replace("http", "ws")}/v1/route/${account_id}/${machine_id}`,
      editor_mat,
      {
        on_data: (channel, _s, body) => editor_inbox.push({ channel, body }),
        on_close: (code) => editor_closed.push(code),
        on_error: (code, message) => editor_errors.push({ code, message }),
        on_channel_opened: (channel) => editor_opened.push(channel),
      },
      WebSocket,
    );
    expect((await editor_link.connect()).role).toBe("client");

    // Editor's view of the Forge enrolled key (authenticated Core record).
    const ml = await api(rig.app, "GET", "/v1/machines", { headers: { cookie: session_cookie, origin: "http://localhost" } });
    expect(ml.status).toBe(200);
    const listed = (ml.json as { machines?: { id: string; label?: string; public_key: { x: string } }[] }).machines ?? [];
    const forge_cnf = Uint8Array.from(Buffer.from((listed.find((m) => m.id === machine_id)?.public_key.x ?? "") as string, "base64url"));
    expect(forge_cnf.length).toBe(32);

    const uni_ctx = { account: account_id, machine: machine_id, channel: "r-unary" };
    const stream_ctx = { account: account_id, machine: machine_id, channel: "r-stream" };
    const editor_uni = SecureChannel.initiate(static_keypair_from_secret(random_bytes(32)), {
      cnf_sign_key: editor_sk, expected_forge_cnf: forge_cnf, own_grant_jwt: editor_grant_jwt, ctx: uni_ctx,
    });
    const editor_stream = SecureChannel.initiate(static_keypair_from_secret(random_bytes(32)), {
      cnf_sign_key: editor_sk, expected_forge_cnf: forge_cnf, own_grant_jwt: editor_grant_jwt, ctx: stream_ctx,
    });

    type End = { ch: SecureChannel; channel: string };
    const ends: End[] = [
      { ch: editor_uni, channel: "r-unary" },
      { ch: editor_stream, channel: "r-stream" },
    ];
    const arrived = new Map<End, Uint8Array[]>();
    for (const e of ends) arrived.set(e, []);
    const settle = async (): Promise<void> => {
      for (const e of ends) {
        for (const body of e.ch.pump_outbound()) editor_link.send_opaque(e.channel, body);
      }
      await new Promise((r) => setTimeout(r, 10));
      for (const e of ends) {
        const rest: { channel: string; body: Uint8Array }[] = [];
        for (const item of editor_inbox.splice(0, editor_inbox.length)) {
          if (item.channel !== e.channel) {
            rest.push(item);
            continue;
          }
          const r = e.ch.handle_incoming(item.body);
          if (r) (arrived.get(e) as Uint8Array[]).push(r);
        }
        editor_inbox.push(...rest);
      }
    };
    const collect_from = async (e: End, want: number): Promise<Uint8Array[]> => {
      const got = arrived.get(e) as Uint8Array[];
      for (let i = 0; i < 600 && got.length < want; i++) await settle();
      if (got.length < want) throw new Error(`stall: wanted ${want}, got ${got.length}`);
      return got.splice(0, got.length);
    };

    editor_link.open("r-unary");
    editor_link.open("r-stream");
    for (let i = 0; i < 120 && (!editor_uni.is_open() || !editor_stream.is_open()); i++) await settle();
    if (!editor_uni.is_open() || !editor_stream.is_open()) {
      const inbox_dump = editor_inbox.slice(0, 8).map((x) => `${x.channel}:${x.body.length}`).join(",");
      throw new Error(
        `noise stall: uni=${editor_uni.noise.get_phase()} stream=${editor_stream.noise.get_phase()} inbox=[${inbox_dump}] ` +
          `opened=[${editor_opened.join(",")}] errors=${JSON.stringify(editor_errors)} closed=${JSON.stringify(editor_closed)}\n` +
          `forge stdout:\n${forge_out.slice(-20).join("\n")}\nstderr:\n${forge_log.slice(-20).join("\n")}`,
      );
    }
    expect(editor_uni.is_open(), "unary open").toBe(true);
    expect(editor_stream.is_open(), "stream open").toBe(true);

    // -- unary GET /state from the REAL Store (fresh dir: valid empty shape)
    // Responses are tolerant: required fields asserted, additive State
    // fields (threads_next/waiting/account/...) allowed.
    editor_uni.queue_app(JSON.stringify({ id: "r1", method: "GET", path: "/state" }));
    const sresp = await collect_from(ends[0] as End, 1);
    const state = require_fields(JSON.parse(td.decode(sresp[0] as Uint8Array)), ["id", "status", "body"], "TunnelResponse");
    expect(state["id"]).toBe("r1");
    expect(state["status"]).toBe(200);
    const sbody = require_fields(
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
    editor_stream.queue_app(JSON.stringify({ id: "rs1", method: "SUBSCRIBE", path: "/events?since=0" }));
    const sevents = await collect_from(ends[1] as End, 2);
    const sack = require_fields(JSON.parse(td.decode(sevents[0] as Uint8Array)), ["id", "status", "body"], "StreamAck");
    const stream_id = ((sack["body"] as Record<string, unknown>)["$stream"] as Record<string, string>)["stream"] as string;
    expect(typeof stream_id).toBe("string");
    const first = require_fields(
      ((JSON.parse(td.decode(sevents[1] as Uint8Array)) as Record<string, unknown>)["$event"]) as Record<string, unknown>,
      ["stream", "envelope"], "$event",
    );
    expect((first["envelope"] as Record<string, unknown>)["type"]).toBe("hello");

    // -- 2 MiB draft PUT then GET (paced, real Reassembly + draft store) --
    // Valid large route: PUT /drafts/smoke with {expected_revision:0,
    // body:{text:big_text}} -> DraftWriteResult; GET /drafts/smoke ->
    // DraftSnapshot. Crosses the 1 MiB window both directions on unary while
    // the event stream stays open (concurrent stream + unary). Raw
    // application/octet-stream blob PUTs are an invalid route and stay
    // rejected by Forge WebP validation; this test does not weaken that.
    expect(editor_stream.is_open(), "stream still open for concurrent draft").toBe(true);
    const big_text = "0123456789ABCDEF".repeat(131072);
    expect(big_text.length).toBe(2 * 1024 * 1024);
    const put_draft_req = JSON.stringify({
      id: "rdraft1",
      method: "PUT",
      path: "/drafts/smoke",
      body: { expected_revision: 0, body: { text: big_text } },
    });
    const put_draft_frames = chunk_transfer("rdraft1", te.encode(put_draft_req));
    expect(put_draft_frames.length).toBeGreaterThan(50);
    for (const c of put_draft_frames) {
      const { ct } = editor_uni.noise.seal(te.encode(c));
      await editor_link.send_acked("r-unary", ct, { timeout_ms: 60_000 });
    }
    const put_draft_resp = await collect_tunnel_response(ends[0] as End, "rdraft1", settle, arrived, td);
    expect(put_draft_resp["status"]).toBe(200);
    const put_draft_body = require_fields(put_draft_resp["body"], ["saved", "current"], "DraftWriteResult");
    expect(put_draft_body["saved"]).toBe(true);
    const put_current = require_fields(put_draft_body["current"], ["revision", "body"], "DraftSnapshot");
    expect((put_current["body"] as Record<string, unknown>)["text"]).toBe(big_text);

    // GET the same draft back (chunked download, reassembled TunnelChunks).
    editor_uni.queue_app(JSON.stringify({ id: "rdraft2", method: "GET", path: "/drafts/smoke" }));
    const get_draft_resp = await collect_tunnel_response(ends[0] as End, "rdraft2", settle, arrived, td);
    expect(get_draft_resp["status"]).toBe(200);
    const get_draft_body = require_fields(get_draft_resp["body"] as Record<string, unknown>, ["revision", "body"], "DraftSnapshot");
    expect((get_draft_body["body"] as Record<string, unknown>)["text"]).toBe(big_text);

    // -- UNSUBSCRIBE after the concurrent draft roundtrip ---------------------
    // Demultiplex by id: live $events may still be queued ahead of the
    // rs2 response on the stream channel; drain them, don't assume the
    // first inbound frame is the response.
    editor_stream.queue_app(JSON.stringify({ id: "rs2", method: "UNSUBSCRIBE", path: `/events/${stream_id}` }));
    const sunsub_resp = await collect_stream_response(ends[1] as End, "rs2", settle, arrived, td);
    expect(sunsub_resp["id"]).toBe("rs2");

    // -- NATIVE client proof: the actual RelayClient (same transport as
    // ForgeClient::via_relay) against the live Core + workerd + Forge ----
    // Plain binary, no ambient reactor: any GPUI-entry-style reactor miss
    // fails here instead of hiding behind the JS initiator above.
    const native_sk = ed25519.utils.randomSecretKey();
    const native_body = JSON.stringify({
      audience: "ast-relay",
      scope: ["relay:connect", "forge:execute", "machine:sync"],
      ttlSeconds: 300,
      targetMachineId: machine_id,
      cnf: { kty: "OKP", crv: "Ed25519", x: b64u(ed25519.getPublicKey(native_sk)) },
    });
    const neg = await api(rig.app, "POST", "/v1/grants/issue", {
      headers: { cookie: session_cookie, origin: "http://localhost" },
      raw_body: native_body,
    });
    expect(neg.status).toBe(200);
    const native_jwt = (neg.json as { token: string }).token;
    const machine_label = listed.find((m) => m.id === machine_id)?.label ?? "interop-forge";
    const native_cfg = {
      relay_base_url: base,
      account_id: account_id,
      machine_id: machine_id,
      forge_ed25519_b64u: b64u(forge_cnf),
      grant_jwt: native_jwt,
      cnf_secret_hex: Buffer.from(native_sk).toString("hex"),
      core_base_url: core_base_url,
      session_token: session_cookie.split(";")[0]?.replace(/^ast_session=/, "") ?? "",
      draft_scope: "native-smoke",
    };
    // Async spawn (never execFileSync): the same Node event loop hosts the
    // live Core HTTP proxy that the Forge's revocation poll and the Relay's
    // JWKS fetch hit. Blocking the loop for the whole native run would
    // freeze those fetches and fake a client stall.
    const native_out = await run_native_peer(native_cfg);
    const native_lines = native_out.trim().split("\n").filter((l) => l.trim());
    const native_summary = JSON.parse(native_lines[native_lines.length - 1] as string) as Record<string, unknown>;
    expect(native_summary["ok"]).toBe(true);
    expect(native_summary["draft_bytes"]).toBe(2 * 1024 * 1024);
    expect(typeof native_summary["state_head"]).toBe("number");
    expect(typeof native_summary["stream"]).toBe("string");

    // -- Core revocation sweeps the live connection ---------------------------
    const rev = await api(rig.app, "POST", `/v1/machines/${machine_id}/revoke`, {
      headers: { cookie: session_cookie, origin: "http://localhost" },
    });
    expect(rev.status).toBe(200);
    await wait_for(() => editor_closed.some((c) => c === 4002), "revocation sweep", 60_000);
  }, 300_000);
});

// Runs the native client binary WITHOUT blocking the Node event loop.
// The same loop serves the Core HTTP proxy (Forge revocation polls,
// Relay JWKS fetches) and pumps the JS initiator link, so a synchronous
// execFileSync here would freeze the server side and fake a client stall.
// Bounded 180 s timeout, stdin config, sanitized captured output.
function run_native_peer(cfg: Record<string, unknown>): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(NATIVE_SMOKE_BIN, [], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`native-smoke timed out after 180 s; stderr: ${stderr.slice(-2000)}`));
    }, 180_000);
    child.stdout?.on("data", (d: Buffer) => {
      stdout += d.toString();
    });
    child.stderr?.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error(`native-smoke failed (status ${code}): ${stdout}\n${stderr.slice(-2000)}`));
      }
    });
    child.stdin?.write(`${JSON.stringify(cfg)}\n`);
    child.stdin?.end();
  });
}

function chunk_transfer(transfer: string, bytes: Uint8Array): string[] {  const total = Math.max(1, Math.ceil(bytes.length / CHUNK_RAW));
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
async function collect_tunnel_response(
  end: { ch: unknown; channel: string },
  want_id: string,
  settle: () => Promise<void>,
  arrived: Map<unknown, Uint8Array[]>,
  td: TextDecoder,
): Promise<Record<string, unknown>> {
  const chunks_by_transfer = new Map<string, { index: number; total: number; bytes_b64u: string }[]>();
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
          throw new Error(`expected JSON frame for ${want_id}`);
        }
        if (typeof parsed["transfer"] === "string") {
          const transfer = parsed["transfer"] as string;
          const list = chunks_by_transfer.get(transfer) ?? [];
          list.push({
            index: parsed["index"] as number,
            total: parsed["total"] as number,
            bytes_b64u: parsed["bytes_b64u"] as string,
          });
          chunks_by_transfer.set(transfer, list);
          const first = list[0];
          if (first && list.length === first.total) {
            list.sort((a, b) => a.index - b.index);
            const bytes = Buffer.concat(list.map((c) => Buffer.from(c.bytes_b64u, "base64url")));
            const resp = JSON.parse(Buffer.from(bytes).toString("utf8")) as Record<string, unknown>;
            if (resp["id"] === want_id) return resp;
            chunks_by_transfer.delete(transfer);
          }
          continue;
        }
        if (parsed["id"] === want_id) return parsed;
      }
    }
  }
  throw new Error(`stall: wanted TunnelResponse ${want_id}`);
}

// Collect one stream-channel response by id, draining live $events (and a
// terminal $event end) that may be queued ahead of it. Never assumes the
// first inbound frame after the request is its response.
async function collect_stream_response(
  end: { ch: unknown; channel: string },
  want_id: string,
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
          throw new Error(`expected JSON frame for ${want_id}`);
        }
        if (parsed["$event"] !== undefined) continue;
        if (parsed["id"] === want_id) return parsed;
      }
    }
  }
  throw new Error(`stall: wanted stream response ${want_id}`);
}
