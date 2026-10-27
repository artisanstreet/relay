// Real Workers/Durable Objects integration via Miniflare (workerd).
// Exercises the actual DO stack: hibernatable WebSockets, alarms,
// storage persistence, HTTP routes — with REAL grants against a local
// JWKS stub. Negative behaviors included (auth, expiry, revocation,
// backpressure, cross-room binding).

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { mint_grant, test_core_key, TEST_AUD, TEST_ISS, TEST_KID } from "./helpers.ts";
import { pop_sign } from "../src/e2e.ts";
import { b64u_encode } from "../src/jwt.ts";

let mf: Miniflare;
let jwksServer: ReturnType<typeof createServer>;
let base = "";
const core = test_core_key();
// Mutable Core stub state for the revocation poll test (EXACT Core wire
// shape: camelCase revokedMachineIds/revokedKeyIds/asOf).
const stubRevocations: { revokedMachineIds: string[]; revokedKeyIds: string[]; asOf: string } = {
  revokedMachineIds: [],
  revokedKeyIds: [],
  asOf: new Date().toISOString(),
};

beforeAll(async () => {
  jwksServer = createServer((req, res) => {
    if (req.url === "/v1/grants/revocations") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ v: 1, ...stubRevocations }));
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }],
    }));
  });
  await new Promise<void>((r) => jwksServer.listen(0, "127.0.0.1", () => r()));
  const jwksPort = (jwksServer.address() as AddressInfo).port;

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
      CORE_JWKS_URL: `http://127.0.0.1:${jwksPort}/jwks.json`,
      CORE_ISS: TEST_ISS,
      RELAY_AUD: TEST_AUD,
      GRANT_MAX_TTL_S: "300",
      CORE_REVOCATIONS_URL: `http://127.0.0.1:${jwksPort}/v1/grants/revocations`,
      REVOCATION_POLL_MS: "2000",
    },
  });
  base = String(await mf.ready);
}, 120_000);

afterAll(async () => {
  await mf?.dispose();
  jwksServer?.close();
});

function wsUrl(account: string, machine: string): string {
  return `${base.replace("http", "ws")}/v1/route/${account}/${machine}`;
}

interface WsClient {
  ws: WebSocket;
  received: { data: string }[];
  closed: { code: number; reason: string } | null;
}

function connect(): Promise<WsClient> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl("acct1", "forge1"));
    const c: WsClient = { ws, received: [], closed: null };
    ws.addEventListener("open", () => resolve(c));
    ws.addEventListener("error", () => reject(new Error("ws connect failed")));
    ws.addEventListener("message", (ev) => {
      c.received.push({ data: String((ev as unknown as { data: unknown }).data) });
    });
    ws.addEventListener("close", (ev) => {
      const ce = ev as unknown as { code: number; reason: string };
      c.closed = { code: ce.code, reason: ce.reason };
    });
  });
}

function last(c: WsClient): unknown {
  return JSON.parse(c.received[c.received.length - 1]?.data ?? "null");
}

async function wait_for(cond: () => boolean, label: string): Promise<void> {
  const deadline = Date.now() + 8000;
  for (;;) {
    if (cond()) return;
    if (Date.now() > deadline) throw new Error(`timeout: ${label}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

async function admit(c: WsClient, role: "forge" | "client", grantOpts = {}) {
  const g = await mint_grant(core, { role, account: "acct1", machine: "forge1", ...grantOpts });
  c.ws.send(JSON.stringify({ v: 1, type: "hello", grant: g.jwt }));
  await wait_for(() => c.received.some((m) => JSON.parse(m.data).type === "challenge"), "challenge");
  const ch = c.received.map((m) => JSON.parse(m.data)).find((f) => f.type === "challenge") as { nonce: string };
  const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
  c.ws.send(JSON.stringify({ v: 1, type: "authenticate", jti: g.jti, sig: b64u_encode(pop_sign(g.cnf_sk, nonce, g.jti)) }));
  await wait_for(() => c.received.some((m) => JSON.parse(m.data).type === "ready"), "ready");
  return g;
}

describe("worker stack (miniflare)", () => {
  it("health check", async () => {
    const res = await fetch(`${base}/v1/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, service: "artisan-relay", v: 1 });
  });

  it("presence requires a same-room bearer grant", async () => {
    const anon = await fetch(`${base}/v1/presence/acct1/forge1`);
    expect(anon.status).toBe(401);
    const other = await mint_grant(core, { account: "acct-evil", machine: "forge1" });
    const cross = await fetch(`${base}/v1/presence/acct1/forge1`, {
      headers: { Authorization: `Bearer ${other.jwt}` },
    });
    expect(cross.status).toBe(403);
    const ok = await mint_grant(core, {});
    const good = await fetch(`${base}/v1/presence/acct1/forge1`, {
      headers: { Authorization: `Bearer ${ok.jwt}` },
    });
    expect(good.status).toBe(200);
    const body = (await good.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ v: 1, forge_online: false, clients: 0 });
  });

  it("admits forge + client over real websockets and routes data", async () => {
    const f = await connect();
    const c = await connect();
    await admit(f, "forge", { scope: ["relay:connect", "forge:execute", "machine:sync"] });
    await admit(c, "client");
    c.ws.send(JSON.stringify({ v: 1, type: "open", channel: "ws-ch" }));
    await wait_for(() => f.received.some((m) => JSON.parse(m.data).type === "channel-opened"), "channel-opened");
    const body = Buffer.from("opaque-bytes").toString("base64url");
    c.ws.send(JSON.stringify({ v: 1, type: "data", channel: "ws-ch", seq: 0, body }));
    await wait_for(
      () => f.received.some((m) => { const f2 = JSON.parse(m.data); return f2.type === "data" && f2.body === body; }),
      "data routed",
    );
    // Auto-ack path is exercised by client.ts, not raw sockets; ack manually:
    f.ws.send(JSON.stringify({ v: 1, type: "ack", channel: "ws-ch", seq: 0 }));
    f.ws.close();
    c.ws.close();
  });

  it("rejects cross-room grants with a 4403 close", async () => {
    const c = await connect();
    const g = await mint_grant(core, { machine: "other-forge" });
    c.ws.send(JSON.stringify({ v: 1, type: "hello", grant: g.jwt }));
    await wait_for(() => c.closed !== null, "close");
    expect(c.closed?.code).toBe(4403);
  });

  it("closes connections whose grant expires (per-frame, no alarm needed)", async () => {
    const c = await connect();
    const iat = Math.floor(Date.now() / 1000);
    await admit(c, "client", { iat, exp: iat + 5 });
    await new Promise((r) => setTimeout(r, 6000));
    c.ws.send(JSON.stringify({ v: 1, type: "pong", t: Date.now() }));
    await wait_for(() => c.closed !== null, "expiry close");
    expect(c.closed?.code).toBe(4401);
  });

  it("revocation poll closes live connections and sticks for new ones", async () => {
    const c = await connect();
    const g = await admit(c, "client");
    // Revoke by cnf key using Core's exact field names.
    stubRevocations.revokedKeyIds = [Buffer.from(g.cnf_pk).toString("base64url")];
    await wait_for(() => c.closed !== null, "revocation close");
    expect(c.closed?.code).toBe(4002);
    // Re-entry with the same (now revoked) key is rejected at hello.
    const c2 = await connect();
    c2.ws.send(JSON.stringify({ v: 1, type: "hello", grant: g.jwt }));
    await wait_for(() => c2.closed !== null, "revoked re-entry");
    expect(c2.closed?.code).toBe(4002);
    stubRevocations.revokedKeyIds = [];
  }, 60_000);

  it("unacked flood gets backpressure errors, room stays bounded", async () => {
    const f = await connect();
    const c = await connect();
    await admit(f, "forge", { scope: ["relay:connect"] });
    await admit(c, "client");
    c.ws.send(JSON.stringify({ v: 1, type: "open", channel: "flood" }));
    await wait_for(() => c.received.some((m) => JSON.parse(m.data).type === "channel-opened"), "open");
    for (let i = 0; i < 70; i++) {
      c.ws.send(JSON.stringify({ v: 1, type: "data", channel: "flood", seq: i, body: "eA" }));
    }
    await wait_for(
      () => c.received.some((m) => { const f2 = JSON.parse(m.data); return f2.type === "error" && f2.code === "backpressure"; }),
      "backpressure",
    );
    expect(c.closed).toBeNull();
    const dataAtForge = f.received.filter((m) => JSON.parse(m.data).type === "data").length;
    expect(dataAtForge).toBeLessThanOrEqual(64);
    f.ws.close();
    c.ws.close();
  });
});
