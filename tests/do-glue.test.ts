// Durable Object glue regressions: hibernation wake-up, new connections
// after eviction, concurrent-load safety, and storage-failure paths.
//
// Uses faked hibernation primitives (WebSocketPair, storage, sockets) to
// drive the REAL MachineRoom code (fetch/webSocketMessage/alarm). What the
// fakes do NOT prove is workerd's actual eviction timing — stated honestly
// in docs/NOTES.md. What they DO prove: restore-before-serve, single
// shared load, fail-closed storage errors, and ordered retries.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MachineRoom } from "../src/index.ts";
import type { Env } from "../src/index.ts";
import type { RoomSnapshot } from "../src/room.ts";
import { mintGrant, testCoreKey, TEST_AUD, TEST_ISS, TEST_KID } from "./helpers.ts";
import { popSign } from "../src/e2e.ts";
import { b64uEncode } from "../src/jwt.ts";

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

class FakeWs {
  attachment: unknown = null;
  sent: string[] = [];
  closed: { code?: number; reason?: string } | null = null;
  constructor(public name: string) {}
  serializeAttachment(a: unknown): void {
    this.attachment = a;
  }
  deserializeAttachment(): unknown {
    return this.attachment;
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(code?: number, reason?: string): void {
    this.closed = { code, reason };
  }
}

class FakePair {
  0: FakeWs;
  1: FakeWs;
  constructor() {
    this[0] = new FakeWs("client");
    this[1] = new FakeWs("server");
  }
}

/** workerd allows 101 + webSocket; undici does not — stub for glue tests. */
class StubResponse {
  status: number;
  webSocket: unknown;
  headers: Headers;
  private body: string;
  constructor(body: string | null, init: { status?: number; headers?: Record<string, string>; webSocket?: unknown } = {}) {
    this.body = body ?? "";
    this.status = init.status ?? 200;
    this.webSocket = init.webSocket;
    this.headers = new Headers(init.headers);
  }
  static json(obj: unknown, init: { status?: number } = {}): StubResponse {
    return new StubResponse(JSON.stringify(obj), {
      status: init.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  }
  async json(): Promise<unknown> {
    return JSON.parse(this.body);
  }
  async text(): Promise<string> {
    return this.body;
  }
}

class FakeStorage {
  data = new Map<string, unknown>();
  alarms: (number | null)[] = [];
  failGet = false;
  failPut = false;
  getCalls = 0;
  putCalls = 0;
  async get<T>(key: string): Promise<T | undefined> {
    this.getCalls++;
    if (this.failGet) throw new Error("storage get failed");
    return this.data.get(key) as T | undefined;
  }
  async put(key: string, value: unknown): Promise<void> {
    this.putCalls++;
    if (this.failPut) throw new Error("storage put failed");
    this.data.set(key, value);
  }
  async setAlarm(t: number): Promise<void> {
    this.alarms.push(t);
  }
  async deleteAlarm(): Promise<void> {
    this.alarms.push(null);
  }
  async getAlarm(): Promise<number | null> {
    return null;
  }
}

class FakeState {
  storage = new FakeStorage();
  sockets: FakeWs[] = [];
  waited: Promise<unknown>[] = [];
  acceptWebSocket(ws: FakeWs): void {
    this.sockets.push(ws);
  }
  getWebSockets(): FakeWs[] {
    return this.sockets.filter((s) => !s.closed);
  }
  waitUntil(p: Promise<unknown>): void {
    this.waited.push(p);
    p.catch(() => {});
  }
}

const core = testCoreKey();
const JWKS = { keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }] };

function env(): Env {
  return {
    MACHINE_ROOM: {} as Env["MACHINE_ROOM"],
    CORE_JWKS_URL: "https://core.test/.well-known/jwks.json",
    CORE_ISS: TEST_ISS,
    RELAY_AUD: TEST_AUD,
    GRANT_MAX_TTL_S: "300",
    CORE_REVOCATIONS_URL: "http://127.0.0.1:1/rev",
    REVOCATION_POLL_MS: "60000",
  };
}

/** Scoped global fetch stub: JWKS only, everything else delegates. */
let realFetch: typeof fetch;
let realResponse: typeof Response;
function stubGlobalFetch(): void {
  realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: unknown) => {
    const url = String(input);
    if (url === "https://core.test/.well-known/jwks.json") {
      return new Response(JSON.stringify(JWKS), { status: 200, headers: { "content-type": "application/json" } });
    }
    return realFetch(input as never, init as never);
  }) as typeof fetch;
}

/** Drain all waitUntil promises (chained persists may add more). */
async function settled(state: FakeState): Promise<void> {
  for (let i = 0; i < 20 && state.waited.length > 0; i++) {
    const batch = state.waited.splice(0, state.waited.length);
    await Promise.allSettled(batch);
  }
}

function asWs(s: FakeWs): WebSocket {
  return s as unknown as WebSocket;
}

function frames(ws: FakeWs): unknown[] {
  return ws.sent.map((m) => JSON.parse(m));
}

async function upgrade(do_: MachineRoom, account = "acct1", machine = "forge1"): Promise<FakeWs> {
  const req = new Request(`https://relay/room/${account}/${machine}`, {
    headers: { Upgrade: "websocket" },
  });
  const res = await do_.fetch(req);
  expect(res.status).toBe(101);
  const state = (do_ as unknown as { state: FakeState }).state;
  const server = state.sockets[state.sockets.length - 1] as FakeWs;
  if (!server) throw new Error("no server socket accepted");
  return server;
}

async function authedServer(
  do_: MachineRoom,
  server: FakeWs,
  role: "forge" | "client",
  grantOpts = {},
): Promise<{ jti: string }> {
  const g = await mintGrant(core, { role, account: "acct1", machine: "forge1", ...grantOpts });
  await do_.webSocketMessage(asWs(server), JSON.stringify({ v: 1, type: "hello", grant: g.jwt }));
  const ch = frames(server).find((f) => (f as { type: string }).type === "challenge") as { nonce: string };
  if (!ch) throw new Error(`no challenge; got ${JSON.stringify(frames(server))}`);
  const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
  await do_.webSocketMessage(    asWs(server),
    JSON.stringify({ v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) }),
  );
  const ready = frames(server).some((f) => (f as { type: string }).type === "ready");
  if (!ready) throw new Error(`no ready; got ${JSON.stringify(frames(server))}`);
  return { jti: g.jti };
}

beforeEach(() => {
  (globalThis as Record<string, unknown>)["WebSocketPair"] = FakePair;
  realResponse = globalThis.Response;
  (globalThis as Record<string, unknown>)["Response"] = StubResponse;
  stubGlobalFetch();
});

afterEach(() => {
  globalThis.fetch = realFetch;
  globalThis.Response = realResponse;
  delete (globalThis as Record<string, unknown>)["WebSocketPair"];
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("DO hibernation glue", () => {
  it("new connection after eviction restores members/channels (no discard)", async () => {
    const state = new FakeState();
    const a = new MachineRoom(state as never, env());
    const forgeSock = await upgrade(a);
    await authedServer(a, forgeSock, "forge");
    await a.webSocketMessage(asWs(forgeSock), JSON.stringify({ v: 1, type: "pong", t: Date.now() }));
    await settled(state);
    const snap = state.storage.data.get("relay:room:v1") as RoomSnapshot | undefined;
    expect(snap?.conns.length).toBe(1);

    // "Eviction": fresh instance, same storage + live sockets.
    const b = new MachineRoom(state as never, env());
    const clientSock = await upgrade(b);
    // The restored forge must still be a member: presence + routing work
    // without any re-hello from the old socket.
    await authedServer(b, clientSock, "client");
    await b.webSocketMessage(asWs(clientSock), JSON.stringify({ v: 1, type: "open", channel: "ch1" }));
    await settled(state);
    await b.webSocketMessage(      asWs(clientSock),
      JSON.stringify({ v: 1, type: "data", channel: "ch1", seq: 0, body: "eA" }),
    );
    const atForge = frames(forgeSock).filter((f) => (f as { type: string }).type === "data");
    expect(atForge.length).toBe(1);
    // Old socket speaks without re-authenticating.
    await b.webSocketMessage(      asWs(forgeSock),
      JSON.stringify({ v: 1, type: "data", channel: "ch1", seq: 0, body: "eA" }),
    );
    const atClient = frames(clientSock).filter((f) => (f as { type: string }).type === "data");
    expect(atClient.length).toBe(1);
    await settled(state);
    const snap2 = state.storage.data.get("relay:room:v1") as RoomSnapshot;
    expect(snap2.conns.length).toBe(2);
    expect(snap2.channels.length).toBe(1);
  });

  it("concurrent wake-up shares a single load (no double restore)", async () => {
    const state = new FakeState();
    const a = new MachineRoom(state as never, env());
    const forgeSock = await upgrade(a);
    await authedServer(a, forgeSock, "forge");
    await settled(state);
    expect(state.storage.getCalls).toBeGreaterThan(0);
    state.storage.getCalls = 0;

    const b = new MachineRoom(state as never, env());
    // N concurrent messages on the old socket with a cold instance.
    await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        b.webSocketMessage(asWs(forgeSock), JSON.stringify({ v: 1, type: "pong", t: Date.now() + i })),
      ),
    );
    // Exactly one storage read served all eight (shared load promise).
    expect(state.storage.getCalls).toBe(1);
    const snap = state.storage.data.get("relay:room:v1") as RoomSnapshot | undefined;
    expect(snap?.conns.length).toBe(1);
  });

  it("room mismatch never clobbers another room's snapshot", async () => {
    const state = new FakeState();
    const a = new MachineRoom(state as never, env());
    const forgeSock = await upgrade(a);
    void forgeSock;
    await authedServer(a, forgeSock, "forge");
    await settled(state);
    const before = JSON.stringify(state.storage.data.get("relay:room:v1"));
    expect(before).toContain("forge1");

    // Same storage, different room id: must 400, never overwrite.
    const b = new MachineRoom(state as never, env());
    const res = await b.fetch(
      new Request("https://relay/room/acct1/other-forge", { headers: { Upgrade: "websocket" } }),
    );
    expect(res.status).toBe(400);
    expect(JSON.stringify(state.storage.data.get("relay:room:v1"))).toBe(before);
    // The loaded (non-clobbered) room still serves its own id with members.
    const clientSock = await upgrade(b);
    await authedServer(b, clientSock, "client");
    const ready = frames(clientSock).find((f) => (f as { type: string }).type === "ready") as {
      forge_online: boolean;
    };
    expect(ready.forge_online).toBe(true);
  });

  it("storage failure on fetch is a 500 with retry (never a fresh room)", async () => {
    const state = new FakeState();
    const a = new MachineRoom(state as never, env());
    const forgeSock = await upgrade(a);
    await authedServer(a, forgeSock, "forge");
    await settled(state);
    const before = JSON.stringify(state.storage.data.get("relay:room:v1"));

    state.storage.failGet = true;
    const b = new MachineRoom(state as never, env());
    const bad = await b.fetch(
      new Request("https://relay/room/acct1/forge1", { headers: { Upgrade: "websocket" } }),
    );
    expect(bad.status).toBe(500);
    // Authority untouched: persisted snapshot unchanged (no fresh-room clobber).
    expect(JSON.stringify(state.storage.data.get("relay:room:v1"))).toBe(before);

    // Storage recovers: the SAME instance retries successfully.
    state.storage.failGet = false;
    const good = await b.fetch(
      new Request("https://relay/room/acct1/forge1", { headers: { Upgrade: "websocket" } }),
    );
    expect(good.status).toBe(101);
    // Old member survived (restored, still routable).
    await b.webSocketMessage(      asWs(forgeSock),
      JSON.stringify({ v: 1, type: "pong", t: Date.now() }),
    );
    expect(forgeSock.closed).toBeNull();
  });

  it("storage failure on message fails closed with 1011 (no fresh room)", async () => {
    const state = new FakeState();
    const a = new MachineRoom(state as never, env());
    const forgeSock = await upgrade(a);
    await authedServer(a, forgeSock, "forge");
    await settled(state);
    const before = JSON.stringify(state.storage.data.get("relay:room:v1"));

    state.storage.failGet = true;
    const b = new MachineRoom(state as never, env());
    await b.webSocketMessage(asWs(forgeSock), JSON.stringify({ v: 1, type: "pong", t: Date.now() }));
    expect(forgeSock.closed?.code).toBe(1011);
    // No fresh room persisted on failed load (snapshot unchanged).
    expect(JSON.stringify(state.storage.data.get("relay:room:v1"))).toBe(before);
  });

  it("failed persist restores dirtiness and retries on later flush", async () => {
    const state = new FakeState();
    const a = new MachineRoom(state as never, env());
    const forgeSock = await upgrade(a);
    await authedServer(a, forgeSock, "forge");
    const clientSock = await upgrade(a);
    await authedServer(a, clientSock, "client");
    await settled(state);
    // Break storage, then mutate (client opens ch1): the failed save must
    // not lose the change.
    state.storage.failPut = true;
    await a.webSocketMessage(asWs(clientSock), JSON.stringify({ v: 1, type: "open", channel: "ch1" }));
    await settled(state);
    const stale = state.storage.data.get("relay:room:v1") as RoomSnapshot;
    expect(stale.channels.length).toBe(0); // failed save: still the admission snapshot
    // Fail-closed boundary: live sockets are closed (clients reconnect and
    // re-hello with fresh grants) rather than diverging from storage.
    expect(forgeSock.closed?.code).toBe(1011);
    expect(clientSock.closed?.code).toBe(1011);
    // Dirtiness restored (behavioral proof below): the next flush after
    // recovery persists the LATEST state, including ch1 from the failed pass.
    // Storage recovers: the next flush persists the LATEST state,
    // including the change from the failed pass.
    state.storage.failPut = false;
    await a.webSocketMessage(asWs(clientSock), JSON.stringify({ v: 1, type: "open", channel: "ch2" }));
    await settled(state);
    const snap = state.storage.data.get("relay:room:v1") as RoomSnapshot;
    expect(snap.channels.map((c) => c.name).sort()).toEqual(["ch1", "ch2"]);
  });
});
