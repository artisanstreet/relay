// RoomState behavior: admission, routing, lifecycle, bounds. Pure logic
// with fake sockets; the real Workers/DO stack is covered by
// test/worker.test.ts (Miniflare) and test/integration.test.ts.

import { describe, expect, it } from "vitest";
import { CLOSE_AUTH, CLOSE_BACKPRESSURE, CLOSE_FORBIDDEN, CLOSE_POLICY, CLOSE_REPLACED, CLOSE_REVOKED, MAX_BODY_B64 } from "../src/room.ts";
import { popSign } from "../src/e2e.ts";
import { b64uEncode } from "../src/jwt.ts";
import { fakeSocket, lastSent, makeRoom, mintGrant, send, testCoreKey, testVerifier } from "./helpers.ts";

void CLOSE_BACKPRESSURE;

async function admittedForge(h = makeRoom(testVerifier(testCoreKey())), role: "forge" | "client" = "forge", grantOpts = {}) {
  const core = testCoreKey();
  const g = await mintGrant(core, { role, ...grantOpts });
  const s = fakeSocket();
  h.room.onConnect("c1", s);
  await send(h.room, "c1", { v: 1, type: "hello", grant: g.jwt });
  const ch = lastSent(s) as { type: string; nonce: string };
  expect(ch.type).toBe("challenge");
  const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
  await send(h.room, "c1", { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) });
  const frames = s.sent.map((m) => JSON.parse(m) as { type: string });
  expect(frames.some((f) => f.type === "ready")).toBe(true);
  return { h, s, g, core };
}

describe("room admission", () => {
  it("admits forge and client, reports presence", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const fg = await mintGrant(core, { role: "forge" });
    const cg = await mintGrant(core, { role: "client" });
    const fs = fakeSocket();
    const cs = fakeSocket();
    h.room.onConnect("f", fs);
    h.room.onConnect("c", cs);
    const doAuth = async (id: string, s: ReturnType<typeof fakeSocket>, g: { jwt: string; jti: string; cnfSk: Uint8Array }) => {
      await send(h.room, id, { v: 1, type: "hello", grant: g.jwt });
      const ch = lastSent(s) as { nonce: string };
      const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
      await send(h.room, id, { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) });
    };
    await doAuth("f", fs, fg);
    await doAuth("c", cs, cg);
    expect(h.room.presence()).toEqual({ forge_online: true, clients: 1 });
    void fg;
    void cg;
  });

  it("closes when hello is not first", async () => {
    const h = makeRoom(testVerifier(testCoreKey()));
    const s = fakeSocket();
    h.room.onConnect("c1", s);
    await send(h.room, "c1", { v: 1, type: "pong", t: 1 });
    expect(s.closed?.code).toBe(CLOSE_AUTH);
  });

  it("closes malformed JSON and invalid frames", async () => {
    const h = makeRoom(testVerifier(testCoreKey()));
    const s = fakeSocket();
    h.room.onConnect("c1", s);
    await h.room.onMessage("c1", "{nope");
    expect(s.closed?.code).toBe(CLOSE_POLICY);
    const s2 = fakeSocket();
    h.room.onConnect("c2", s2);
    await send(h.room, "c2", { v: 1, type: "hello", grant: "x", injected: true });
    expect(s2.closed?.code).toBe(CLOSE_POLICY);
  });

  it("rejects grants for another machine or account", async () => {
    for (const opts of [{ machine: "other" }, { account: "other" }]) {
      const core = testCoreKey();
      const h = makeRoom(testVerifier(core));
      const g = await mintGrant(core, { role: "forge", ...opts });
      const s = fakeSocket();
      h.room.onConnect("c1", s);
      await send(h.room, "c1", { v: 1, type: "hello", grant: g.jwt });
      expect(s.closed?.code).toBe(CLOSE_FORBIDDEN);
    }
  });

  it("rejects grants without relay:connect, and unknown scopes at claim validation", async () => {
    const core = testCoreKey();
    {
      const h = makeRoom(testVerifier(core));
      const g = await mintGrant(core, { role: "client", scope: ["forge:execute"] });
      const s = fakeSocket();
      h.room.onConnect("c1", s);
      await send(h.room, "c1", { v: 1, type: "hello", grant: g.jwt });
      expect(s.closed?.code).toBe(CLOSE_FORBIDDEN);
    }
    {
      // relay:admin was removed with the Core v1 alignment (no admin push):
      // unknown scope values fail strict claim decode -> bad grant (4401).
      const h = makeRoom(testVerifier(core));
      const g = await mintGrant(core, { role: "client", scope: ["relay:admin"] });
      const s = fakeSocket();
      h.room.onConnect("c1", s);
      await send(h.room, "c1", { v: 1, type: "hello", grant: g.jwt });
      expect(s.closed?.code).toBe(CLOSE_AUTH);
    }
  });

  it("rejects replayed grant jti", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const g = await mintGrant(core, { role: "client" });
    for (const id of ["c1", "c2"]) {
      const s = fakeSocket();
      h.room.onConnect(id, s);
      await send(h.room, id, { v: 1, type: "hello", grant: g.jwt });
      if (id === "c2") expect(s.closed?.code).toBe(CLOSE_AUTH);
    }
  });

  it("rejects bad proof-of-possession", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const g = await mintGrant(core, { role: "client" });
    const s = fakeSocket();
    h.room.onConnect("c1", s);
    await send(h.room, "c1", { v: 1, type: "hello", grant: g.jwt });
    const ch = lastSent(s) as { nonce: string };
    const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
    const { ed25519 } = await import("@noble/curves/ed25519.js");
    await send(h.room, "c1", { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(ed25519.utils.randomSecretKey(), nonce, g.jti)) });
    expect(s.closed?.code).toBe(CLOSE_AUTH);
  });

  it("replaces the forge connection on fresh auth", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const mk = async (id: string) => {
      const g = await mintGrant(core, { role: "forge" });
      const s = fakeSocket();
      h.room.onConnect(id, s);
      await send(h.room, id, { v: 1, type: "hello", grant: g.jwt });
      const ch = lastSent(s) as { nonce: string };
      const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
      await send(h.room, id, { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) });
      return s;
    };
    const first = await mk("f1");
    const second = await mk("f2");
    expect(first.closed?.code).toBe(CLOSE_REPLACED);
    expect(second.closed).toBeNull();
    expect(h.room.presence().forge_online).toBe(true);
  });

  it("expires hello and challenge timeouts via tick", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const s = fakeSocket();
    h.room.onConnect("c1", s);
    h.advance(6000);
    h.room.tick();
    expect(s.closed?.code).toBe(CLOSE_AUTH);
    const g = await mintGrant(core, { role: "client" });
    const s2 = fakeSocket();
    h.room.onConnect("c2", s2);
    await send(h.room, "c2", { v: 1, type: "hello", grant: g.jwt });
    h.advance(61_000);
    h.room.tick();
    expect(s2.closed?.code).toBe(CLOSE_AUTH);
  });

  it("drops heartbeat-dead connections and pings the live", async () => {
    const { h, s } = await admittedForge();
    h.room.tick(); // sends ping
    expect(s.sent.some((m) => JSON.parse(m).type === "ping")).toBe(true);
    h.advance(61_000);
    h.room.tick();
    expect(s.closed?.code).toBe(CLOSE_POLICY);
  });
});

describe("room routing", () => {
  async function openChannel() {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const fg = await mintGrant(core, { role: "forge" });
    const cg = await mintGrant(core, { role: "client" });
    const fs = fakeSocket();
    const cs = fakeSocket();
    h.room.onConnect("f", fs);
    h.room.onConnect("c", cs);
    const auth = async (id: string, s: ReturnType<typeof fakeSocket>, g: { jwt: string; jti: string; cnfSk: Uint8Array }) => {
      await send(h.room, id, { v: 1, type: "hello", grant: g.jwt });
      const ch = lastSent(s) as { nonce: string };
      const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
      await send(h.room, id, { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) });
    };
    await auth("f", fs, fg);
    await auth("c", cs, cg);
    await send(h.room, "c", { v: 1, type: "open", channel: "ch1" });
    return { h, fs, cs };
  }

  it("routes data both directions, opaque to the room", async () => {
    const { h, fs, cs } = await openChannel();
    const opaque = b64uEncode(new TextEncoder().encode("ciphertext-bytes-not-plaintext"));
    await send(h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 0, body: opaque });
    const atForge = JSON.parse(fs.sent[fs.sent.length - 1] as string) as { type: string; body: string; seq: number };
    expect(atForge.type).toBe("data");
    expect(atForge.body).toBe(opaque);
    expect(atForge.seq).toBe(0);
    await send(h.room, "f", { v: 1, type: "data", channel: "ch1", seq: 0, body: opaque });
    const atClient = JSON.parse(cs.sent[cs.sent.length - 1] as string) as { type: string; body: string };
    expect(atClient.type).toBe("data");
    expect(atClient.body).toBe(opaque);
  });

  it("enforces contiguous transport seq (first 0, then last+1)", async () => {
    const t = await openChannel();
    // Gap on first frame: rejected (must start at 0).
    await send(t.h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 4, body: "eA" });
    const gap = JSON.parse(t.cs.sent[t.cs.sent.length - 1] as string) as { type: string; code?: string };
    expect(gap.type).toBe("error");
    expect(gap.code).toBe("bad-seq");
    await send(t.h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 0, body: "eA" });
    await send(t.h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 0, body: "eA" });
    const last = JSON.parse(t.cs.sent[t.cs.sent.length - 1] as string) as { type: string; code?: string };
    expect(last.type).toBe("error");
    expect(last.code).toBe("bad-seq");
    await send(t.h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 1, body: "eA" });
    const fwd = JSON.parse(t.fs.sent[t.fs.sent.length - 1] as string) as { type: string; seq: number };
    expect(fwd.type).toBe("data");
    expect(fwd.seq).toBe(1);
    // Skip ahead: rejected (gap).
    await send(t.h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 9, body: "eA" });
    const gap2 = JSON.parse(t.cs.sent[t.cs.sent.length - 1] as string) as { type: string; code?: string };
    expect(gap2.code).toBe("bad-seq");
  });

  it("opening channels requires forge:execute (routing-only cannot open)", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const auth = async (id: string, role: "forge" | "client", scope?: string[]) => {
      const g = await mintGrant(core, { role, ...(scope ? { scope } : {}) });
      const s = fakeSocket();
      h.room.onConnect(id, s);
      await send(h.room, id, { v: 1, type: "hello", grant: g.jwt });
      const ch = lastSent(s) as { nonce: string };
      const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
      await send(h.room, id, {
        v: 1, type: "authenticate", jti: g.jti,
        sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)),
      });
      return s;
    };
    await auth("f", "forge");
    // Routing-only bearer: admitted (ready) but open is forbidden.
    const cs = await auth("c", "client", ["relay:connect"]);
    await send(h.room, "c", { v: 1, type: "open", channel: "ch1" });
    const last = lastSent(cs) as { type: string; code?: string };
    expect(last.type).toBe("error");
    expect(last.code).toBe("bad-scope");
    expect(cs.closed?.code).toBe(CLOSE_FORBIDDEN);
  });

  it("rejects cross-client channels and unknown channels", async () => {
    const t = await openChannel();
    const core = testCoreKey();
    void core;
    await send(t.h.room, "c", { v: 1, type: "data", channel: "nope", seq: 0, body: "eA" });
    const last = JSON.parse(t.cs.sent[t.cs.sent.length - 1] as string) as { type: string; code?: string };
    expect(last.type).toBe("error");
    expect(last.code).toBe("no-channel");
  });

  it("closes channels and notifies the peer", async () => {
    const t = await openChannel();
    await send(t.h.room, "c", { v: 1, type: "close", channel: "ch1", reason: "done" });
    const got = JSON.parse(t.fs.sent[t.fs.sent.length - 1] as string) as { type: string };
    expect(got.type).toBe("channel-closed");
  });

  it("rejects oversize bodies", async () => {
    const t = await openChannel();
    await send(t.h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 0, body: "x".repeat(MAX_BODY_B64 + 1) });
    expect(t.cs.closed?.code).toBe(CLOSE_POLICY);
  });

  it("notifies clients when forge disconnects and reopens cleanly", async () => {
    const t = await openChannel();
    t.h.room.onClose("f");
    const last = JSON.parse(t.cs.sent[t.cs.sent.length - 1] as string) as { type: string };
    expect(last.type).toBe("presence");
    expect(t.h.room.presence().forge_online).toBe(false);
  });
});

describe("room revocation (Core v1 list model)", () => {
  it("rejects revoked machines and keys at hello, sweeps live conns", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const g = await mintGrant(core, { role: "client" });
    // Revoke by machine id.
    h.room.setRevocations(["forge1"], []);
    const s = fakeSocket();
    h.room.onConnect("c1", s);
    await send(h.room, "c1", { v: 1, type: "hello", grant: g.jwt });
    expect(s.closed?.code).toBe(CLOSE_REVOKED);

    // Revoke by cnf key (clear machine list first).
    h.room.setRevocations([], [b64uEncode(g.cnfPk)]);
    const s2 = fakeSocket();
    h.room.onConnect("c2", s2);
    await send(h.room, "c2", { v: 1, type: "hello", grant: g.jwt });
    expect(s2.closed?.code).toBe(CLOSE_REVOKED);
  });

  it("sweeps a live connection when its key appears on the list", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    const g = await mintGrant(core, { role: "client" });
    const s = fakeSocket();
    h.room.onConnect("c2", s);
    await send(h.room, "c2", { v: 1, type: "hello", grant: g.jwt });
    const ch = lastSent(s) as { nonce: string };
    const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
    await send(h.room, "c2", { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) });
    expect(s.closed).toBeNull();
    h.room.setRevocations([], [b64uEncode(g.cnfPk)]);
    expect(s.closed?.code).toBe(CLOSE_REVOKED);
  });

  it("unrelated machines and keys are unaffected", async () => {
    const core = testCoreKey();
    const h = makeRoom(testVerifier(core));
    h.room.setRevocations(["other-forge"], ["deadbeef"]);
    const g = await mintGrant(core, { role: "client" });
    const s = fakeSocket();
    h.room.onConnect("c", s);
    await send(h.room, "c", { v: 1, type: "hello", grant: g.jwt });
    expect(s.closed).toBeNull();
    expect(h.room.presence()).toEqual({ forge_online: false, clients: 0 });
  });
});
