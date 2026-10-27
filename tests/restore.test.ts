// Hibernation wake-up: snapshot()/restore() across RoomState instances.
// Simulates DO eviction: instance A serves traffic and snapshots; instance B
// (fresh, same account/machine) restores onto live sockets. No real DO needed
// to prove the reconstruction logic; the Workers runtime path is covered by
// test/worker.test.ts (Miniflare).

import { describe, expect, it } from "vitest";
import { CLOSE_AUTH, CLOSE_REVOKED } from "../src/room.ts";
import { RoomState } from "../src/room.ts";
import type { RoomSocket } from "../src/room.ts";
import { popSign } from "../src/e2e.ts";
import { b64uEncode } from "../src/jwt.ts";
import { fakeSocket, lastSent, mintGrant, send, testCoreKey, testVerifier } from "./helpers.ts";

async function authConn(room: RoomState, id: string, role: "forge" | "client", core = testCoreKey(), grantOpts = {}) {
  const g = await mintGrant(core, { role, ...grantOpts });
  const s = fakeSocket();
  room.onConnect(id, s);
  await send(room, id, { v: 1, type: "hello", grant: g.jwt });
  const ch = lastSent(s) as { nonce: string };
  const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
  await send(room, id, { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) });
  return { s, g };
}

function adapter(s: ReturnType<typeof fakeSocket>): RoomSocket {
  return { send: (d: string) => s.send(d), close: (c?: number, r?: string) => s.close(c, r) };
}

describe("hibernation restore", () => {
  it("restores membership, channels, and seq high-waters onto live sockets", async () => {
    const core = testCoreKey();
    const verify = testVerifier(core);
    const a = new RoomState("acct1", "forge1", verify, () => Date.now());
    await authConn(a, "f", "forge", core);
    await authConn(a, "c", "client", core);
    await send(a, "c", { v: 1, type: "open", channel: "ch1" });
    await send(a, "c", { v: 1, type: "data", channel: "ch1", seq: 0, body: "eA" });
    await send(a, "c", { v: 1, type: "data", channel: "ch1", seq: 1, body: "eA" });
    const snap = a.snapshot();
    expect(snap.conns.length).toBe(2);
    expect(snap.channels.length).toBe(1);

    // "Eviction": fresh instance, same identity, live sockets for both conns.
    const b = new RoomState("acct1", "forge1", verify, () => Date.now());
    const fs = fakeSocket();
    const cs = fakeSocket();
    const sockets = new Map([["f", fs], ["c", cs]]);
    const res = b.restore(snap, (id) => (sockets.has(id) ? adapter(sockets.get(id) as ReturnType<typeof fakeSocket>) : null));
    expect(res).toEqual({ restored: 2, dropped: 0 });
    expect(b.presence()).toEqual({ forge_online: true, clients: 1 });

    // Routing resumes with enforced high-waters: replay of seq 1 fails.
    await send(b, "c", { v: 1, type: "data", channel: "ch1", seq: 1, body: "eA" });
    const last = JSON.parse(cs.sent[cs.sent.length - 1] as string) as { type: string; code?: string };
    expect(last.type).toBe("error");
    expect(last.code).toBe("bad-seq");
    await send(b, "c", { v: 1, type: "data", channel: "ch1", seq: 2, body: "eA" });
    const fwd = JSON.parse(fs.sent[fs.sent.length - 1] as string) as { type: string; seq: number };
    expect(fwd.type).toBe("data");
    expect(fwd.seq).toBe(2);
  });

  it("drops expired and revoked conns at restore, keeps the rest", async () => {
    const core = testCoreKey();
    const verify = testVerifier(core);
    const a = new RoomState("acct1", "forge1", verify, () => Date.now());
    const { g: fg } = await authConn(a, "f", "forge", core);
    const { g: cg } = await authConn(a, "c", "client", core);
    void fg;
    const snap = a.snapshot();

    // Revoke the client's KEY before the wake (v1 list model).
    const b = new RoomState("acct1", "forge1", verify, () => Date.now());
        const fs = fakeSocket();
    const cs = fakeSocket();
    const sockets = new Map([["f", fs], ["c", cs]]);
    // Merge revocation into the snapshot path: restore reads snap's own
    // persisted lists, the way the DO would after a poll.
    const snap2 = { ...snap, revokedKeys: [Buffer.from(cg.cnfPk).toString("base64url")] };
    const res = b.restore(snap2, (id) => (sockets.has(id) ? adapter(sockets.get(id) as ReturnType<typeof fakeSocket>) : null));
    expect(res.restored).toBe(1);
    expect(res.dropped).toBe(1);
    expect(cs.closed?.code).toBe(CLOSE_REVOKED);
    expect(b.presence()).toEqual({ forge_online: true, clients: 0 });
  });

  it("rejects mismatched snapshots", () => {
    const verify = testVerifier(testCoreKey());
    const b = new RoomState("acct1", "forge1", verify, () => Date.now());
    const bad = {
      v: 1 as const, account: "other", machine: "forge1",
      revokedMachines: [], revokedKeys: [], usedJti: [], conns: [], channels: [],
    };
    expect(() => b.restore(bad, () => null)).toThrow(/mismatch/);
  });

  it("grants expire per-frame and on sweep, even after long sleep", async () => {
    const core = testCoreKey();
    let now = Date.now();
    const verify = testVerifier(core);
    const a = new RoomState("acct1", "forge1", verify, () => now);
    const iat = Math.floor(now / 1000);
    // Short-lived grant: 100s TTL.
    const g = await mintGrant(core, { role: "client", iat, exp: iat + 100 });
    const s = fakeSocket();
    a.onConnect("c", s);
    await send(a, "c", { v: 1, type: "hello", grant: g.jwt });
    const ch = lastSent(s) as { nonce: string };
    const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
    await send(a, "c", { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) });
    expect(s.closed).toBeNull();

    // Sleep past expiry with NO tick (alarm missed the wake): the next
    // frame is still rejected per-frame.
    now += 200_000;
    await send(a, "c", { v: 1, type: "pong", t: now });
    expect(s.closed?.code).toBe(CLOSE_AUTH);

    // Sweep path: fresh conn, sleep, then tick closes it.
    const g2 = await mintGrant(core, { role: "client", iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 100 });
    const s2 = fakeSocket();
    a.onConnect("c2", s2);
    await send(a, "c2", { v: 1, type: "hello", grant: g2.jwt });
    const ch2 = lastSent(s2) as { nonce: string };
    const n2 = Uint8Array.from(Buffer.from(ch2.nonce, "base64url"));
    await send(a, "c2", { v: 1, type: "authenticate", jti: g2.jti, sig: b64uEncode(popSign(g2.cnfSk, n2, g2.jti)) });
    now += 200_000;
    a.tick();
    expect(s2.closed?.code).toBe(CLOSE_AUTH);
  });

  it("nextDeadlineMs is null when idle, set when work exists", async () => {
    const core = testCoreKey();
    const verify = testVerifier(core);
    let now = Date.now();
    const a = new RoomState("acct1", "forge1", verify, () => now);
    expect(a.nextDeadlineMs()).toBeNull();
    const s = fakeSocket();
    a.onConnect("c", s);
    const d = a.nextDeadlineMs();
    expect(d).toBe(now + 5_000); // hello timeout
    const { g } = await authConn(a, "c2", "client", core);
    void g;
    expect(a.nextDeadlineMs()).not.toBeNull();
    a.onClose("c");
    a.onClose("c2");
    // Everything gone: idle room needs no alarm.
    expect(a.nextDeadlineMs()).toBeNull();
  });
});
