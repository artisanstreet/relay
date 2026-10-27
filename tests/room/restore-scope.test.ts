import { describe, expect, it } from "vitest";
import { RoomState } from "../../src/room/state.ts";
import { fakeSocket, lastSent, mintGrant, send, testCoreKey, testVerifier } from "../helpers.ts";
import { popSign } from "../../src/e2e.ts";
import { b64uEncode } from "../../src/b64u.ts";

async function auth_conn(room: RoomState, id: string, role: "forge" | "client", core = testCoreKey()) {
  const g = await mintGrant(core, { role });
  const s = fakeSocket();
  room.onConnect(id, s);
  await send(room, id, { v: 1, type: "hello", grant: g.jwt });
  const ch = lastSent(s) as { nonce: string };
  const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
  await send(room, id, { v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) });
  return { s, g };
}

function adapter(s: ReturnType<typeof fakeSocket>) {
  return { send: (d: string) => s.send(d), close: (c?: number, r?: string) => s.close(c, r) };
}

describe("hibernation preserves channel-open authority (scope)", () => {
  it("restored client with forge:execute opens new channels", async () => {
    const core = testCoreKey();
    const verify = testVerifier(core);
    const a = new RoomState("acct1", "forge1", verify, () => Date.now());
    await auth_conn(a, "f", "forge", core);
    const c = await auth_conn(a, "c", "client", core);
    await send(a, "c", { v: 1, type: "open", channel: "ch1" });
    expect(lastSent(c.s)).toMatchObject({ type: "channel-opened", channel: "ch1" });

    const snap = a.snapshot();
    expect(snap.conns.find((k) => k.conn === "c")?.scope).toContain("forge:execute");

    const b = new RoomState("acct1", "forge1", verify, () => Date.now());
    const fs = fakeSocket();
    const cs = fakeSocket();
    const sockets = new Map([["f", fs], ["c", cs]]);
    expect(b.restore(snap, (id) => (sockets.has(id) ? adapter(sockets.get(id)!) : null))).toEqual({
      restored: 2,
      dropped: 0,
    });
    await send(b, "c", { v: 1, type: "open", channel: "ch2" });
    expect(lastSent(cs)).toMatchObject({ type: "channel-opened", channel: "ch2" });
    expect(cs.closed).toBeNull();
  });

  it("scope-less snapshot (pre-fix) fails closed, client re-hellos", async () => {
    const core = testCoreKey();
    const verify = testVerifier(core);
    const a = new RoomState("acct1", "forge1", verify, () => Date.now());
    await auth_conn(a, "f", "forge", core);
    await auth_conn(a, "c", "client", core);
    const snap = a.snapshot();
    const legacy = {
      ...snap,
      conns: snap.conns.map(({ scope: _dropped, ...rest }) => rest),
    } as unknown as typeof snap;
    const b = new RoomState("acct1", "forge1", verify, () => Date.now());
    const fs = fakeSocket();
    const cs = fakeSocket();
    const sockets = new Map([["f", fs], ["c", cs]]);
    const res = b.restore(legacy, (id) => (sockets.has(id) ? adapter(sockets.get(id)!) : null));
    expect(res.restored + res.dropped).toBe(2);
    expect(cs.closed?.code).toBe(4401);
  });
});
