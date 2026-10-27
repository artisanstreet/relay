import { describe, expect, it } from "vitest";
import { RoomState } from "../../src/room/state.ts";
import { fake_socket, last_sent, mint_grant, send, test_core_key, test_verifier } from "../helpers.ts";
import { pop_sign } from "../../src/e2e.ts";
import { b64u_encode } from "../../src/b64u.ts";

async function auth_conn(room: RoomState, id: string, role: "forge" | "client", core = test_core_key()) {
  const g = await mint_grant(core, { role });
  const s = fake_socket();
  room.on_connect(id, s);
  await send(room, id, { v: 1, type: "hello", grant: g.jwt });
  const ch = last_sent(s) as { nonce: string };
  const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
  await send(room, id, { v: 1, type: "authenticate", jti: g.jti, sig: b64u_encode(pop_sign(g.cnf_sk, nonce, g.jti)) });
  return { s, g };
}

function adapter(s: ReturnType<typeof fake_socket>) {
  return { send: (d: string) => s.send(d), close: (c?: number, r?: string) => s.close(c, r) };
}

describe("hibernation preserves channel-open authority (scope)", () => {
  it("restored client with forge:execute opens new channels", async () => {
    const core = test_core_key();
    const verify = test_verifier(core);
    const a = new RoomState("acct1", "forge1", verify, () => Date.now());
    await auth_conn(a, "f", "forge", core);
    const c = await auth_conn(a, "c", "client", core);
    await send(a, "c", { v: 1, type: "open", channel: "ch1" });
    expect(last_sent(c.s)).toMatchObject({ type: "channel-opened", channel: "ch1" });

    const snap = a.snapshot();
    expect(snap.conns.find((k) => k.conn === "c")?.scope).toContain("forge:execute");

    const b = new RoomState("acct1", "forge1", verify, () => Date.now());
    const fs = fake_socket();
    const cs = fake_socket();
    const sockets = new Map([["f", fs], ["c", cs]]);
    expect(b.restore(snap, (id) => (sockets.has(id) ? adapter(sockets.get(id)!) : null))).toEqual({
      restored: 2,
      dropped: 0,
    });
    await send(b, "c", { v: 1, type: "open", channel: "ch2" });
    expect(last_sent(cs)).toMatchObject({ type: "channel-opened", channel: "ch2" });
    expect(cs.closed).toBeNull();
  });

  it("scope-less snapshot (pre-fix) fails closed, client re-hellos", async () => {
    const core = test_core_key();
    const verify = test_verifier(core);
    const a = new RoomState("acct1", "forge1", verify, () => Date.now());
    await auth_conn(a, "f", "forge", core);
    await auth_conn(a, "c", "client", core);
    const snap = a.snapshot();
    const legacy = {
      ...snap,
      conns: snap.conns.map(({ scope: _dropped, ...rest }) => rest),
    } as unknown as typeof snap;
    const b = new RoomState("acct1", "forge1", verify, () => Date.now());
    const fs = fake_socket();
    const cs = fake_socket();
    const sockets = new Map([["f", fs], ["c", cs]]);
    const res = b.restore(legacy, (id) => (sockets.has(id) ? adapter(sockets.get(id)!) : null));
    expect(res.restored + res.dropped).toBe(2);
    expect(cs.closed?.code).toBe(4401);
  });
});
