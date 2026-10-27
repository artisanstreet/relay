// Adversarial suite: attacker-perspective cases against RoomState.
// Each test names the attacker capability and asserts the room holds.

import { describe, expect, it } from "vitest";
import { CLOSE_AUTH, CLOSE_FORBIDDEN, CLOSE_POLICY, CLOSE_REVOKED } from "../src/room.ts";
import { pop_sign } from "../src/e2e.ts";
import { b64u_encode } from "../src/jwt.ts";
import { fake_socket, is_challenge, last_sent, make_room, mint_grant, send, test_core_key, test_verifier, wait_for_frame } from "./helpers.ts";

async function nonce_of(s: ReturnType<typeof fake_socket>): Promise<Uint8Array> {
  const ch = await wait_for_frame(s, is_challenge);
  return Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
}

describe("adversaries", () => {
  it("cross-account grant cannot enter another account's room", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core), "acct1", "forge1");
    const g = await mint_grant(core, { account: "acct-evil", role: "client" });
    const s = fake_socket();
    h.room.on_connect("a", s);
    await send(h.room, "a", { v: 1, type: "hello", grant: g.jwt });
    expect(s.closed?.code).toBe(CLOSE_FORBIDDEN);
  });

  it("stolen JWT without the cnf secret cannot authenticate", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const victim = await mint_grant(core, { role: "client" });
    const s = fake_socket();
    h.room.on_connect("a", s);
    await send(h.room, "a", { v: 1, type: "hello", grant: victim.jwt });
    const nonce = await nonce_of(s);
    const { ed25519 } = await import("@noble/curves/ed25519.js");
    await send(h.room, "a", {
      v: 1, type: "authenticate", jti: victim.jti,
      sig: b64u_encode(pop_sign(ed25519.utils.randomSecretKey(), nonce, victim.jti)),
    });
    expect(s.closed?.code).toBe(CLOSE_AUTH);
  });

  it("replayed victim jti from a second connection is rejected", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const victim = await mint_grant(core, { role: "client" });
    // Victim admits first (consumes the single-use jti).
    const vs = fake_socket();
    h.room.on_connect("victim", vs);
    await send(h.room, "victim", { v: 1, type: "hello", grant: victim.jwt });
    await send(h.room, "victim", {
      v: 1, type: "authenticate", jti: victim.jti,
      sig: b64u_encode(pop_sign(victim.cnf_sk, await nonce_of(vs), victim.jti)),
    });
    expect(vs.closed).toBeNull();
    // Attacker replays the same JWT: rejected at hello, no challenge.
    const s2 = fake_socket();
    h.room.on_connect("evil", s2);
    await send(h.room, "evil", { v: 1, type: "hello", grant: victim.jwt });
    expect(s2.closed?.code).toBe(CLOSE_AUTH);
  });

  it("tampered grant bytes fail verification without leaking why", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const g = await mint_grant(core, { role: "client" });
    const parts = g.jwt.split(".");
    const tampered = `${parts[0]}.${parts[1]}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    const s = fake_socket();
    h.room.on_connect("a", s);
    await send(h.room, "a", { v: 1, type: "hello", grant: tampered });
    expect(s.closed?.code).toBe(CLOSE_AUTH);
    const last = last_sent(s) as { type: string; code: string; message: string };
    expect(last.type).toBe("error");
    expect(last.message).not.toContain(g.jwt.slice(0, 10)); // no secret material in errors
  });

  it("expired grant is rejected at hello", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const now = Math.floor(Date.now() / 1000);
    const g = await mint_grant(core, { role: "client", iat: now - 500, exp: now - 200 });
    const s = fake_socket();
    h.room.on_connect("a", s);
    await send(h.room, "a", { v: 1, type: "hello", grant: g.jwt });
    expect(s.closed?.code).toBe(CLOSE_AUTH);
  });

  it("channel squatting by a second client is rejected", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const auth = async (id: string, role: "forge" | "client") => {
      const g = await mint_grant(core, { role });
      const s = fake_socket();
      h.room.on_connect(id, s);
      await send(h.room, id, { v: 1, type: "hello", grant: g.jwt });
      await send(h.room, id, {
        v: 1, type: "authenticate", jti: g.jti,
        sig: b64u_encode(pop_sign(g.cnf_sk, await nonce_of(s), g.jti)),
      });
      return s;
    };
    const fs = await auth("f", "forge");
    void fs;
    const c1 = await auth("c1", "client");
    const c2 = await auth("c2", "client");
    await send(h.room, "c1", { v: 1, type: "open", channel: "ch1" });
    await send(h.room, "c2", { v: 1, type: "open", channel: "ch1" });
    const last = last_sent(c2) as { type: string; code?: string };
    expect(last.type).toBe("error");
    expect(last.code).toBe("channel-in-use");
    expect(c2.closed).toBeNull(); // squat attempt doesn't kill the connection
    void c1;
  });

  it("forge cannot open channels (client-only operation)", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const g = await mint_grant(core, { role: "forge" });
    const s = fake_socket();
    h.room.on_connect("f", s);
    await send(h.room, "f", { v: 1, type: "hello", grant: g.jwt });
    await send(h.room, "f", {
      v: 1, type: "authenticate", jti: g.jti,
      sig: b64u_encode(pop_sign(g.cnf_sk, await nonce_of(s), g.jti)),
    });
    await send(h.room, "f", { v: 1, type: "open", channel: "ch9" });
    const last = last_sent(s) as { type: string; code?: string };
    expect(last.type).toBe("error");
  });

  it("transport seq violations are non-fatal errors (connection survives)", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const auth = async (id: string, role: "forge" | "client") => {
      const g = await mint_grant(core, { role });
      const s = fake_socket();
      h.room.on_connect(id, s);
      await send(h.room, id, { v: 1, type: "hello", grant: g.jwt });
      await send(h.room, id, {
        v: 1, type: "authenticate", jti: g.jti,
        sig: b64u_encode(pop_sign(g.cnf_sk, await nonce_of(s), g.jti)),
      });
      return s;
    };
    await auth("f", "forge");
    const cs = await auth("c", "client");
    await send(h.room, "c", { v: 1, type: "open", channel: "ch1" });
    await send(h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 0, body: "eA" });
    await send(h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 0, body: "eA" });
    expect(cs.closed).toBeNull();
    await send(h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 1, body: "eA" });
    expect(cs.closed).toBeNull();
  });

  it("unacked flood stalls at a bounded window (drop-newest + error)", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const auth = async (id: string, role: "forge" | "client") => {
      const g = await mint_grant(core, { role });
      const s = fake_socket();
      h.room.on_connect(id, s);
      await send(h.room, id, { v: 1, type: "hello", grant: g.jwt });
      await send(h.room, id, {
        v: 1, type: "authenticate", jti: g.jti,
        sig: b64u_encode(pop_sign(g.cnf_sk, await nonce_of(s), g.jti)),
      });
      return s;
    };
    const fs = await auth("f", "forge");
    const cs = await auth("c", "client");
    await send(h.room, "c", { v: 1, type: "open", channel: "ch1" });
    // Forge never acks: 64 frames fill the window, the 65th drops.
    for (let i = 0; i < 64; i++) {
      await send(h.room, "c", { v: 1, type: "data", channel: "ch1", seq: i, body: "eA" });
    }
    expect(fs.sent.filter((m) => JSON.parse(m).type === "data").length).toBe(64);
    await send(h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 64, body: "eA" });
    expect(fs.sent.filter((m) => JSON.parse(m).type === "data").length).toBe(64); // dropped
    const last = last_sent(cs) as { type: string; code?: string };
    expect(last.type).toBe("error");
    expect(last.code).toBe("backpressure");
    expect(cs.closed).toBeNull(); // sender survives; app must cope with loss
    // One cumulative ack releases the whole window; flow resumes.
    await send(h.room, "f", { v: 1, type: "ack", channel: "ch1", seq: 63 });
    await send(h.room, "c", { v: 1, type: "data", channel: "ch1", seq: 65, body: "eA" });
    expect(fs.sent.filter((m) => JSON.parse(m).type === "data").length).toBe(65);
  });

  it("heartbeat pong keeps a connection alive; silence kills it", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const iat = Math.floor(Date.now() / 1000);
    // Long-lived grant so the heartbeat (not expiry) is what fires.
    const g = await mint_grant(core, { role: "client", iat, exp: iat + 300 });
    const s = fake_socket();
    h.room.on_connect("c", s);
    await send(h.room, "c", { v: 1, type: "hello", grant: g.jwt });
    await send(h.room, "c", {
      v: 1, type: "authenticate", jti: g.jti,
      sig: b64u_encode(pop_sign(g.cnf_sk, await nonce_of(s), g.jti)),
    });
    h.advance(30_000);
    h.room.tick();
    await send(h.room, "c", { v: 1, type: "pong", t: Date.now() });
    h.advance(30_000);
    h.room.tick();
    expect(s.closed).toBeNull(); // ponged 30s ago: alive
    h.advance(61_000);
    h.room.tick();
    expect(s.closed?.code).toBe(CLOSE_POLICY);
  });

  it("revoked keys cannot enter (machine/key list model)", async () => {
    const core = test_core_key();
    const h = make_room(test_verifier(core));
    const g = await mint_grant(core, { role: "client" });
    h.room.set_revocations([], [b64u_encode(g.cnf_pk)]);
    const s = fake_socket();
    h.room.on_connect("c", s);
    await send(h.room, "c", { v: 1, type: "hello", grant: g.jwt });
    expect(s.closed?.code).toBe(CLOSE_REVOKED);
  });
});
