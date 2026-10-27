// NoiseChannel tests: real noise-handshake sessions with JWT-identity
// binding. The Noise crypto itself is the library's job, proven
// interoperable via test/noise-interop.test.ts (live snow).

import { describe, expect, it } from "vitest";
import {
  NoiseChannel,
  binding_message,
  equal_bytes,
  prologue_bytes,
  static_keypair_from_secret,
  ROLE_INITIATOR,
  ROLE_RESPONDER,
  MAX_APP_PLAINTEXT,
} from "../src/channel.ts";
import { make_channel_jwt_verifier } from "../src/channel-verify.ts";
import { new_ed25519_keypair } from "../src/e2e.ts";
import { randomBytes as random_bytes } from "@noble/hashes/utils.js";
import { mint_grant, stub_fetch, test_core_key, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";
import type { VerifyChannelJwt } from "../src/channel.ts";

const CTX = { account: "acct1", machine: "forge1", channel: "ch1" };

/** Poll for open with a real timeout instead of hoping a flush suffices. */

async function wait_closed(ch: { get_phase(): string }, label: string): Promise<void> {
  const deadline = Date.now() + 5000;
  for (;;) {
    const got = ch.get_phase();
    if (got === "closed") return;
    if (Date.now() > deadline) throw new Error(`${label}: timed out, stuck at ${got}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function wait_phase(ch: { get_phase(): string }, want: string, label: string): Promise<void> {
  const deadline = Date.now() + 5000;
  for (;;) {
    const got = ch.get_phase();
    if (got === want) return;
    if (got === "closed") throw new Error(`${label}: session closed while waiting for ${want}`);
    if (Date.now() > deadline) throw new Error(`${label}: timed out waiting for ${want}, stuck at ${got}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

interface Ends {
  init: NoiseChannel;
  resp: NoiseChannel;
  forge_cnf: { sk: Uint8Array; pk: Uint8Array };
  editor_cnf: { sk: Uint8Array; pk: Uint8Array };
  editor_jwt: string;
}

async function make_ends(ctx = CTX): Promise<Ends> {
  const core = test_core_key();
  const forge_cnf = new_ed25519_keypair(); // enrolled machine key (stable)
  const editor_cnf = new_ed25519_keypair(); // ephemeral per-grant key
  const g = await mint_grant(core, { account: ctx.account, machine: ctx.machine, cnf_sk: editor_cnf.sk });
  const verify: VerifyChannelJwt = make_channel_jwt_verifier(
    { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
    stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }] }),
  );
  const init = new NoiseChannel({
    initiator: true,
    static_keypair: static_keypair_from_secret(random_bytes(32)),
    cnf_sign_key: editor_cnf.sk,
    expected_responder_cnf: forge_cnf.pk,
    own_grant_jwt: g.jwt,
    ctx,
  });
  const resp = new NoiseChannel({
    initiator: false,
    static_keypair: static_keypair_from_secret(random_bytes(32)),
    cnf_sign_key: forge_cnf.sk,
    verify_channel_jwt: verify,
    ctx,
  });
  return { init, resp, forge_cnf, editor_cnf, editor_jwt: g.jwt };
}

function do_handshake(init: NoiseChannel, resp: NoiseChannel): void {
  const m1 = init.next_handshake_message();
  expect(m1.length).toBe(32);
  resp.receive_handshake_message(m1);
  const m2 = resp.next_handshake_message();
  expect(m2.length).toBe(96);
  init.receive_handshake_message(m2);
  const m3 = init.next_handshake_message();
  expect(m3.length).toBe(64);
  resp.receive_handshake_message(m3);
}

async function full_open(ends?: Ends): Promise<Ends> {
  const e = ends ?? (await make_ends());
  do_handshake(e.init, e.resp);
  const [c_init] = e.init.take_outbound();
  expect(c_init).toBeDefined();
  e.resp.receive_transport(c_init as Uint8Array);
  await wait_phase(e.resp, "open", "responder confirm");
  const [c_resp] = e.resp.take_outbound();
  expect(c_resp).toBeDefined();
  const back = e.init.receive_transport(c_resp as Uint8Array);
  await wait_phase(e.init, "open", "initiator confirm");
  expect(back).toBeNull();
  expect(e.init.get_phase()).toBe("open");
  expect(e.init.handshake_hash_hex()).toEqual(e.resp.handshake_hash_hex());
  return e;
}

describe("noise channel with JWT identity binding", () => {
  it("opens with mutual confirmation and equal handshake hashes", async () => {
    await full_open();
  });

  it("exchanges app data both directions with exact bytes", async () => {
    const { init, resp } = await full_open();
    const a = init.seal(new TextEncoder().encode("hello forge"));
    expect(new TextDecoder().decode(resp.receive_transport(a.ct) as Uint8Array)).toBe("hello forge");
    const b = resp.seal(new TextEncoder().encode("hello editor"));
    expect(new TextDecoder().decode(init.receive_transport(b.ct) as Uint8Array)).toBe("hello editor");
  });

  it("MITM handshake substitution fails the transcript check", async () => {
    const e = await make_ends();
    const m1 = e.init.next_handshake_message();
    e.resp.receive_handshake_message(m1);
    const m2 = e.resp.next_handshake_message();
    (m2[40] as number) ^= 0xff; // attacker flips a bit in the encrypted responder message
    expect(() => e.init.receive_handshake_message(m2)).toThrow();
    expect(e.init.get_phase()).toBe("closed");
  });

  it("prologue (context) mismatch fails the handshake", async () => {
    const core = test_core_key();
    const forge_cnf = new_ed25519_keypair();
    const editor_cnf = new_ed25519_keypair();
    const g = await mint_grant(core, { cnf_sk: editor_cnf.sk });
    const verify = make_channel_jwt_verifier(
      { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
      stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const init = new NoiseChannel({
      initiator: true,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: editor_cnf.sk,
      expected_responder_cnf: forge_cnf.pk,
      own_grant_jwt: g.jwt,
      ctx: { ...CTX, channel: "ch1" },
    });
    const resp = new NoiseChannel({
      initiator: false,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: forge_cnf.sk,
      verify_channel_jwt: verify,
      ctx: { ...CTX, channel: "CH2" },
    });
    const m1 = init.next_handshake_message();
    resp.receive_handshake_message(m1);
    const m2 = resp.next_handshake_message();
    expect(() => init.receive_handshake_message(m2)).toThrow();
    expect(init.get_phase()).toBe("closed");
  });

  it("responder rejects a grant JWT bound to another machine", async () => {
    const core = test_core_key();
    const forge_cnf = new_ed25519_keypair();
    const editor_cnf = new_ed25519_keypair();
    // Grant is for forge2, but the channel context is forge1.
    const g = await mint_grant(core, { machine: "forge2", cnf_sk: editor_cnf.sk });
    const verify = make_channel_jwt_verifier(
      { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
      stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const init = new NoiseChannel({
      initiator: true,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: editor_cnf.sk,
      expected_responder_cnf: forge_cnf.pk,
      own_grant_jwt: g.jwt,
      ctx: CTX,
    });
    const resp = new NoiseChannel({
      initiator: false,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: forge_cnf.sk,
      verify_channel_jwt: verify,
      ctx: CTX,
    });
    do_handshake(init, resp);
    const [c_init] = init.take_outbound();
    resp.receive_transport(c_init as Uint8Array);
    await wait_closed(resp, "wrong-machine grant");
  });

  it("responder rejects a forged binding signature (stolen JWT, no cnf secret)", async () => {
    const e = await make_ends();
    // Attacker holds the JWT but not the cnf secret: craft a channel with
    // a WRONG cnf_sign_key while reusing the victim's JWT.
    const attacker_cnf = new_ed25519_keypair();
    const evil = new NoiseChannel({
      initiator: true,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: attacker_cnf.sk, // not the key the JWT binds
      expected_responder_cnf: e.forge_cnf.pk,
      own_grant_jwt: e.editor_jwt,
      ctx: CTX,
    });
    do_handshake(evil, e.resp);
    const [c_init] = evil.take_outbound();
    e.resp.receive_transport(c_init as Uint8Array);
    await wait_closed(e.resp, "forged binding");
  });

  it("responder rejects in-confirm JWTs without client role + forge:execute", async () => {
    const core = test_core_key();
    const mk_verify = () =>
      make_channel_jwt_verifier(
        { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
        stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
      );
    const forge_cnf = new_ed25519_keypair();
    for (const [name, opts] of [
      ["forge role", { role: "forge" as const, scope: ["relay:connect", "forge:execute", "machine:sync"] }],
      ["missing forge:execute", { role: "client" as const, scope: ["relay:connect"] }],
    ] as const) {
      const editor_cnf = new_ed25519_keypair();
      const g = await mint_grant(core, { cnf_sk: editor_cnf.sk, role: opts.role, scope: [...opts.scope] });
      const init = new NoiseChannel({
        initiator: true,
        static_keypair: static_keypair_from_secret(random_bytes(32)),
        cnf_sign_key: editor_cnf.sk,
        expected_responder_cnf: forge_cnf.pk,
        own_grant_jwt: g.jwt,
        ctx: CTX,
      });
      const resp = new NoiseChannel({
        initiator: false,
        static_keypair: static_keypair_from_secret(random_bytes(32)),
        cnf_sign_key: forge_cnf.sk,
        verify_channel_jwt: mk_verify(),
        ctx: CTX,
      });
      do_handshake(init, resp);
      const [c_init] = init.take_outbound();
      resp.receive_transport(c_init as Uint8Array);
      await wait_closed(resp, name);
    }
  });

  it("initiator rejects a responder key that is not the enrolled Forge", async () => {
    const core = test_core_key();
    const forge_cnf = new_ed25519_keypair(); // real enrolled key (expected)
    const impostor_cnf = new_ed25519_keypair(); // key the responder signs with
    const editor_cnf = new_ed25519_keypair();
    const g = await mint_grant(core, { cnf_sk: editor_cnf.sk });
    const verify = make_channel_jwt_verifier(
      { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
      stub_fetch({
        keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }],
      }),
    );
    const init = new NoiseChannel({
      initiator: true,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: editor_cnf.sk,
      expected_responder_cnf: forge_cnf.pk, // real enrolled key expected
      own_grant_jwt: g.jwt,
      ctx: CTX,
    });
    const resp = new NoiseChannel({
      initiator: false,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: impostor_cnf.sk, // impostor signs
      verify_channel_jwt: verify,
      ctx: CTX,
    });
    do_handshake(init, resp);
    const [c_init] = init.take_outbound();
    resp.receive_transport(c_init as Uint8Array);
    await wait_phase(resp, "open", "responder confirm"); // responder side is fine
    const [c_resp] = resp.take_outbound();
    init.receive_transport(c_resp as Uint8Array); // initiator check runs synchronously
    expect(init.get_phase()).toBe("closed");
  });

  it("initiator binding failure is fail-closed even when checked synchronously", async () => {
    const e = await make_ends();
    do_handshake(e.init, e.resp);
    const [c_init] = e.init.take_outbound();
    // Corrupt the responder confirm's signature bytes in flight: flip the
    // last byte (inside the 64B binding signature).
    e.resp.receive_transport(c_init as Uint8Array);
    await wait_phase(e.resp, "open", "responder confirm");
    const [c_resp] = e.resp.take_outbound() as [Uint8Array];
    const tampered = Uint8Array.from(c_resp);
    const last_idx = tampered.length - 1;
    tampered[last_idx] = ((tampered[last_idx] ?? 0) ^ 0xff);
    // Tampering breaks AEAD (fail-closed at decrypt, before signature logic).
    expect(() => e.init.receive_transport(tampered)).toThrow();
    expect(e.init.get_phase()).toBe("closed");
  });

  it("reflection fails: own ciphertext unreadable on the receive path", async () => {
    const { init } = await full_open();
    const { ct } = init.seal(new TextEncoder().encode("self"));
    expect(() => init.receive_transport(ct)).toThrow();
    expect(init.get_phase()).toBe("closed");
  });

  it("replay of a transport message fails (sequential nonces)", async () => {
    const { init, resp } = await full_open();
    const { ct } = init.seal(new TextEncoder().encode("once"));
    expect(resp.receive_transport(ct)).not.toBeNull();
    expect(() => resp.receive_transport(ct)).toThrow();
    expect(resp.get_phase()).toBe("closed");
  });

  it("a lost message destroys the session (sequential nonces, fail-closed)", async () => {
    const { init, resp } = await full_open();
    const a = init.seal(new TextEncoder().encode("m0"));
    const b = init.seal(new TextEncoder().encode("m1"));
    void a; // "lost" on purpose: the cipher stream cannot skip it
    expect(() => resp.receive_transport(b.ct)).toThrow(/transport decrypt failed/);
    expect(resp.get_phase()).toBe("closed");
  });

  it("data cannot be sealed before confirmation", async () => {
    const e = await make_ends();
    do_handshake(e.init, e.resp);
    expect(e.init.get_phase()).toBe("confirm");
    expect(() => e.init.seal(new TextEncoder().encode("early"))).toThrow(/not open/);
  });

  it("rejects oversize plaintext", async () => {
    const { init } = await full_open();
    expect(() => init.seal(new Uint8Array(MAX_APP_PLAINTEXT + 1))).toThrow(/chunk/);
  });

  it("rotation is enforced by age", async () => {
    let now = 1_000_000;
    const core = test_core_key();
    const forge_cnf = new_ed25519_keypair();
    const editor_cnf = new_ed25519_keypair();
    // Grant times follow the channel clock (1000s), not wall time.
    const g = await mint_grant(core, { cnf_sk: editor_cnf.sk, iat: 1000, nbf: 1000, exp: 1120 });
    const verify = make_channel_jwt_verifier(
      { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
      stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const init = new NoiseChannel({
      initiator: true,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: editor_cnf.sk,
      expected_responder_cnf: forge_cnf.pk,
      own_grant_jwt: g.jwt,
      ctx: CTX,
      now_ms: () => now,
    });
    const resp = new NoiseChannel({
      initiator: false,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: forge_cnf.sk,
      verify_channel_jwt: verify,
      ctx: CTX,
      now_ms: () => now,
    });
    do_handshake(init, resp);
    const [c_init] = init.take_outbound();
    resp.receive_transport(c_init as Uint8Array);
    await wait_phase(resp, "open", "responder confirm");
    const [c_resp] = resp.take_outbound();
    init.receive_transport(c_resp as Uint8Array);
    await wait_phase(init, "open", "initiator confirm");
    expect(init.needs_rotation()).toBe(false);
    now += 25 * 60 * 60 * 1000;
    expect(init.needs_rotation()).toBe(true);
    expect(() => init.seal(new TextEncoder().encode("late"))).toThrow(/rotation due/);
  });

  it("never mutates caller handshake buffers (library aliases inputs)", async () => {
    // Regression: noise-handshake TOK_E stores a subarray VIEW of the input
    // and _clear() zero-fills it on completion. The wrapper must copy, so
    // caller buffers (and fixture evidence) stay byte-identical.
    const e = await make_ends();
    const m1 = e.init.next_handshake_message();
    const m1copy = Uint8Array.from(m1);
    e.resp.receive_handshake_message(m1);
    expect([...m1]).toEqual([...m1copy]);
    const m2 = e.resp.next_handshake_message();
    const m2copy = Uint8Array.from(m2);
    e.init.receive_handshake_message(m2);
    expect([...m2]).toEqual([...m2copy]);
    const m3 = e.init.next_handshake_message();
    const m3copy = Uint8Array.from(m3);
    e.resp.receive_handshake_message(m3);
    expect([...m3]).toEqual([...m3copy]);
    // And the ephemeral public keys are real (not zeroed).
    expect(m1.some((b) => b !== 0)).toBe(true);
    expect(m2.subarray(0, 32).some((b) => b !== 0)).toBe(true);
  });

  it("binding message layout is fixed", () => {    const h = new Uint8Array(64).fill(9);
    const m1 = binding_message(ROLE_INITIATOR, h);
    const m2 = binding_message(ROLE_RESPONDER, h);
    expect(m1.length).toBe("ast-relay-bind-v1".length + 1 + 64);
    expect(m1).not.toEqual(m2); // role separation
    expect(() => binding_message(ROLE_INITIATOR, new Uint8Array(32))).toThrow();
    expect(equal_bytes(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
    expect(prologue_bytes(CTX).length).toBeGreaterThan(0);
  });

  it("destroy closes the session", async () => {
    const { init } = await full_open();
    init.destroy();
    expect(init.get_phase()).toBe("closed");
    expect(() => init.seal(new TextEncoder().encode("x"))).toThrow();
  });
});
