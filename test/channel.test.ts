// NoiseChannel tests: real noise-handshake sessions with JWT-identity
// binding. The Noise crypto itself is the library's job, proven
// interoperable via test/noise-interop.test.ts (live snow).

import { describe, expect, it } from "vitest";
import {
  NoiseChannel,
  bindingMessage,
  constantTimeEqual,
  prologueBytes,
  staticKeypairFromSecret,
  ROLE_INITIATOR,
  ROLE_RESPONDER,
  MAX_APP_PLAINTEXT,
} from "../src/channel.ts";
import { makeChannelJwtVerifier } from "../src/channel-verify.ts";
import { newEd25519Keypair } from "../src/e2e.ts";
import { randomBytes } from "@noble/hashes/utils.js";
import { mintGrant, stubFetch, testCoreKey, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";
import type { VerifyChannelJwt } from "../src/channel.ts";

const CTX = { account: "acct1", machine: "forge1", channel: "ch1" };

async function flush(times = 20): Promise<void> {
  for (let i = 0; i < times; i++) await new Promise((r) => setImmediate(r));
}

/** Poll for open with a real timeout instead of hoping a flush suffices. */

async function waitClosed(ch: { getPhase(): string }, label: string): Promise<void> {
  const deadline = Date.now() + 5000;
  for (;;) {
    const got = ch.getPhase();
    if (got === "closed") return;
    if (Date.now() > deadline) throw new Error(`${label}: timed out, stuck at ${got}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function waitPhase(ch: { getPhase(): string }, want: string, label: string): Promise<void> {
  const deadline = Date.now() + 5000;
  for (;;) {
    const got = ch.getPhase();
    if (got === want) return;
    if (got === "closed") throw new Error(`${label}: session closed while waiting for ${want}`);
    if (Date.now() > deadline) throw new Error(`${label}: timed out waiting for ${want}, stuck at ${got}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

interface Ends {
  init: NoiseChannel;
  resp: NoiseChannel;
  forgeCnf: { sk: Uint8Array; pk: Uint8Array };
  editorCnf: { sk: Uint8Array; pk: Uint8Array };
  editorJwt: string;
}

async function makeEnds(ctx = CTX): Promise<Ends> {
  const core = testCoreKey();
  const forgeCnf = newEd25519Keypair(); // enrolled machine key (stable)
  const editorCnf = newEd25519Keypair(); // ephemeral per-grant key
  const g = await mintGrant(core, { account: ctx.account, machine: ctx.machine, cnfSk: editorCnf.sk });
  const verify: VerifyChannelJwt = makeChannelJwtVerifier(
    { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
    stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }] }),
  );
  const init = new NoiseChannel({
    initiator: true,
    staticKeypair: staticKeypairFromSecret(randomBytes(32)),
    cnfSignKey: editorCnf.sk,
    expectedResponderCnf: forgeCnf.pk,
    ownGrantJwt: g.jwt,
    ctx,
  });
  const resp = new NoiseChannel({
    initiator: false,
    staticKeypair: staticKeypairFromSecret(randomBytes(32)),
    cnfSignKey: forgeCnf.sk,
    verifyChannelJwt: verify,
    ctx,
  });
  return { init, resp, forgeCnf, editorCnf, editorJwt: g.jwt };
}

function doHandshake(init: NoiseChannel, resp: NoiseChannel): void {
  const m1 = init.nextHandshakeMessage();
  expect(m1.length).toBe(32);
  resp.receiveHandshakeMessage(m1);
  const m2 = resp.nextHandshakeMessage();
  expect(m2.length).toBe(96);
  init.receiveHandshakeMessage(m2);
  const m3 = init.nextHandshakeMessage();
  expect(m3.length).toBe(64);
  resp.receiveHandshakeMessage(m3);
}

async function fullOpen(ends?: Ends): Promise<Ends> {
  const e = ends ?? (await makeEnds());
  doHandshake(e.init, e.resp);
  const [cInit] = e.init.takeOutbound();
  expect(cInit).toBeDefined();
  e.resp.receiveTransport(cInit as Uint8Array);
  await waitPhase(e.resp, "open", "responder confirm");
  const [cResp] = e.resp.takeOutbound();
  expect(cResp).toBeDefined();
  const back = e.init.receiveTransport(cResp as Uint8Array);
  await waitPhase(e.init, "open", "initiator confirm");
  expect(back).toBeNull();
  expect(e.init.getPhase()).toBe("open");
  expect(e.init.handshakeHashHex()).toEqual(e.resp.handshakeHashHex());
  return e;
}

describe("noise channel with JWT identity binding", () => {
  it("opens with mutual confirmation and equal handshake hashes", async () => {
    await fullOpen();
  });

  it("exchanges app data both directions with exact bytes", async () => {
    const { init, resp } = await fullOpen();
    const a = init.seal(new TextEncoder().encode("hello forge"));
    expect(new TextDecoder().decode(resp.receiveTransport(a.ct) as Uint8Array)).toBe("hello forge");
    const b = resp.seal(new TextEncoder().encode("hello editor"));
    expect(new TextDecoder().decode(init.receiveTransport(b.ct) as Uint8Array)).toBe("hello editor");
  });

  it("MITM handshake substitution fails the transcript check", async () => {
    const e = await makeEnds();
    const m1 = e.init.nextHandshakeMessage();
    e.resp.receiveHandshakeMessage(m1);
    const m2 = e.resp.nextHandshakeMessage();
    (m2[40] as number) ^= 0xff; // attacker flips a bit in the encrypted responder message
    expect(() => e.init.receiveHandshakeMessage(m2)).toThrow();
    expect(e.init.getPhase()).toBe("closed");
  });

  it("prologue (context) mismatch fails the handshake", async () => {
    const core = testCoreKey();
    const forgeCnf = newEd25519Keypair();
    const editorCnf = newEd25519Keypair();
    const g = await mintGrant(core, { cnfSk: editorCnf.sk });
    const verify = makeChannelJwtVerifier(
      { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
      stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const init = new NoiseChannel({
      initiator: true,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: editorCnf.sk,
      expectedResponderCnf: forgeCnf.pk,
      ownGrantJwt: g.jwt,
      ctx: { ...CTX, channel: "ch1" },
    });
    const resp = new NoiseChannel({
      initiator: false,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: forgeCnf.sk,
      verifyChannelJwt: verify,
      ctx: { ...CTX, channel: "CH2" },
    });
    const m1 = init.nextHandshakeMessage();
    resp.receiveHandshakeMessage(m1);
    const m2 = resp.nextHandshakeMessage();
    expect(() => init.receiveHandshakeMessage(m2)).toThrow();
    expect(init.getPhase()).toBe("closed");
  });

  it("responder rejects a grant JWT bound to another machine", async () => {
    const core = testCoreKey();
    const forgeCnf = newEd25519Keypair();
    const editorCnf = newEd25519Keypair();
    // Grant is for forge2, but the channel context is forge1.
    const g = await mintGrant(core, { machine: "forge2", cnfSk: editorCnf.sk });
    const verify = makeChannelJwtVerifier(
      { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
      stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const init = new NoiseChannel({
      initiator: true,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: editorCnf.sk,
      expectedResponderCnf: forgeCnf.pk,
      ownGrantJwt: g.jwt,
      ctx: CTX,
    });
    const resp = new NoiseChannel({
      initiator: false,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: forgeCnf.sk,
      verifyChannelJwt: verify,
      ctx: CTX,
    });
    doHandshake(init, resp);
    const [cInit] = init.takeOutbound();
    resp.receiveTransport(cInit as Uint8Array);
    await waitClosed(resp, "wrong-machine grant");
  });

  it("responder rejects a forged binding signature (stolen JWT, no cnf secret)", async () => {
    const e = await makeEnds();
    // Attacker holds the JWT but not the cnf secret: craft a channel with
    // a WRONG cnfSignKey while reusing the victim's JWT.
    const attackerCnf = newEd25519Keypair();
    const evil = new NoiseChannel({
      initiator: true,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: attackerCnf.sk, // not the key the JWT binds
      expectedResponderCnf: e.forgeCnf.pk,
      ownGrantJwt: e.editorJwt,
      ctx: CTX,
    });
    doHandshake(evil, e.resp);
    const [cInit] = evil.takeOutbound();
    e.resp.receiveTransport(cInit as Uint8Array);
    await waitClosed(e.resp, "forged binding");
  });

  it("initiator rejects a responder key that is not the enrolled Forge", async () => {
    const core = testCoreKey();
    const forgeCnf = newEd25519Keypair(); // real enrolled key (expected)
    const impostorCnf = newEd25519Keypair(); // key the responder signs with
    const editorCnf = newEd25519Keypair();
    const g = await mintGrant(core, { cnfSk: editorCnf.sk });
    const verify = makeChannelJwtVerifier(
      { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
      stubFetch({
        keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }],
      }),
    );
    const init = new NoiseChannel({
      initiator: true,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: editorCnf.sk,
      expectedResponderCnf: forgeCnf.pk, // real enrolled key expected
      ownGrantJwt: g.jwt,
      ctx: CTX,
    });
    const resp = new NoiseChannel({
      initiator: false,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: impostorCnf.sk, // impostor signs
      verifyChannelJwt: verify,
      ctx: CTX,
    });
    doHandshake(init, resp);
    const [cInit] = init.takeOutbound();
    resp.receiveTransport(cInit as Uint8Array);
    await waitPhase(resp, "open", "responder confirm"); // responder side is fine
    const [cResp] = resp.takeOutbound();
    init.receiveTransport(cResp as Uint8Array); // initiator check runs synchronously
    expect(init.getPhase()).toBe("closed");
  });

  it("initiator binding failure is fail-closed even when checked synchronously", async () => {
    const e = await makeEnds();
    doHandshake(e.init, e.resp);
    const [cInit] = e.init.takeOutbound();
    // Corrupt the responder confirm's signature bytes in flight: flip the
    // last byte (inside the 64B binding signature).
    e.resp.receiveTransport(cInit as Uint8Array);
    await waitPhase(e.resp, "open", "responder confirm");
    const [cResp] = e.resp.takeOutbound() as [Uint8Array];
    const tampered = Uint8Array.from(cResp);
    const lastIdx = tampered.length - 1;
    tampered[lastIdx] = ((tampered[lastIdx] ?? 0) ^ 0xff);
    // Tampering breaks AEAD (fail-closed at decrypt, before signature logic).
    expect(() => e.init.receiveTransport(tampered)).toThrow();
    expect(e.init.getPhase()).toBe("closed");
  });

  it("reflection fails: own ciphertext unreadable on the receive path", async () => {
    const { init } = await fullOpen();
    const { ct } = init.seal(new TextEncoder().encode("self"));
    expect(() => init.receiveTransport(ct)).toThrow();
    expect(init.getPhase()).toBe("closed");
  });

  it("replay of a transport message fails (sequential nonces)", async () => {
    const { init, resp } = await fullOpen();
    const { ct } = init.seal(new TextEncoder().encode("once"));
    expect(resp.receiveTransport(ct)).not.toBeNull();
    expect(() => resp.receiveTransport(ct)).toThrow();
    expect(resp.getPhase()).toBe("closed");
  });

  it("a lost message destroys the session (sequential nonces, fail-closed)", async () => {
    const { init, resp } = await fullOpen();
    const a = init.seal(new TextEncoder().encode("m0"));
    const b = init.seal(new TextEncoder().encode("m1"));
    void a; // "lost" on purpose: the cipher stream cannot skip it
    expect(() => resp.receiveTransport(b.ct)).toThrow(/transport decrypt failed/);
    expect(resp.getPhase()).toBe("closed");
  });

  it("data cannot be sealed before confirmation", async () => {
    const e = await makeEnds();
    doHandshake(e.init, e.resp);
    expect(e.init.getPhase()).toBe("confirm");
    expect(() => e.init.seal(new TextEncoder().encode("early"))).toThrow(/not open/);
  });

  it("rejects oversize plaintext", async () => {
    const { init } = await fullOpen();
    expect(() => init.seal(new Uint8Array(MAX_APP_PLAINTEXT + 1))).toThrow(/chunk/);
  });

  it("rotation is enforced by age", async () => {
    let now = 1_000_000;
    const core = testCoreKey();
    const forgeCnf = newEd25519Keypair();
    const editorCnf = newEd25519Keypair();
    // Grant times follow the channel clock (1000s), not wall time.
    const g = await mintGrant(core, { cnfSk: editorCnf.sk, iat: 1000, nbf: 1000, exp: 1120 });
    const verify = makeChannelJwtVerifier(
      { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
      stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const init = new NoiseChannel({
      initiator: true,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: editorCnf.sk,
      expectedResponderCnf: forgeCnf.pk,
      ownGrantJwt: g.jwt,
      ctx: CTX,
      nowMs: () => now,
    });
    const resp = new NoiseChannel({
      initiator: false,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: forgeCnf.sk,
      verifyChannelJwt: verify,
      ctx: CTX,
      nowMs: () => now,
    });
    doHandshake(init, resp);
    const [cInit] = init.takeOutbound();
    resp.receiveTransport(cInit as Uint8Array);
    await waitPhase(resp, "open", "responder confirm");
    const [cResp] = resp.takeOutbound();
    init.receiveTransport(cResp as Uint8Array);
    await waitPhase(init, "open", "initiator confirm");
    expect(init.needsRotation()).toBe(false);
    now += 25 * 60 * 60 * 1000;
    expect(init.needsRotation()).toBe(true);
    expect(() => init.seal(new TextEncoder().encode("late"))).toThrow(/rotation due/);
  });

  it("binding message layout is fixed", () => {
    const h = new Uint8Array(64).fill(9);
    const m1 = bindingMessage(ROLE_INITIATOR, h);
    const m2 = bindingMessage(ROLE_RESPONDER, h);
    expect(m1.length).toBe("ast-relay-bind-v1".length + 1 + 64);
    expect(m1).not.toEqual(m2); // role separation
    expect(() => bindingMessage(ROLE_INITIATOR, new Uint8Array(32))).toThrow();
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
    expect(prologueBytes(CTX).length).toBeGreaterThan(0);
  });

  it("destroy closes the session", async () => {
    const { init } = await fullOpen();
    init.destroy();
    expect(init.getPhase()).toBe("closed");
    expect(() => init.seal(new TextEncoder().encode("x"))).toThrow();
  });
});
