// Cross-language fixture vectors (contracts/fixtures/noise-xx.json).
//
// Fully deterministic: fixed static keys, fixed ephemerals (via the
// documented `noiseOpts` fixture hook — production never passes it),
// fixed cnf keys, fixed grant times, fixed prologue. The test asserts
// EXACT bytes, so any silent change in the pinned library or our framing
// fails loudly. Regenerate with UPDATE_FIXTURES=1 (then re-freeze).
//
// NOTE (honest scope): these vectors pin OUR side. They do not prove Rust
// interop by themselves — Noise ephemerals are random per live run. The
// live proof is test/noise-interop.test.ts (JS <-> real snow, same run).

import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  NoiseChannel,
  prologueBytes,
} from "../src/channel.ts";
import { makeChannelJwtVerifier } from "../src/channel-verify.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import realDh from "noise-handshake/dh";
import type { NoiseKeyPair } from "noise-handshake";
import { mintGrant, stubFetch, testCoreKey, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_PATH = join(root, "contracts", "fixtures", "noise-xx.json");

const hex = (b: Uint8Array): string => bytesToHex(b);
const unhex = (s: string): Uint8Array => hexToBytes(s);

// Fixed inputs (arbitrary but frozen; NOT secrets — fixtures only).
const INIT_STATIC_PRIV = "1111111111111111111111111111111111111111111111111111111111111111";
const RESP_STATIC_PRIV = "2222222222222222222222222222222222222222222222222222222222222222";
const INIT_EPH_PRIV = "3333333333333333333333333333333333333333333333333333333333333333";
const RESP_EPH_PRIV = "4444444444444444444444444444444444444444444444444444444444444444";
const INIT_CNF_SEED = "5555555555555555555555555555555555555555555555555555555555555555";
const RESP_CNF_SEED = "6666666666666666666666666666666666666666666666666666666666666666";
const CTX = { account: "acct_01ARZ3NDEKTSV4RRFFQ69G5FAV", machine: "mch_01ARZ3NDEKTSV4RRFFQ69G5FB7", channel: "fixture-ch" };
const GRANT_IAT = 2_000_000_000;
const GRANT_JTI = "fixture-grant-001";
const PLAINTEXT_A = "fixture message initiator to responder";
const PLAINTEXT_B = "fixture reply responder to initiator";

/** Deterministic curve backend: fixed ephemeral sequence, real DH. */
function fixedCurve(ephHex: string[]) {
  const queue = ephHex.map(unhex);
  return {
    DHLEN: 32,
    PKLEN: 32,
    SKLEN: 32,
    ALG: "25519",
    generateKeyPair: () => {
      const sk = queue.shift();
      if (!sk) throw new Error("eph queue exhausted");
      const kp = realDh.generateKeyPair(sk);
      return { publicKey: Uint8Array.from(kp.publicKey), secretKey: Uint8Array.from(sk) };
    },
    dh: (publicKey: Uint8Array, keypair: NoiseKeyPair) => {
      const out = realDh.dh(publicKey, keypair);
      return Uint8Array.from(out);
    },
  };
}

function staticPair(privHex: string) {
  const kp = realDh.generateKeyPair(unhex(privHex));
  return { publicKey: Uint8Array.from(kp.publicKey), secretKey: Uint8Array.from(unhex(privHex)) };
}

interface FixtureFile {
  protocol: string;
  ctx: { account: string; machine: string; channel: string };
  prologue_hex: string;
  init_static_pub: string;
  resp_static_pub: string;
  init_cnf_pub: string;
  resp_cnf_pub: string;
  grant_jwt: string;
  jwks: { keys: unknown[] };
  m1: string;
  m2: string;
  m3: string;
  handshake_hash: string;
  confirm_init_ct: string;
  confirm_resp_ct: string;
  data_init_ct: string;
  data_resp_ct: string;
  plaintext_a: string;
  plaintext_b: string;
}

/** Real-deadline wait for a channel phase. The old fixed 50-tick
 * `setImmediate` spin could elapse before async JWT verification finished
 * under full-suite load, leaving `takeOutbound()[0]` undefined and failing
 * downstream with an opaque `ct.length` TypeError. This waits on wall
 * time and names the stage that timed out. */
async function waitForPhase(
  ch: { getPhase: () => string },
  phase: string,
  what: string,
  timeoutMs = 10_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (ch.getPhase() !== phase) {
    if (Date.now() > deadline) throw new Error(`${what}: timed out waiting for phase ${phase}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function buildFixture(): Promise<FixtureFile> {
  const core = testCoreKey(0x77);
  const initCnfSk = unhex(INIT_CNF_SEED);
  const respCnfSk = unhex(RESP_CNF_SEED);
  const initCnfPk = ed25519.getPublicKey(initCnfSk);
  const respCnfPk = ed25519.getPublicKey(respCnfSk);
  const g = await mintGrant(core, {
    account: CTX.account, machine: CTX.machine, cnfSk: initCnfSk,
    iat: GRANT_IAT, nbf: GRANT_IAT, exp: GRANT_IAT + 120, jti: GRANT_JTI,
  });
  const verify = makeChannelJwtVerifier(
    { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
    stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
  );
  const init = new NoiseChannel({
    initiator: true,
    staticKeypair: staticPair(INIT_STATIC_PRIV),
    cnfSignKey: Uint8Array.from(initCnfSk),
    expectedResponderCnf: respCnfPk,
    ownGrantJwt: g.jwt,
    ctx: CTX,
    nowMs: () => GRANT_IAT * 1000,
    noiseOpts: { curve: fixedCurve([INIT_EPH_PRIV]) as never },
  });
  const resp = new NoiseChannel({
    initiator: false,
    staticKeypair: staticPair(RESP_STATIC_PRIV),
    cnfSignKey: Uint8Array.from(respCnfSk),
    verifyChannelJwt: verify,
    ctx: CTX,
    nowMs: () => GRANT_IAT * 1000,
    noiseOpts: { curve: fixedCurve([RESP_EPH_PRIV]) as never },
  });
  const m1 = init.nextHandshakeMessage();
  resp.receiveHandshakeMessage(m1);
  const m2 = resp.nextHandshakeMessage();
  init.receiveHandshakeMessage(m2);
  const m3 = init.nextHandshakeMessage();
  resp.receiveHandshakeMessage(m3);
  const [cInit] = init.takeOutbound();
  if (!(cInit instanceof Uint8Array)) throw new Error("fixture initiator confirm missing");
  resp.receiveTransport(cInit);
  await waitForPhase(resp, "open", "fixture responder confirm (async JWT verify)", 10_000);
  const [cResp] = resp.takeOutbound();
  if (!(cResp instanceof Uint8Array)) {
    throw new Error("fixture responder confirm missing: channel open but no outbound ciphertext");
  }
  init.receiveTransport(cResp);
  await waitForPhase(init, "open", "fixture initiator confirm", 10_000);
  if (init.getPhase() !== "open" || resp.getPhase() !== "open") throw new Error("fixture channels did not open");
  const dataInit = init.seal(new TextEncoder().encode(PLAINTEXT_A));
  const opened = resp.receiveTransport(dataInit.ct);
  if (new TextDecoder().decode(opened as Uint8Array) !== PLAINTEXT_A) throw new Error("fixture data mismatch");
  const dataResp = resp.seal(new TextEncoder().encode(PLAINTEXT_B));
  const openedB = init.receiveTransport(dataResp.ct);
  if (new TextDecoder().decode(openedB as Uint8Array) !== PLAINTEXT_B) throw new Error("fixture data mismatch");
  return {
    protocol: "Noise_XX_25519_ChaChaPoly_BLAKE2b",
    ctx: { ...CTX },
    prologue_hex: hex(prologueBytes(CTX)),
    init_static_pub: hex(staticPair(INIT_STATIC_PRIV).publicKey),
    resp_static_pub: hex(staticPair(RESP_STATIC_PRIV).publicKey),
    init_cnf_pub: hex(initCnfPk),
    resp_cnf_pub: hex(respCnfPk),
    grant_jwt: g.jwt,
    jwks: { keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }] },
    m1: hex(m1),
    m2: hex(m2),
    m3: hex(m3),
    handshake_hash: init.handshakeHashHex() as string,
    confirm_init_ct: hex(cInit as Uint8Array),
    confirm_resp_ct: hex(cResp as Uint8Array),
    data_init_ct: hex(dataInit.ct),
    data_resp_ct: hex(dataResp.ct),
    plaintext_a: PLAINTEXT_A,
    plaintext_b: PLAINTEXT_B,
  };
}

describe("fixture vectors", () => {
  it("matches committed bytes exactly (or regenerates with UPDATE_FIXTURES=1)", async () => {
    const built = await buildFixture();
    if (process.env["UPDATE_FIXTURES"] === "1") {
      mkdirSync(dirname(FIXTURE_PATH), { recursive: true });
      writeFileSync(FIXTURE_PATH, JSON.stringify(built, null, 2) + "\n");
    }
    const committed = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as FixtureFile;
    expect(built).toEqual(committed);
  }, 30_000);
});
