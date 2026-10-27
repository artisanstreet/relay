// Cross-language fixture vectors (contracts/fixtures/noise-xx.json).
//
// Fully deterministic: fixed static keys, fixed ephemerals (via the
// documented `noise_opts` fixture hook — production never passes it),
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
  prologue_bytes,
} from "../src/channel.ts";
import { make_channel_jwt_verifier } from "../src/channel-verify.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes as hex_to_bytes, bytesToHex as bytes_to_hex } from "@noble/hashes/utils.js";
import real_dh from "noise-handshake/dh";
import type { NoiseKeyPair } from "noise-handshake";
import { mint_grant, stub_fetch, test_core_key, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_PATH = join(root, "contracts", "fixtures", "noise-xx.json");

const hex = (b: Uint8Array): string => bytes_to_hex(b);
const unhex = (s: string): Uint8Array => hex_to_bytes(s);

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
function fixed_curve(eph_hex: string[]) {
  const queue = eph_hex.map(unhex);
  return {
    DHLEN: 32,
    PKLEN: 32,
    SKLEN: 32,
    ALG: "25519",
    generateKeyPair: () => {
      const sk = queue.shift();
      if (!sk) throw new Error("eph queue exhausted");
      const kp = real_dh.generateKeyPair(sk);
      return { publicKey: Uint8Array.from(kp.publicKey), secretKey: Uint8Array.from(sk) };
    },
    dh: (public_key: Uint8Array, keypair: NoiseKeyPair) => {
      const out = real_dh.dh(public_key, keypair);
      return Uint8Array.from(out);
    },
  };
}

function static_pair(priv_hex: string) {
  const kp = real_dh.generateKeyPair(unhex(priv_hex));
  return { public_key: Uint8Array.from(kp.publicKey), secret_key: Uint8Array.from(unhex(priv_hex)) };
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
 * under full-suite load, leaving `take_outbound()[0]` undefined and failing
 * downstream with an opaque `ct.length` TypeError. This waits on wall
 * time and names the stage that timed out. */
async function wait_for_phase(
  ch: { get_phase: () => string },
  phase: string,
  what: string,
  timeout_ms = 10_000,
): Promise<void> {
  const deadline = Date.now() + timeout_ms;
  while (ch.get_phase() !== phase) {
    if (Date.now() > deadline) throw new Error(`${what}: timed out waiting for phase ${phase}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function build_fixture(): Promise<FixtureFile> {
  const core = test_core_key(0x77);
  const init_cnf_sk = unhex(INIT_CNF_SEED);
  const resp_cnf_sk = unhex(RESP_CNF_SEED);
  const init_cnf_pk = ed25519.getPublicKey(init_cnf_sk);
  const resp_cnf_pk = ed25519.getPublicKey(resp_cnf_sk);
  const g = await mint_grant(core, {
    account: CTX.account, machine: CTX.machine, cnf_sk: init_cnf_sk,
    iat: GRANT_IAT, nbf: GRANT_IAT, exp: GRANT_IAT + 120, jti: GRANT_JTI,
  });
  const verify = make_channel_jwt_verifier(
    { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
    stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
  );
  const init = new NoiseChannel({
    initiator: true,
    static_keypair: static_pair(INIT_STATIC_PRIV),
    cnf_sign_key: Uint8Array.from(init_cnf_sk),
    expected_responder_cnf: resp_cnf_pk,
    own_grant_jwt: g.jwt,
    ctx: CTX,
    now_ms: () => GRANT_IAT * 1000,
    noise_opts: { curve: fixed_curve([INIT_EPH_PRIV]) as never },
  });
  const resp = new NoiseChannel({
    initiator: false,
    static_keypair: static_pair(RESP_STATIC_PRIV),
    cnf_sign_key: Uint8Array.from(resp_cnf_sk),
    verify_channel_jwt: verify,
    ctx: CTX,
    now_ms: () => GRANT_IAT * 1000,
    noise_opts: { curve: fixed_curve([RESP_EPH_PRIV]) as never },
  });
  const m1 = init.next_handshake_message();
  resp.receive_handshake_message(m1);
  const m2 = resp.next_handshake_message();
  init.receive_handshake_message(m2);
  const m3 = init.next_handshake_message();
  resp.receive_handshake_message(m3);
  const [c_init] = init.take_outbound();
  if (!(c_init instanceof Uint8Array)) throw new Error("fixture initiator confirm missing");
  resp.receive_transport(c_init);
  await wait_for_phase(resp, "open", "fixture responder confirm (async JWT verify)", 10_000);
  const [c_resp] = resp.take_outbound();
  if (!(c_resp instanceof Uint8Array)) {
    throw new Error("fixture responder confirm missing: channel open but no outbound ciphertext");
  }
  init.receive_transport(c_resp);
  await wait_for_phase(init, "open", "fixture initiator confirm", 10_000);
  if (init.get_phase() !== "open" || resp.get_phase() !== "open") throw new Error("fixture channels did not open");
  const data_init = init.seal(new TextEncoder().encode(PLAINTEXT_A));
  const opened = resp.receive_transport(data_init.ct);
  if (new TextDecoder().decode(opened as Uint8Array) !== PLAINTEXT_A) throw new Error("fixture data mismatch");
  const data_resp = resp.seal(new TextEncoder().encode(PLAINTEXT_B));
  const opened_b = init.receive_transport(data_resp.ct);
  if (new TextDecoder().decode(opened_b as Uint8Array) !== PLAINTEXT_B) throw new Error("fixture data mismatch");
  return {
    protocol: "Noise_XX_25519_ChaChaPoly_BLAKE2b",
    ctx: { ...CTX },
    prologue_hex: hex(prologue_bytes(CTX)),
    init_static_pub: hex(static_pair(INIT_STATIC_PRIV).public_key),
    resp_static_pub: hex(static_pair(RESP_STATIC_PRIV).public_key),
    init_cnf_pub: hex(init_cnf_pk),
    resp_cnf_pub: hex(resp_cnf_pk),
    grant_jwt: g.jwt,
    jwks: { keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }] },
    m1: hex(m1),
    m2: hex(m2),
    m3: hex(m3),
    handshake_hash: init.handshake_hash_hex() as string,
    confirm_init_ct: hex(c_init as Uint8Array),
    confirm_resp_ct: hex(c_resp as Uint8Array),
    data_init_ct: hex(data_init.ct),
    data_resp_ct: hex(data_resp.ct),
    plaintext_a: PLAINTEXT_A,
    plaintext_b: PLAINTEXT_B,
  };
}

describe("fixture vectors", () => {
  it("matches committed bytes exactly (or regenerates with UPDATE_FIXTURES=1)", async () => {
    const built = await build_fixture();
    if (process.env["UPDATE_FIXTURES"] === "1") {
      mkdirSync(dirname(FIXTURE_PATH), { recursive: true });
      writeFileSync(FIXTURE_PATH, JSON.stringify(built, null, 2) + "\n");
    }
    const committed = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as FixtureFile;
    expect(built).toEqual(committed);
  }, 30_000);
});
