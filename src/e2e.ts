// Proof-of-possession + device identity keys (Ed25519, @noble/curves).
//
// The E2E session itself is Noise XX (`src/channel.ts`, established
// `noise-handshake` library). This module binds JWT bearers to holders at
// Relay admission: sig = Ed25519(cnf_sk, "ast-relay-auth-v1" || nonce || jti).
// Contract: contracts/e2e.md.

import { ed25519 } from "@noble/curves/ed25519.js";

export const POP_DOMAIN = "ast-relay-auth-v1";

const te = new TextEncoder();
const td = new TextDecoder();

export function popMessage(nonce: Uint8Array, jti: string): Uint8Array {
  const d = te.encode(POP_DOMAIN);
  const j = te.encode(jti);
  const out = new Uint8Array(d.length + nonce.length + j.length);
  out.set(d, 0);
  out.set(nonce, d.length);
  out.set(j, d.length + nonce.length);
  return out;
}

export function popSign(cnfSk: Uint8Array, nonce: Uint8Array, jti: string): Uint8Array {
  return ed25519.sign(popMessage(nonce, jti), cnfSk);
}

export function popVerify(
  cnfPk: Uint8Array,
  nonce: Uint8Array,
  jti: string,
  sig: Uint8Array,
): boolean {
  try {
    return ed25519.verify(sig, popMessage(nonce, jti), cnfPk);
  } catch {
    return false;
  }
}

export function newEd25519Keypair(): { sk: Uint8Array; pk: Uint8Array } {
  const sk = ed25519.utils.randomSecretKey();
  return { sk, pk: ed25519.getPublicKey(sk) };
}

export function encodeUtf8(s: string): Uint8Array {
  return te.encode(s);
}

export function decodeUtf8(b: Uint8Array): string {
  return td.decode(b);
}
