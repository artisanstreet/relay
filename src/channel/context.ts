import type { NoiseKeyPair } from "noise-handshake";
import dhCurve from "noise-handshake/dh";

export const NOISE_PROTOCOL = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
export const PROLOGUE_DOMAIN = "ast-relay-noise-v1";
export const BIND_DOMAIN = "ast-relay-bind-v1";
export const ROLE_INITIATOR = 0x01;
export const ROLE_RESPONDER = 0x02;

const te = new TextEncoder();

export interface ChannelCtx {
  account: string;
  machine: string;
  channel: string;
}

/** Prologue binds account/machine/channel into the handshake hash. */
export function prologueBytes(ctx: ChannelCtx): Uint8Array {
  const parts = [PROLOGUE_DOMAIN, ctx.account, ctx.machine, ctx.channel].map((s) => te.encode(s));
  const total = parts.reduce((n, b) => n + b.length, 0) + parts.length - 1;
  const out = new Uint8Array(total);
  let o = 0;
  parts.forEach((b, i) => {
    out.set(b, o);
    o += b.length;
    if (i < parts.length - 1) out[o++] = 0x00;
  });
  return out;
}

/**
 * Binding message: BIND_DOMAIN || role || handshake_hash.
 * The hash already covers prologue (context) and every handshake byte
 * (both static keys, both ephemerals), so signing it binds the exact
 * negotiated transcript. Role separates initiator/responder signatures.
 */
export function bindingMessage(role: number, handshakeHash: Uint8Array): Uint8Array {
  if (handshakeHash.length !== 64) throw new Error("handshake hash must be 64 bytes");
  const d = te.encode(BIND_DOMAIN);
  const out = new Uint8Array(d.length + 1 + 64);
  out.set(d, 0);
  out[d.length] = role;
  out.set(handshakeHash, d.length + 1);
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return d === 0;
}

/** Responder-side JWT check: returns the verified cnf public key (32B). */
export type VerifyChannelJwt = (jwt: string, ctx: ChannelCtx, nowSec?: number) => Promise<Uint8Array>;

export interface NoiseKeypairBytes {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Fresh (or caller-supplied) X25519 static keypair (same backend). */
export function staticKeypairFromSecret(secretKey: Uint8Array): NoiseKeypairBytes {
  const kp: NoiseKeyPair = dhCurve.generateKeyPair(secretKey);
  return { publicKey: Uint8Array.from(kp.publicKey), secretKey: Uint8Array.from(kp.secretKey) };
}
