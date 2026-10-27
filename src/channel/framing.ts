export const APP_MAGIC = "AR1";
export const KIND_CONFIRM = 0x00;
export const KIND_DATA = 0x01;
/** Plaintext cap per transport message (Noise cap 65535 incl. 16B tag). */
export const MAX_APP_PLAINTEXT = 60_000;

/**
 * Exact Relay data-body length (base64url chars, NO padding — b64u_encode
 * strips `=`) that seal() will produce for `plaintext_len` plaintext bytes
 * on `channel` — computable BEFORE sealing (and before any Noise nonce is
 * consumed):
 *   appFrame  = 3 + 1 + 1 + ch_len + 1 + pt
 *   noise_ct   = appFrame + 16 (XChaCha20-Poly1305 tag)
 *   body      = 4 * ceil(noise_ct / 3) minus padding chars (2 if ct%3==1,
 *               1 if ct%3==2, 0 if ct%3==0)
 * Throws on over-cap plaintext or over-long channel, same as seal().
 * Pinned exact by test/send-window.test.ts across sizes.
 */
export function sealed_frame_size(channel: string, plaintext_len: number): number {
  const ch_len = new TextEncoder().encode(channel).length;
  if (ch_len === 0 || ch_len > 64) throw new Error("bad channel");
  if (plaintext_len > MAX_APP_PLAINTEXT) throw new Error("message too large, chunk it");
  const noise_ct = 3 + 1 + 1 + ch_len + 1 + plaintext_len + 16;
  return 4 * Math.ceil(noise_ct / 3) - (noise_ct % 3 === 1 ? 2 : noise_ct % 3 === 2 ? 1 : 0);
}
/** In-confirm JWT cap (grants are small; bounds confirm parsing). */
export const MAX_GRANT_JWT = 8192;

export function u16be(n: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, n);
  return out;
}

export function read_u16be(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset + off, 2).getUint16(0);
}
