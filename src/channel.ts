// Authenticated E2E channel sessions over Noise XX.
//
// Crypto: `Noise_XX_25519_ChaChaPoly_BLAKE2b` from the established
// `noise-handshake` library (JS) — the same protocol `snow` implements in
// Rust. This module adds only application-level conventions ABOVE Noise,
// each documented in contracts/e2e.md. No handshake crypto here.
//
// Identity model (no static-key registry, no TOFU):
// - Noise static keys are FRESH per channel (pure DH randomness). Peer
//   authentication comes from Ed25519 binding signatures over the
//   negotiated transcript hash, keyed to Core JWT identities:
//   - Initiator (Editor) sends its Core-signed grant JWT INSIDE the first
//     encrypted confirm frame. The responder (Forge) verifies that JWT
//     itself (JWKS, sub/mid/scope/expiry — same rules as Relay admission)
//     and takes the verified `cnf` key as the initiator's identity.
//   - The responder signs with its enrolled machine `cnf` key, which the
//     initiator already holds from the authenticated Core machine record.
// - `cnf` material forwarded by Relay is NEVER trusted directly; both
//   binding keys are independently verified (in-confirm JWT, Core record).
// - MITM (e.g. malicious Relay substituting handshake keys) fails the
//   transcript-hash comparison before signatures even matter.
//
// Transport model: one ordered WebSocket per direction; reconnects always
// start a NEW channel. Standard sequential Noise nonces — no explicit
// nonces, no reorder windows. Any violation (AEAD failure, seq gap, kind
// violation, confirmation failure) destroys the session (fail-closed).
//
// Security properties (accurate):
// - Mutual authentication via transcript-bound Ed25519 signatures.
// - Forward secrecy for recorded sessions: XX mixes only ephemeral-
//   involving DHs; fresh statics per channel add margin. Later `cnf`-key
//   compromise does not decrypt recorded sessions.
// - NO post-compromise security within a live session. Rotation is
//   ENFORCED (seal() throws once due; needsRotation() for proactive turn).
// - Directional transport keys; reflection fails AEAD by construction.

import NoiseState from "noise-handshake";
import type { NoiseKeyPair, NoiseOpts } from "noise-handshake";
import CipherState from "noise-handshake/cipher";
import dhCurve from "noise-handshake/dh";
import { ed25519 } from "@noble/curves/ed25519.js";

export const NOISE_PROTOCOL = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
export const PROLOGUE_DOMAIN = "ast-relay-noise-v1";
export const BIND_DOMAIN = "ast-relay-bind-v1";
export const ROLE_INITIATOR = 0x01;
export const ROLE_RESPONDER = 0x02;
export const APP_MAGIC = "AR1";
export const KIND_CONFIRM = 0x00;
export const KIND_DATA = 0x01;
/** Plaintext cap per transport message (Noise cap 65535 incl. 16B tag). */
export const MAX_APP_PLAINTEXT = 60_000;

/**
 * Exact Relay data-body length (base64url chars, NO padding — b64uEncode
 * strips `=`) that seal() will produce for `plaintextLen` plaintext bytes
 * on `channel` — computable BEFORE sealing (and before any Noise nonce is
 * consumed):
 *   appFrame  = 3 + 1 + 1 + chLen + 1 + pt
 *   noiseCt   = appFrame + 16 (XChaCha20-Poly1305 tag)
 *   body      = 4 * ceil(noiseCt / 3) minus padding chars (2 if ct%3==1,
 *               1 if ct%3==2, 0 if ct%3==0)
 * Throws on over-cap plaintext or over-long channel, same as seal().
 * Pinned exact by test/send-window.test.ts across sizes.
 */
export function sealedFrameSize(channel: string, plaintextLen: number): number {
  const chLen = new TextEncoder().encode(channel).length;
  if (chLen === 0 || chLen > 64) throw new Error("bad channel");
  if (plaintextLen > MAX_APP_PLAINTEXT) throw new Error("message too large, chunk it");
  const noiseCt = 3 + 1 + 1 + chLen + 1 + plaintextLen + 16;
  return 4 * Math.ceil(noiseCt / 3) - (noiseCt % 3 === 1 ? 2 : noiseCt % 3 === 2 ? 1 : 0);
}
/** In-confirm JWT cap (grants are small; bounds confirm parsing). */
export const MAX_GRANT_JWT = 8192;
/** Rotation enforced after this many transport messages per direction. */
export const ROTATE_AFTER_MESSAGES = 1 << 20;
/** Rotation enforced after this age even if quiet. */
export const MAX_SESSION_AGE_MS = 24 * 60 * 60 * 1000;

const te = new TextEncoder();
const td = new TextDecoder();

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

function u16be(n: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, n);
  return out;
}

function readU16be(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset + off, 2).getUint16(0);
}

export type SessionPhase = "handshake" | "confirm" | "open" | "closed";

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

export interface NoiseChannelOpts {
  initiator: boolean;
  /** Fresh X25519 static keypair per channel (identity comes from signatures). */
  staticKeypair: NoiseKeypairBytes;
  /** Own Ed25519 `cnf` secret (32B seed): signs the session binding. */
  cnfSignKey: Uint8Array;
  ctx: ChannelCtx;
  nowMs?: () => number;
  /**
   * Initiator only: Forge's enrolled Ed25519 `cnf` public key, from the
   * authenticated Core machine record. Verifies the responder signature.
   */
  expectedResponderCnf?: Uint8Array;
  /**
   * Responder only: verifies the in-confirm grant JWT and returns its
   * `cnf` public key. Never accept Relay-forwarded keys here.
   */
  verifyChannelJwt?: VerifyChannelJwt;
  /**
   * Initiator only: own Core-signed grant JWT, sent inside the encrypted
   * confirm frame for the responder to verify.
   */
  ownGrantJwt?: string;
  /**
   * Fixture-generation hook only: overrides the Noise curve backend
   * (e.g. deterministic ephemerals for byte-frozen vectors). Production
   * MUST NOT pass this; live interop always uses the library default.
   */
  noiseOpts?: NoiseOpts;
}

/**
 * One E2E channel. The channel opener MUST construct with initiator=true;
 * in the Relay topology the opener is always the client (Editor); Forge is
 * responder. (Forge-opened channels in future: opener still initiates.)
 */
export class NoiseChannel {
  private hs: NoiseState;
  private sendCipher: CipherState | null = null;
  private recvCipher: CipherState | null = null;
  private handshakeHash: Uint8Array | null = null;
  private cnfSignKey: Uint8Array;
  private expectedResponderCnf: Uint8Array | null;
  private verifyChannelJwt: VerifyChannelJwt | null;
  private ownGrantJwt: string | null;
  private phase: SessionPhase = "handshake";
  private sentHandshake = 0;
  private receivedHandshake = 0;
  private confirmSent = false;
  private confirmReceived = false;
  private sentCount = 0;
  private recvCount = 0;
  private pendingOutbound: Uint8Array[] = [];
  private readonly bornAt: number;
  private readonly nowMs: () => number;
  readonly ctx: ChannelCtx;
  readonly initiator: boolean;

  constructor(opts: NoiseChannelOpts) {
    if (opts.initiator && (!opts.expectedResponderCnf || !opts.ownGrantJwt)) {
      throw new Error("initiator needs expectedResponderCnf and ownGrantJwt");
    }
    if (!opts.initiator && !opts.verifyChannelJwt) {
      throw new Error("responder needs verifyChannelJwt");
    }
    this.initiator = opts.initiator;
    this.ctx = opts.ctx;
    this.nowMs = opts.nowMs ?? Date.now;
    this.bornAt = this.nowMs();
    this.cnfSignKey = opts.cnfSignKey;
    this.expectedResponderCnf = opts.expectedResponderCnf ?? null;
    this.verifyChannelJwt = opts.verifyChannelJwt ?? null;
    this.ownGrantJwt = opts.ownGrantJwt ?? null;
    this.hs = new NoiseState(
      "XX",
      opts.initiator,
      // Copies: the library aliases key buffers internally; caller buffers
      // must never be mutated by the session.
      {
        publicKey: Uint8Array.from(opts.staticKeypair.publicKey),
        secretKey: Uint8Array.from(opts.staticKeypair.secretKey),
      },
      opts.noiseOpts,
    );
    this.hs.initialise(prologueBytes(opts.ctx));
  }

  getPhase(): SessionPhase {
    return this.phase;
  }

  // -- handshake (payloads empty; identity binds in confirm frames) --------

  /** Produce the next handshake message (throws if not our turn). */
  nextHandshakeMessage(): Uint8Array {
    if (this.phase !== "handshake") throw new Error("handshake already done");
    const expectSend =
      (this.initiator && this.sentHandshake === this.receivedHandshake) ||
      (!this.initiator && this.sentHandshake < this.receivedHandshake);
    if (!expectSend) throw new Error("not our handshake turn");
    const out = Uint8Array.from(this.hs.send(new Uint8Array(0)));
    this.sentHandshake++;
    if (this.hs.complete) this.onHandshakeComplete();
    return out;
  }

  /** Consume a peer handshake message. */
  receiveHandshakeMessage(msg: Uint8Array): void {
    if (this.phase !== "handshake") throw new Error("handshake already done");
    if (msg.length === 0 || msg.length > 65535) throw new Error("bad handshake message length");
    // Defensive copy: noise-handshake aliases the input (TOK_E stores a
    // subarray view) and _clear() zero-fills it on completion. Without this
    // copy the library mutates CALLER buffers (it zeroed our m1/m2 fixture
    // vectors before this fix). Live sessions are unaffected either way,
    // but fixture evidence and caller buffers must stay intact.
    try {
      this.hs.recv(Uint8Array.from(msg));
    } catch {
      this.destroy();
      throw new Error("handshake failed, session destroyed");
    }
    this.receivedHandshake++;
    if (this.hs.complete) this.onHandshakeComplete();
  }

  private onHandshakeComplete(): void {
    const tx = this.hs.tx;
    const rx = this.hs.rx;
    const hash = this.hs.hash;
    if (!tx || !rx || !hash || hash.length !== 64) {
      this.destroy();
      throw new Error("missing transport keys");
    }
    this.sendCipher = new CipherState(Uint8Array.from(tx));
    this.recvCipher = new CipherState(Uint8Array.from(rx));
    this.handshakeHash = Uint8Array.from(hash);
    this.phase = "confirm";
    // Initiator speaks first in confirmation.
    if (this.initiator) void this.emitConfirm();
  }

  private async emitConfirm(): Promise<void> {
    if (!this.sendCipher || !this.handshakeHash) throw new Error("no keys");
    let body: Uint8Array;
    if (this.initiator) {
      if (!this.ownGrantJwt) throw new Error("no grant JWT");
      const jwtBytes = te.encode(this.ownGrantJwt);
      if (jwtBytes.length === 0 || jwtBytes.length > MAX_GRANT_JWT) {
        throw new Error("bad grant JWT length");
      }
      const sig = ed25519.sign(bindingMessage(ROLE_INITIATOR, this.handshakeHash), this.cnfSignKey);
      body = new Uint8Array(64 + 2 + jwtBytes.length + 64);
      body.set(this.handshakeHash, 0);
      body.set(u16be(jwtBytes.length), 64);
      body.set(jwtBytes, 66);
      body.set(sig, 66 + jwtBytes.length);
    } else {
      const sig = ed25519.sign(bindingMessage(ROLE_RESPONDER, this.handshakeHash), this.cnfSignKey);
      body = new Uint8Array(64 + 64);
      body.set(this.handshakeHash, 0);
      body.set(sig, 64);
    }
    const pt = this.frame(KIND_CONFIRM, this.ctx.channel, body);
    const ct = Uint8Array.from(this.sendCipher.encrypt(pt));
    this.sentCount++;
    this.pendingOutbound.push(ct);
    this.confirmSent = true;
  }

  /** Confirm-frame ciphertexts produced by the session (sequential nonces). */
  takeOutbound(): Uint8Array[] {
    const out = this.pendingOutbound;
    this.pendingOutbound = [];
    return out;
  }

  /**
   * Decrypt one transport ciphertext (sequential Noise nonce).
   * Returns app data, or null for confirmation frames. Confirmation is
   * async (JWT verification); poll takeOutbound()/getPhase() after.
   * ANY failure destroys the session (fail-closed).
   */
  receiveTransport(ct: Uint8Array): Uint8Array | null {
    if (this.phase !== "confirm" && this.phase !== "open") {
      throw new Error("session not ready for transport");
    }
    if (!this.recvCipher) throw new Error("no keys");
    if (ct.length === 0 || ct.length > 65535) {
      this.destroy();
      throw new Error("bad transport length");
    }
    let pt: Uint8Array;
    try {
      pt = Uint8Array.from(this.recvCipher.decrypt(ct));
    } catch {
      this.destroy();
      throw new Error("transport decrypt failed, session destroyed");
    }
    this.recvCount++;
    const { kind, body } = this.parseFrame(pt);
    if (kind === KIND_CONFIRM) {
      if (this.phase !== "confirm") {
        this.destroy();
        throw new Error("unexpected confirm, session destroyed");
      }
      // Async (JWT verification on the responder side). Failures destroy
      // the session before rejecting; the rejection itself is swallowed
      // here because callers observe phase/counters, not the promise.
      void this.onConfirm(body).catch(() => {});
      return null;
    }
    // KIND_DATA
    if (this.phase !== "open") {
      this.destroy();
      throw new Error("data before key confirmation, session destroyed");
    }
    // Ordering + replay protection come from the sequential Noise nonce
    // (a lost/reordered message fails AEAD above); the channel string in
    // the frame binds the message to this channel.
    return body;
  }

  private async onConfirm(body: Uint8Array): Promise<void> {
    if (!this.handshakeHash) {
      this.destroy();
      throw new Error("malformed confirm");
    }
    if (this.initiator) {
      // Responder form: hash(64) || sig(64).
      if (body.length !== 128) {
        this.destroy();
        throw new Error("malformed responder confirm");
      }
      const hash = body.subarray(0, 64);
      const sig = body.subarray(64);
      if (!constantTimeEqual(hash, this.handshakeHash)) {
        this.destroy();
        throw new Error("key confirmation failed: transcript mismatch, session aborted");
      }
      if (!this.expectedResponderCnf) {
        this.destroy();
        throw new Error("no responder key");
      }
      let ok = false;
      try {
        ok = ed25519.verify(sig, bindingMessage(ROLE_RESPONDER, this.handshakeHash), this.expectedResponderCnf);
      } catch {
        ok = false;
      }
      if (!ok) {
        this.destroy();
        throw new Error("responder binding signature invalid: not the enrolled Forge");
      }
    } else {
      // Initiator form: hash(64) || jwt_len(u16) || jwt || sig(64).
      if (body.length < 64 + 2 + 16 + 64) {
        this.destroy();
        throw new Error("malformed initiator confirm");
      }
      const hash = body.subarray(0, 64);
      const jwtLen = readU16be(body, 64);
      if (jwtLen === 0 || jwtLen > MAX_GRANT_JWT || 66 + jwtLen + 64 !== body.length) {
        this.destroy();
        throw new Error("malformed initiator confirm JWT framing");
      }
      const jwt = td.decode(body.subarray(66, 66 + jwtLen));
      const sig = body.subarray(66 + jwtLen);
      if (!constantTimeEqual(hash, this.handshakeHash)) {
        this.destroy();
        throw new Error("key confirmation failed: transcript mismatch, session aborted");
      }
      // Verify the grant independently (JWKS, sub/mid/scope/expiry) and
      // take ONLY the verified cnf key — never trust Relay-forwarded keys.
      // nowSec comes from the channel clock (real time in prod; fixture
      // time in deterministic vector generation).
      let cnfPk: Uint8Array;
      try {
        cnfPk = await (this.verifyChannelJwt as VerifyChannelJwt)(jwt, this.ctx, Math.floor(this.nowMs() / 1000));
      } catch {
        this.destroy();
        throw new Error("initiator grant JWT invalid, session aborted");
      }
      let ok = false;
      try {
        ok = ed25519.verify(sig, bindingMessage(ROLE_INITIATOR, this.handshakeHash), cnfPk);
      } catch {
        ok = false;
      }
      if (!ok) {
        this.destroy();
        throw new Error("initiator binding signature invalid: JWT identity does not cover this session");
      }
    }
    this.confirmReceived = true;
    if (!this.initiator && !this.confirmSent) await this.emitConfirm();
    if (this.confirmSent && this.confirmReceived) this.phase = "open";
  }

  /**
   * Seal app data. Rotation is ENFORCED: throws once due — the caller must
   * open a new channel and re-handshake (no post-compromise security is
   * claimed for continued use).
   */
  seal(plaintext: Uint8Array): { ct: Uint8Array } {
    if (this.phase !== "open") throw new Error("session not open");
    if (this.rotationDue()) throw new Error("rotation due: open a new channel");
    if (plaintext.length > MAX_APP_PLAINTEXT) throw new Error("message too large, chunk it");
    if (!this.sendCipher) throw new Error("no keys");
    const framed = this.frame(KIND_DATA, this.ctx.channel, plaintext);
    const ct = Uint8Array.from(this.sendCipher.encrypt(framed));
    this.sentCount++;
    return { ct };
  }

  private frame(kind: number, channel: string, body: Uint8Array): Uint8Array {
    const ch = te.encode(channel);
    if (ch.length === 0 || ch.length > 64) throw new Error("bad channel");
    const out = new Uint8Array(3 + 1 + 1 + ch.length + 1 + body.length);
    let o = 0;
    out.set(te.encode(APP_MAGIC), o);
    o += 3;
    out[o++] = 0x01; // app frame version
    out[o++] = ch.length;
    out.set(ch, o);
    o += ch.length;
    out[o++] = kind;
    out.set(body, o);
    return out;
  }

  private parseFrame(pt: Uint8Array): { kind: number; body: Uint8Array } {
    if (pt.length < 3 + 1 + 1 + 1) throw new Error("frame too short");
    if (td.decode(pt.subarray(0, 3)) !== APP_MAGIC) throw new Error("bad magic");
    if (pt[3] !== 0x01) throw new Error("unsupported frame version");
    const chLen = pt[4] ?? 0;
    if (5 + chLen + 1 > pt.length) throw new Error("frame too short");
    const ch = td.decode(pt.subarray(5, 5 + chLen));
    if (ch !== this.ctx.channel) {
      this.destroy();
      throw new Error("channel mismatch, session destroyed");
    }
    const kind = pt[5 + chLen] ?? 0xff;
    if (kind !== KIND_CONFIRM && kind !== KIND_DATA) throw new Error("unknown kind");
    return { kind, body: Uint8Array.from(pt.subarray(5 + chLen + 1)) };
  }

  private rotationDue(): boolean {
    return this.sentCount + this.recvCount >= ROTATE_AFTER_MESSAGES || this.nowMs() - this.bornAt >= MAX_SESSION_AGE_MS;
  }

  needsRotation(): boolean {
    return this.rotationDue();
  }

  counters(): { sent: number; received: number; phase: SessionPhase } {
    return { sent: this.sentCount, received: this.recvCount, phase: this.phase };
  }

  handshakeHashHex(): string | null {
    if (!this.handshakeHash) return null;
    return [...this.handshakeHash].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /** Best-effort key erasure (JS engine copies may linger; documented limit). */
  destroy(): void {
    this.phase = "closed";
    this.pendingOutbound = [];
    try {
      (this.hs.tx as Uint8Array | null)?.fill(0);
      (this.hs.rx as Uint8Array | null)?.fill(0);
    } catch { /* ignore */ }
    this.sendCipher = null;
    this.recvCipher = null;
    this.handshakeHash?.fill(0);
    this.handshakeHash = null;
    this.cnfSignKey.fill(0);
  }
}
