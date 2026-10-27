import NoiseState from "noise-handshake";
import type { NoiseOpts } from "noise-handshake";
import CipherState from "noise-handshake/cipher";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Either } from "effect";
import {
  BIND_DOMAIN,
  ROLE_INITIATOR,
  ROLE_RESPONDER,
  bindingMessage,
  constantTimeEqual,
  prologueBytes,
} from "./context.ts";
import type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt } from "./context.ts";
import {
  APP_MAGIC,
  KIND_CONFIRM,
  KIND_DATA,
  MAX_APP_PLAINTEXT,
  MAX_GRANT_JWT,
  readU16be,
  u16be,
} from "./framing.ts";

/** Rotation enforced after this many transport messages per direction. */
export const ROTATE_AFTER_MESSAGES = 1 << 20;
/** Rotation enforced after this age even if quiet. */
export const MAX_SESSION_AGE_MS = 24 * 60 * 60 * 1000;

const te = new TextEncoder();
const td = new TextDecoder();

export type SessionPhase = "handshake" | "confirm" | "open" | "closed";

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
    Either.match(Either.try({ try: () => this.hs.recv(Uint8Array.from(msg)), catch: () => undefined }), {
      onLeft: (): never => {
        this.destroy();
        throw new Error("handshake failed, session destroyed");
      },
      onRight: () => undefined,
    });
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
    const recv_cipher = this.recvCipher;
    if (ct.length === 0 || ct.length > 65535) {
      this.destroy();
      throw new Error("bad transport length");
    }
    const pt: Uint8Array = Either.match(
      Either.try({ try: () => Uint8Array.from(recv_cipher.decrypt(ct)), catch: () => undefined }),
      {
        onLeft: (): never => {
          this.destroy();
          throw new Error("transport decrypt failed, session destroyed");
        },
        onRight: (right) => right,
      },
    );
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
    const transcript = this.handshakeHash;
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
      const expected_cnf = this.expectedResponderCnf;
      const ok = Either.getOrElse(
        Either.try({
          try: () => ed25519.verify(sig, bindingMessage(ROLE_RESPONDER, transcript), expected_cnf),
          catch: () => false,
        }),
        (fallback) => fallback,
      );
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
      const cnfPk: Uint8Array = await (this.verifyChannelJwt as VerifyChannelJwt)(
        jwt,
        this.ctx,
        Math.floor(this.nowMs() / 1000),
      ).then(
        (pk) => pk,
        (): never => {
          this.destroy();
          throw new Error("initiator grant JWT invalid, session aborted");
        },
      );
      const ok = Either.getOrElse(
        Either.try({
          try: () => ed25519.verify(sig, bindingMessage(ROLE_INITIATOR, transcript), cnfPk),
          catch: () => false,
        }),
        (fallback) => fallback,
      );
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
    void Either.try({
      try: () => {
        (this.hs.tx as Uint8Array | null)?.fill(0);
        (this.hs.rx as Uint8Array | null)?.fill(0);
      },
      catch: () => undefined,
    });
    this.sendCipher = null;
    this.recvCipher = null;
    this.handshakeHash?.fill(0);
    this.handshakeHash = null;
    this.cnfSignKey.fill(0);
  }
}
