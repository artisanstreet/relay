import NoiseState from "noise-handshake";
import type { NoiseOpts } from "noise-handshake";
import CipherState from "noise-handshake/cipher";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex as bytes_to_hex } from "@noble/hashes/utils.js";
import { Either } from "effect";
import {
  BIND_DOMAIN,
  ROLE_INITIATOR,
  ROLE_RESPONDER,
  binding_message,
  equal_bytes,
  prologue_bytes,
} from "./context.ts";
import type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt } from "./context.ts";
import {
  APP_MAGIC,
  KIND_CONFIRM,
  KIND_DATA,
  MAX_APP_PLAINTEXT,
  MAX_GRANT_JWT,
  read_u16be,
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
  static_keypair: NoiseKeypairBytes;
  /** Own Ed25519 `cnf` secret (32B seed): signs the session binding. */
  cnf_sign_key: Uint8Array;
  ctx: ChannelCtx;
  now_ms?: () => number;
  /**
   * Initiator only: Forge's enrolled Ed25519 `cnf` public key, from the
   * authenticated Core machine record. Verifies the responder signature.
   */
  expected_responder_cnf?: Uint8Array;
  /**
   * Responder only: verifies the in-confirm grant JWT and returns its
   * `cnf` public key. Never accept Relay-forwarded keys here.
   */
  verify_channel_jwt?: VerifyChannelJwt;
  /**
   * Initiator only: own Core-signed grant JWT, sent inside the encrypted
   * confirm frame for the responder to verify.
   */
  own_grant_jwt?: string;
  /**
   * Fixture-generation hook only: overrides the Noise curve backend
   * (e.g. deterministic ephemerals for byte-frozen vectors). Production
   * MUST NOT pass this; live interop always uses the library default.
   */
  noise_opts?: NoiseOpts;
}

/**
 * One E2E channel. The channel opener MUST construct with initiator=true;
 * in the Relay topology the opener is always the client (Editor); Forge is
 * responder. (Forge-opened channels in future: opener still initiates.)
 */
export class NoiseChannel {
  private hs: NoiseState;
  private send_cipher: CipherState | null = null;
  private recv_cipher: CipherState | null = null;
  private handshake_hash: Uint8Array | null = null;
  private cnf_sign_key: Uint8Array;
  private expected_responder_cnf: Uint8Array | null;
  private verify_channel_jwt: VerifyChannelJwt | null;
  private own_grant_jwt: string | null;
  private phase: SessionPhase = "handshake";
  private sent_handshake = 0;
  private received_handshake = 0;
  private confirm_sent = false;
  private confirm_received = false;
  private sent_count = 0;
  private recv_count = 0;
  private pending_outbound: Uint8Array[] = [];
  private readonly born_at: number;
  private readonly now_ms: () => number;
  readonly ctx: ChannelCtx;
  readonly initiator: boolean;

  constructor(opts: NoiseChannelOpts) {
    if (opts.initiator && (!opts.expected_responder_cnf || !opts.own_grant_jwt)) {
      throw new Error("initiator needs expected_responder_cnf and own_grant_jwt");
    }
    if (!opts.initiator && !opts.verify_channel_jwt) {
      throw new Error("responder needs verify_channel_jwt");
    }
    this.initiator = opts.initiator;
    this.ctx = opts.ctx;
    this.now_ms = opts.now_ms ?? Date.now;
    this.born_at = this.now_ms();
    this.cnf_sign_key = opts.cnf_sign_key;
    this.expected_responder_cnf = opts.expected_responder_cnf ?? null;
    this.verify_channel_jwt = opts.verify_channel_jwt ?? null;
    this.own_grant_jwt = opts.own_grant_jwt ?? null;
    this.hs = new NoiseState(
      "XX",
      opts.initiator,
      // Copies: the library aliases key buffers internally; caller buffers
      // must never be mutated by the session.
      {
        publicKey: Uint8Array.from(opts.static_keypair.public_key),
        secretKey: Uint8Array.from(opts.static_keypair.secret_key),
      },
      opts.noise_opts,
    );
    this.hs.initialise(prologue_bytes(opts.ctx));
  }

  get_phase(): SessionPhase {
    return this.phase;
  }

  // -- handshake (payloads empty; identity binds in confirm frames) --------

  /** Produce the next handshake message (throws if not our turn). */
  next_handshake_message(): Uint8Array {
    if (this.phase !== "handshake") throw new Error("handshake already done");
    const expect_send =
      (this.initiator && this.sent_handshake === this.received_handshake) ||
      (!this.initiator && this.sent_handshake < this.received_handshake);
    if (!expect_send) throw new Error("not our handshake turn");
    const out = Uint8Array.from(this.hs.send(new Uint8Array(0)));
    this.sent_handshake++;
    if (this.hs.complete) this.on_handshake_complete();
    return out;
  }

  /** Consume a peer handshake message. */
  receive_handshake_message(msg: Uint8Array): void {
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
    this.received_handshake++;
    if (this.hs.complete) this.on_handshake_complete();
  }

  private on_handshake_complete(): void {
    const tx = this.hs.tx;
    const rx = this.hs.rx;
    const hash = this.hs.hash;
    if (!tx || !rx || !hash || hash.length !== 64) {
      this.destroy();
      throw new Error("missing transport keys");
    }
    this.send_cipher = new CipherState(Uint8Array.from(tx));
    this.recv_cipher = new CipherState(Uint8Array.from(rx));
    this.handshake_hash = Uint8Array.from(hash);
    this.phase = "confirm";
    // Initiator speaks first in confirmation.
    if (this.initiator) void this.emit_confirm();
  }

  private async emit_confirm(): Promise<void> {
    if (!this.send_cipher || !this.handshake_hash) throw new Error("no keys");
    let body: Uint8Array;
    if (this.initiator) {
      if (!this.own_grant_jwt) throw new Error("no grant JWT");
      const jwt_bytes = te.encode(this.own_grant_jwt);
      if (jwt_bytes.length === 0 || jwt_bytes.length > MAX_GRANT_JWT) {
        throw new Error("bad grant JWT length");
      }
      const sig = ed25519.sign(binding_message(ROLE_INITIATOR, this.handshake_hash), this.cnf_sign_key);
      body = new Uint8Array(64 + 2 + jwt_bytes.length + 64);
      body.set(this.handshake_hash, 0);
      body.set(u16be(jwt_bytes.length), 64);
      body.set(jwt_bytes, 66);
      body.set(sig, 66 + jwt_bytes.length);
    } else {
      const sig = ed25519.sign(binding_message(ROLE_RESPONDER, this.handshake_hash), this.cnf_sign_key);
      body = new Uint8Array(64 + 64);
      body.set(this.handshake_hash, 0);
      body.set(sig, 64);
    }
    const pt = this.frame(KIND_CONFIRM, this.ctx.channel, body);
    const ct = Uint8Array.from(this.send_cipher.encrypt(pt));
    this.sent_count++;
    this.pending_outbound.push(ct);
    this.confirm_sent = true;
  }

  /** Confirm-frame ciphertexts produced by the session (sequential nonces). */
  take_outbound(): Uint8Array[] {
    const out = this.pending_outbound;
    this.pending_outbound = [];
    return out;
  }

  /**
   * Decrypt one transport ciphertext (sequential Noise nonce).
   * Returns app data, or null for confirmation frames. Confirmation is
   * async (JWT verification); poll take_outbound()/get_phase() after.
   * ANY failure destroys the session (fail-closed).
   */
  receive_transport(ct: Uint8Array): Uint8Array | null {
    if (this.phase !== "confirm" && this.phase !== "open") {
      throw new Error("session not ready for transport");
    }
    if (!this.recv_cipher) throw new Error("no keys");
    const recv_cipher = this.recv_cipher;
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
    this.recv_count++;
    const { kind, body } = this.parse_frame(pt);
    if (kind === KIND_CONFIRM) {
      if (this.phase !== "confirm") {
        this.destroy();
        throw new Error("unexpected confirm, session destroyed");
      }
      // Async (JWT verification on the responder side). Failures destroy
      // the session before rejecting; the rejection itself is swallowed
      // here because callers observe phase/counters, not the promise.
      void this.on_confirm(body).catch(() => {});
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

  private async on_confirm(body: Uint8Array): Promise<void> {
    if (!this.handshake_hash) {
      this.destroy();
      throw new Error("malformed confirm");
    }
    const transcript = this.handshake_hash;
    if (this.initiator) {
      // Responder form: hash(64) || sig(64).
      if (body.length !== 128) {
        this.destroy();
        throw new Error("malformed responder confirm");
      }
      const hash = body.subarray(0, 64);
      const sig = body.subarray(64);
      if (!equal_bytes(hash, this.handshake_hash)) {
        this.destroy();
        throw new Error("key confirmation failed: transcript mismatch, session aborted");
      }
      if (!this.expected_responder_cnf) {
        this.destroy();
        throw new Error("no responder key");
      }
      const expected_cnf = this.expected_responder_cnf;
      const ok = Either.getOrElse(
        Either.try({
          try: () => ed25519.verify(sig, binding_message(ROLE_RESPONDER, transcript), expected_cnf),
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
      const jwt_len = read_u16be(body, 64);
      if (jwt_len === 0 || jwt_len > MAX_GRANT_JWT || 66 + jwt_len + 64 !== body.length) {
        this.destroy();
        throw new Error("malformed initiator confirm JWT framing");
      }
      const jwt = td.decode(body.subarray(66, 66 + jwt_len));
      const sig = body.subarray(66 + jwt_len);
      if (!equal_bytes(hash, this.handshake_hash)) {
        this.destroy();
        throw new Error("key confirmation failed: transcript mismatch, session aborted");
      }
      // Verify the grant independently (JWKS, sub/mid/scope/expiry) and
      // take ONLY the verified cnf key — never trust Relay-forwarded keys.
      // now_sec comes from the channel clock (real time in prod; fixture
      // time in deterministic vector generation).
      const cnf_pk: Uint8Array = await (this.verify_channel_jwt as VerifyChannelJwt)(
        jwt,
        this.ctx,
        Math.floor(this.now_ms() / 1000),
      ).then(
        (pk) => pk,
        (): never => {
          this.destroy();
          throw new Error("initiator grant JWT invalid, session aborted");
        },
      );
      const ok = Either.getOrElse(
        Either.try({
          try: () => ed25519.verify(sig, binding_message(ROLE_INITIATOR, transcript), cnf_pk),
          catch: () => false,
        }),
        (fallback) => fallback,
      );
      if (!ok) {
        this.destroy();
        throw new Error("initiator binding signature invalid: JWT identity does not cover this session");
      }
    }
    this.confirm_received = true;
    if (!this.initiator && !this.confirm_sent) await this.emit_confirm();
    if (this.confirm_sent && this.confirm_received) this.phase = "open";
  }

  /**
   * Seal app data. Rotation is ENFORCED: throws once due — the caller must
   * open a new channel and re-handshake (no post-compromise security is
   * claimed for continued use).
   */
  seal(plaintext: Uint8Array): { ct: Uint8Array } {
    if (this.phase !== "open") throw new Error("session not open");
    if (this.rotation_due()) throw new Error("rotation due: open a new channel");
    if (plaintext.length > MAX_APP_PLAINTEXT) throw new Error("message too large, chunk it");
    if (!this.send_cipher) throw new Error("no keys");
    const framed = this.frame(KIND_DATA, this.ctx.channel, plaintext);
    const ct = Uint8Array.from(this.send_cipher.encrypt(framed));
    this.sent_count++;
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

  private parse_frame(pt: Uint8Array): { kind: number; body: Uint8Array } {
    if (pt.length < 3 + 1 + 1 + 1) throw new Error("frame too short");
    if (td.decode(pt.subarray(0, 3)) !== APP_MAGIC) throw new Error("bad magic");
    if (pt[3] !== 0x01) throw new Error("unsupported frame version");
    const ch_len = pt[4] ?? 0;
    if (5 + ch_len + 1 > pt.length) throw new Error("frame too short");
    const ch = td.decode(pt.subarray(5, 5 + ch_len));
    if (ch !== this.ctx.channel) {
      this.destroy();
      throw new Error("channel mismatch, session destroyed");
    }
    const kind = pt[5 + ch_len] ?? 0xff;
    if (kind !== KIND_CONFIRM && kind !== KIND_DATA) throw new Error("unknown kind");
    return { kind, body: Uint8Array.from(pt.subarray(5 + ch_len + 1)) };
  }

  private rotation_due(): boolean {
    return this.sent_count + this.recv_count >= ROTATE_AFTER_MESSAGES || this.now_ms() - this.born_at >= MAX_SESSION_AGE_MS;
  }

  needs_rotation(): boolean {
    return this.rotation_due();
  }

  counters(): { sent: number; received: number; phase: SessionPhase } {
    return { sent: this.sent_count, received: this.recv_count, phase: this.phase };
  }

  handshake_hash_hex(): string | null {
    if (!this.handshake_hash) return null;
    return bytes_to_hex(this.handshake_hash);
  }

  /** Best-effort key erasure (JS engine copies may linger; documented limit). */
  destroy(): void {
    this.phase = "closed";
    this.pending_outbound = [];
    void Either.try({
      try: () => {
        (this.hs.tx as Uint8Array | null)?.fill(0);
        (this.hs.rx as Uint8Array | null)?.fill(0);
      },
      catch: () => undefined,
    });
    this.send_cipher = null;
    this.recv_cipher = null;
    this.handshake_hash?.fill(0);
    this.handshake_hash = null;
    this.cnf_sign_key.fill(0);
  }
}
