// Client helpers for Forge daemons, browser Editors, and native clients.
// Transport framing + admission live here; application payloads are produced
// and consumed as opaque E2E ciphertext via src/e2e.ts (or the Rust side).

import { readServerFrame } from "./schema.ts";
import type { ClientFrame } from "./schema.ts";
import { b64uDecode, b64uEncode } from "./b64u.ts";
import { encodeUtf8, popSign } from "./e2e.ts";
import { NoiseChannel } from "./channel.ts";
import type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt } from "./channel.ts";
import { sealedFrameSize } from "./channel.ts";
export { sealedFrameSize };

export interface GrantMaterial {
  jwt: string;
  jti: string;
  cnfSk: Uint8Array; // Ed25519 secret key proving possession of cnf
}

export interface ChannelEvents {
  onChannelOpened?(channel: string, peer: "forge" | "client"): void;
  onData?(channel: string, seq: number, body: Uint8Array): void;
  onChannelClosed?(channel: string, reason: string): void;
  onPresence?(forgeOnline: boolean, clients: number): void;
  onError?(code: string, message: string): void;
  onClose?(code: number, reason: string): void;
  /** Fired when a cumulative ack slides our send window (pacing signal). */
  onAck?(channel: string, seq: number): void;
}

/**
 * Client-side send window. Mirrors the Relay's ack windows so senders can
 * pace BEFORE the room drops frames. Values MUST equal room.ts
 * (pinned by test/window-parity.test.ts — duplication is deliberate: the
 * browser bundle must not import the server room module).
 */
export const SEND_WINDOW_FRAMES = 64;
export const SEND_WINDOW_BYTES = 1_048_576; // 1 MiB
/** Bounded park queue for sendAcked waiters per channel. */
export const SEND_QUEUE_MAX = 256;

export type SendStatus = "sent" | "dropped-window-full";

export class SendClosedError extends Error {
  constructor(reason: string) {
    super(`send failed: ${reason}`);
    this.name = "SendClosedError";
  }
}

export class SendTimeoutError extends Error {
  constructor() {
    super("send failed: ack timeout");
    this.name = "SendTimeoutError";
  }
}

export class SendQueueFullError extends Error {
  constructor() {
    super("send failed: send queue full");
    this.name = "SendQueueFullError";
  }
}

/** Window has no space: retry after acks, WITHOUT consuming anything. */
export class SendWouldBlockError extends Error {
  constructor() {
    super("send would block: window full, retry after acks (nothing consumed)");
    this.name = "SendWouldBlockError";
  }
}

/**
 * One in-flight send. `seq === null` while parked in the bounded queue;
 * set on emission. The single timer covers queue wait + ack wait so the
 * timeoutMs contract ("operation completes within T") holds end to end.
 */
interface TrackedSend {
  /** Exact base64url body as transmitted. `bytes` is its length — the SAME
   *  basis the room accounts (frame.body.length), never decoded raw length.
   *  Encoded once at creation; reused for send. */
  b64: string;
  seq: number | null;
  bytes: number;
  resolve: () => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout> | null;
}

function encodeBody(body: Uint8Array): { b64: string; bytes: number } {
  const b64 = b64uEncode(body);
  return { b64, bytes: b64.length };
}

interface ChannelSendState {
  unacked: TrackedSend[];
  unackedBytes: number;
  queued: TrackedSend[];
}

function send(ws: WebSocket, frame: ClientFrame): void {
  ws.send(JSON.stringify(frame));
}

/** Shared admission + framing. Subclass per role for clarity. */
export class RelaySocket {
  protected ws: WebSocket | null = null;
  private seqByChannel = new Map<string, number>();
  private sendState = new Map<string, ChannelSendState>();

  constructor(
    protected url: string,
    protected grant: GrantMaterial,
    protected events: ChannelEvents = {},
    protected wsImpl: typeof WebSocket = WebSocket,
  ) {}

  connect(): Promise<{ role: string; forgeOnline: boolean }> {
    return new Promise((resolve, reject) => {
      const ws = new this.wsImpl(this.url);
      this.ws = ws;
      const fail = (e: unknown) => reject(e instanceof Error ? e : new Error(String(e)));
      ws.addEventListener("error", (e) => fail((e as ErrorEvent).message ?? e));
      ws.addEventListener("close", (e) => {
        const ce = e as unknown as { code?: number; reason?: string };
        this.events.onClose?.(ce.code ?? 1000, ce.reason ?? "");
        this.ws = null;
        this.failAll(new SendClosedError(`connection closed (${ce.code ?? 1000})`));
      });
      const steady = (e2: MessageEvent) => {
        void this.onMessage(String(e2.data)).catch(fail);
      };
      const onFirst = (ev: MessageEvent) => {
        void (async () => {
          try {
            const frame = readServerFrame(JSON.parse(String(ev.data)));
            if (frame.type === "challenge") {
              const nonce = b64uDecode(frame.nonce);
              const sig = popSign(this.grant.cnfSk, nonce, this.grant.jti);
              send(ws, { v: 1, type: "authenticate", jti: this.grant.jti, sig: b64uEncode(sig) });
              return;
            }
            if (frame.type === "ready") {
              ws.removeEventListener("message", onFirst as EventListener);
              ws.addEventListener("message", steady as EventListener);
              resolve({ role: frame.role, forgeOnline: frame.forge_online });
              return;
            }
            if (frame.type === "error") {
              reject(new Error(`${frame.code}: ${frame.message}`));
              return;
            }
          } catch (e) {
            fail(e);
          }
        })();
      };
      ws.addEventListener("message", onFirst as EventListener);
      ws.addEventListener("open", () => {
        send(ws, { v: 1, type: "hello", grant: this.grant.jwt });
      });
    });
  }

  private async onMessage(raw: string): Promise<void> {
    const ws = this.ws;
    if (!ws) return;
    const frame = readServerFrame(JSON.parse(raw));
    switch (frame.type) {
      case "challenge": {
        const sig = popSign(this.grant.cnfSk, b64uDecode(frame.nonce), this.grant.jti);
        send(ws, { v: 1, type: "authenticate", jti: this.grant.jti, sig: b64uEncode(sig) });
        return;
      }
      case "channel-opened":
        this.events.onChannelOpened?.(frame.channel, frame.peer);
        return;
      case "data":
        this.events.onData?.(frame.channel, frame.seq, b64uDecode(frame.body));
        // Transport-level cumulative ack (flow control): the room releases
        // its per-channel window on this. App processing is separate.
        send(ws, { v: 1, type: "ack", channel: frame.channel, seq: frame.seq });
        return;
      case "ack":
        this.releaseWindow(frame.channel, frame.seq);
        return;
      case "channel-closed":
        this.events.onChannelClosed?.(frame.channel, frame.reason);
        this.failChannel(frame.channel, new SendClosedError(`channel closed: ${frame.reason}`));
        return;
      case "presence":
        this.events.onPresence?.(frame.forge_online, frame.clients);
        return;
      case "error":
        this.events.onError?.(frame.code, frame.message);
        return;
      case "ping":
        send(ws, { v: 1, type: "pong", t: frame.t });
        return;
      case "ready":
        return;
    }
  }

  open(channel: string): void {
    const ws = this.ws;
    if (!ws) throw new Error("not connected");
    send(ws, { v: 1, type: "open", channel });
  }

  /**
   * Send an opaque E2E body. Transport seq enforced by Relay per direction.
   * Fire-and-forget with window enforcement: returns "dropped-window-full"
   * instead of overflowing the Relay window (caller retries or re-opens).
   * Prefer sendAcked() when completion matters.
   */
  sendOpaque(channel: string, body: Uint8Array): SendStatus {
    if (!this.ws) throw new Error("not connected");
    const st = this.sendStateFor(channel);
    const { b64, bytes } = encodeBody(body);
    if (!this.windowHasSpace(st, bytes)) return "dropped-window-full";
    // Fire-and-forget: still tracked so the window reflects reality; the
    // no-op callbacks never settle anything the caller waits on.
    // WARNING (ciphertext lifecycle): a "dropped-window-full" return means
    // the caller sealed bytes that will NEVER be delivered. The E2E session
    // is thereby unusable (fail-closed gap) — re-handshake on a fresh
    // channel, never retry the ciphertext. Prefer sendAcked()/sendApp().
    const entry: TrackedSend = { b64, seq: null, bytes, resolve: () => {}, reject: () => {}, timer: null };
    this.emitTracked(channel, st, entry);
    return "sent";
  }

  /**
   * Send an opaque body, resolving when the recipient's cumulative ack
   * covers it. Waits for window space first (bounded queue); rejects on
   * timeout, close, or channel loss. This is the pacing primitive for
   * transfers larger than the window (e.g. multi-MiB uploads): await each
   * chunk (or a small pipeline) and the Relay window never overflows.
   */
  sendAcked(channel: string, body: Uint8Array, opts: { timeoutMs?: number } = {}): Promise<void> {
    const timeoutMs = opts.timeoutMs ?? 30_000;
    return new Promise<void>((resolve, reject) => {
      if (!this.ws) {
        reject(new SendClosedError("not connected"));
        return;
      }
      const st = this.sendStateFor(channel);
      const { b64, bytes } = encodeBody(body);
      const entry: TrackedSend = { b64, seq: null, bytes, resolve, reject, timer: null };
      if (timeoutMs > 0) {
        // Timeout does NOT free window credit (unlike a transport send
        // error): the frame may be sitting unacked at Relay, so our window
        // is desynchronized. Fail the whole channel closed (fail-closed);
        // the app must re-handshake. See contracts/wire.md.
        entry.timer = setTimeout(() => {
          this.failChannel(channel, new SendTimeoutError());
        }, timeoutMs);
      }
      // Fast path: window space available now.
      if (this.windowHasSpace(st, bytes)) {
        this.emitTracked(channel, st, entry);
        return;
      }
      // Park in the bounded queue; waiters drain in order as acks arrive.
      if (st.queued.length >= SEND_QUEUE_MAX) {
        if (entry.timer) clearTimeout(entry.timer);
        reject(new SendQueueFullError());
        return;
      }
      st.queued.push(entry);
    });
  }

  /** Unacked volume per channel (pacing observability). */
  pendingCount(channel: string): { frames: number; bytes: number; queued: number } {
    const st = this.sendState.get(channel);
    if (!st) return { frames: 0, bytes: 0, queued: 0 };
    return { frames: st.unacked.length, bytes: st.unackedBytes, queued: st.queued.length };
  }

  /**
   * Peek: would `encodedBytes` (base64url body length — see sealedFrameSize
   * in channel.ts for the exact pre-seal computation) fit the window now?
   * Pure predicate for throws-before-consume flows (sendApp).
   */
  willFit(channel: string, encodedBytes: number): boolean {
    return this.windowHasSpace(this.sendStateFor(channel), encodedBytes);
  }

  private sendStateFor(channel: string): ChannelSendState {
    let st = this.sendState.get(channel);
    if (!st) {
      st = { unacked: [], unackedBytes: 0, queued: [] };
      this.sendState.set(channel, st);
    }
    return st;
  }

  private windowHasSpace(st: ChannelSendState, bytes: number): boolean {
    return st.unacked.length < SEND_WINDOW_FRAMES && st.unackedBytes + bytes <= SEND_WINDOW_BYTES;
  }

  /**
   * Emit one tracked entry now: assign seq, send, register unacked.
   * The entry keeps its original timer (queue wait + ack wait share one
   * deadline). Send transport errors settle the entry immediately.
   */
  private emitTracked(channel: string, st: ChannelSendState, entry: TrackedSend): void {
    const ws = this.ws;
    if (!ws) {
      this.dropTracked(st, entry, new SendClosedError("not connected"));
      return;
    }
    const seq = (this.seqByChannel.get(channel) ?? -1) + 1;
    this.seqByChannel.set(channel, seq);
    entry.seq = seq;
    st.unacked.push(entry);
    st.unackedBytes += entry.bytes;
    try {
      // entry.b64 is the exact string accounted above; never re-encoded.
      send(ws, { v: 1, type: "data", channel, seq, body: entry.b64 });
    } catch (e) {
      // Transport-level send failure: the frame never left, so Relay holds
      // nothing — free the credit (unlike timeouts, see below).
      this.dropTracked(st, entry, e instanceof Error ? e : new Error(String(e)));
    }
  }

  /** Remove one tracked send from wherever it sits and reject it. */
  private dropTracked(st: ChannelSendState, entry: TrackedSend, e: Error): void {
    let i = st.unacked.indexOf(entry);
    if (i !== -1) {
      st.unacked.splice(i, 1);
      st.unackedBytes = Math.max(0, st.unackedBytes - entry.bytes);
    } else {
      i = st.queued.indexOf(entry);
      if (i === -1) return; // already acked: settled, nothing to do
      st.queued.splice(i, 1);
    }
    if (entry.timer) clearTimeout(entry.timer);
    entry.reject(e);
  }

  /** Slide the send window on a cumulative ack; resolve covered sends. */
  private releaseWindow(channel: string, ackSeq: number): void {
    const st = this.sendState.get(channel);
    if (!st) return;
    let slid = false;
    while (st.unacked.length > 0 && (st.unacked[0]?.seq ?? Infinity) <= ackSeq) {
      const done = st.unacked.shift();
      if (!done) break;
      st.unackedBytes = Math.max(0, st.unackedBytes - done.bytes);
      if (done.timer) clearTimeout(done.timer);
      done.resolve();
      slid = true;
    }
    if (slid) {
      this.events.onAck?.(channel, ackSeq);
      this.drainQueue(channel);
    }
  }

  /** Send queued waiters while window space allows (in order). */
  private drainQueue(channel: string): void {
    const st = this.sendState.get(channel);
    if (!st || !this.ws) return;
    while (st.queued.length > 0) {
      const next = st.queued[0];
      if (!next || !this.windowHasSpace(st, next.bytes)) break;
      st.queued.shift();
      this.emitTracked(channel, st, next);
    }
  }

  /** Reject everything outstanding for a channel (close/loss). */
  private failChannel(channel: string, e: Error): void {
    const st = this.sendState.get(channel);
    if (!st) return;
    for (const u of st.unacked.splice(0, st.unacked.length)) {
      if (u.timer) clearTimeout(u.timer);
      u.reject(e);
    }
    for (const q of st.queued.splice(0, st.queued.length)) {
      if (q.timer) clearTimeout(q.timer);
      q.reject(e);
    }
    st.unackedBytes = 0;
  }

  /** Reject everything outstanding on every channel (socket gone). */
  private failAll(e: Error): void {
    for (const channel of [...this.sendState.keys()]) this.failChannel(channel, e);
  }

  closeChannel(channel: string, reason?: string): void {
    const ws = this.ws;
    if (!ws) return;
    send(ws, { v: 1, type: "close", channel, ...(reason ? { reason } : {}) });
  }

  close(code = 1000, reason = "bye"): void {
    try {
      this.ws?.close(code, reason);
    } catch { /* ignore */ }
    this.ws = null;
    this.failAll(new SendClosedError("connection closed"));
  }
}

export class ForgeLink extends RelaySocket {}
export class EditorLink extends RelaySocket {}

// ---------------------------------------------------------------------------
// E2E session helpers (one per channel). Keys never leave this module's
// callers; Relay only ever sees sealSessionKey envelopes and data frames.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// E2E secure channels over Noise XX (src/channel.ts). Relay data bodies
// carry handshake bytes verbatim during the handshake phase, then raw Noise
// transport ciphertexts (sequential nonces). Relay cannot tell them apart
// and must not try; the session phase machine decides.
// ---------------------------------------------------------------------------

export type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt };
export { NoiseChannel };

/**
 * A Noise XX session bound to one Relay channel, with pump helpers that
 * move handshake/confirm/app bytes through a RelaySocket.
 *
 * Roles: the channel OPENER constructs with initiator=true. In the Relay
 * topology the opener is always the client (Editor); Forge accepts with
 * initiator=false. expectedPeerStatic is the Core-distributed fingerprint
 * of the counterparty's long-term X25519 static key (no TOFU); cnf keys
 * bind the Core JWT identity to the Noise session (contracts/e2e.md).
 */
export class SecureChannel {
  readonly noise: NoiseChannel;
  private appOut: Uint8Array[] = [];

  private constructor(noise: NoiseChannel) {
    this.noise = noise;
  }

  static initiate(
    staticKeypair: NoiseKeypairBytes,
    opts: { cnfSignKey: Uint8Array; expectedForgeCnf: Uint8Array; ownGrantJwt: string; ctx: ChannelCtx },
  ): SecureChannel {
    return new SecureChannel(
      new NoiseChannel({
        initiator: true,
        staticKeypair,
        cnfSignKey: opts.cnfSignKey,
        expectedResponderCnf: opts.expectedForgeCnf,
        ownGrantJwt: opts.ownGrantJwt,
        ctx: opts.ctx,
      }),
    );
  }

  static accept(
    staticKeypair: NoiseKeypairBytes,
    opts: { cnfSignKey: Uint8Array; verifyChannelJwt: VerifyChannelJwt; ctx: ChannelCtx },
  ): SecureChannel {
    return new SecureChannel(
      new NoiseChannel({
        initiator: false,
        staticKeypair,
        cnfSignKey: opts.cnfSignKey,
        verifyChannelJwt: opts.verifyChannelJwt,
        ctx: opts.ctx,
      }),
    );
  }

  isOpen(): boolean {
    return this.noise.getPhase() === "open";
  }

  /**
   * Produce outbound Relay bodies (handshake message, confirm frames, or
   * queued app data) in send order. Call after open(), after every
   * handleIncoming(), and after queueApp().
   */
  pumpOutbound(): Uint8Array[] {
    const out: Uint8Array[] = [];
    out.push(...this.noise.takeOutbound());
    out.push(...this.appOut.splice(0, this.appOut.length));
    if (this.noise.getPhase() === "handshake") {
      try {
        out.push(this.noise.nextHandshakeMessage());
      } catch {
        // Not our turn yet; the peer's message comes first.
      }
    }
    return out;
  }

  /**
   * Feed one inbound Relay data body. Returns app plaintext when a data
   * frame arrives, null for handshake/confirm traffic.
   */
  handleIncoming(body: Uint8Array): Uint8Array | null {
    const phase = this.noise.getPhase();
    if (phase === "handshake") {
      this.noise.receiveHandshakeMessage(body);
      return null;
    }
    if (phase !== "confirm" && phase !== "open") throw new Error("channel closed");
    return this.noise.receiveTransport(body);
  }

  /** Queue app plaintext for the next pumpOutbound(). */
  queueApp(plaintext: Uint8Array | string): void {
    const pt = typeof plaintext === "string" ? encodeUtf8(plaintext) : plaintext;
    const { ct } = this.noise.seal(pt);
    this.appOut.push(ct);
  }

  /**
   * Seal + send with throws-before-consume pacing (the correct upload
   * primitive; browsers use this, not raw sendOpaque):
   *  1. compute the EXACT encoded size pre-seal (sealedFrameSize);
   *  2. if the link window lacks space, throw SendWouldBlockError with
   *     NOTHING consumed (no Noise nonce spent — safe to retry after acks);
   *  3. otherwise seal and sendAcked (resolves on recipient ack).
   * Any later rejection (timeout/close/loss) invalidates the E2E session:
   * re-handshake on a fresh channel, never retry ciphertext.
   */
  async sendApp(
    link: RelaySocket,
    channel: string,
    plaintext: Uint8Array | string,
    opts: { timeoutMs?: number } = {},
  ): Promise<void> {
    const pt = typeof plaintext === "string" ? encodeUtf8(plaintext) : plaintext;
    if (channel !== this.noise.ctx.channel) throw new Error("wrong channel");
    if (!link.willFit(channel, sealedFrameSize(channel, pt.length))) {
      throw new SendWouldBlockError();
    }
    const { ct } = this.noise.seal(pt);
    await link.sendAcked(channel, ct, opts);
  }

  destroy(): void {
    this.noise.destroy();
    this.appOut = [];
  }
}
