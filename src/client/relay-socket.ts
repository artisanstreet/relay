import { Cause, Deferred, Effect, Exit, Option, Queue } from "effect";
import { readServerFrame } from "../schema.ts";
import type { ClientFrame } from "../schema.ts";
import { b64uDecode, b64uEncode } from "../b64u.ts";
import { popSign } from "../e2e.ts";

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

type SendFailure = SendClosedError | SendTimeoutError | SendQueueFullError;

/**
 * One in-flight send. Completion is an Effect Deferred (settled on ack,
 * channel loss, or close); the timeout is an Effect Clock deadline covering
 * queue wait + ack wait so the timeoutMs contract holds end to end.
 */
interface TrackedSend {
  /** Exact base64url body as transmitted. `bytes` is its length — the SAME
   *  basis the room accounts (frame.body.length), never decoded raw length.
   *  Encoded once at creation; reused for send. */
  b64: string;
  seq: number | null;
  bytes: number;
  done: Deferred.Deferred<void, SendFailure>;
}

function encodeBody(body: Uint8Array): { b64: string; bytes: number } {
  const b64 = b64uEncode(body);
  return { b64, bytes: b64.length };
}

interface ChannelSendState {
  unacked: TrackedSend[];
  unackedBytes: number;
  parked: Queue.Queue<TrackedSend>;
}

function send(ws: WebSocket, frame: ClientFrame): void {
  ws.send(JSON.stringify(frame));
}

/** Shared admission + framing. Subclass per role for clarity. */
export class RelaySocket {
  protected ws: WebSocket | null = null;
  private seqByChannel = new Map<string, number>();
  private sendState = new Map<string, ChannelSendState>();
  private stateSem = Effect.runSync(Effect.makeSemaphore(1));

  constructor(
    protected url: string,
    protected grant: GrantMaterial,
    protected events: ChannelEvents = {},
    protected wsImpl: typeof WebSocket = WebSocket,
  ) {}

  connect(): Promise<{ role: string; forgeOnline: boolean }> {
    const self = this;
    type Admission = { role: string; forgeOnline: boolean };
    const program = Effect.async<Admission, Error>((resume) => {
      const ws = new self.wsImpl(self.url);
      self.ws = ws;
      const fail = (e: Error) => resume(Effect.fail(e));
      const cleanup_admission = () => {
        ws.removeEventListener("message", on_first as EventListener);
        ws.removeEventListener("open", on_open as EventListener);
        ws.removeEventListener("error", on_error as EventListener);
        ws.removeEventListener("close", on_close as EventListener);
      };
      const settle_ok = (value: Admission) => {
        cleanup_admission();
        ws.addEventListener("message", on_steady as EventListener);
        ws.addEventListener("close", on_steady_close as EventListener);
        resume(Effect.succeed(value));
      };
      const settle_err = (e: Error) => {
        cleanup_admission();
        try {
          ws.close(4401, "gone");
        } catch { /* expected: socket gone, best effort */ }
        fail(e);
      };
      const on_steady = (e2: MessageEvent) => {
        void self.onMessage(String(e2.data)).catch(() => {});
      };
      const on_steady_close = (e: Event) => {
        const ce = e as unknown as { code?: number; reason?: string };
        self.events.onClose?.(ce.code ?? 1000, ce.reason ?? "");
        self.ws = null;
        self.failAll(new SendClosedError(`connection closed (${ce.code ?? 1000})`));
      };
      const on_error = (e: Event) => {
        const raw: unknown = (e as { message?: unknown }).message ?? e;
        settle_err(raw instanceof Error ? raw : new Error(typeof raw === "string" ? raw : String(raw)));
      };
      const on_close = (e: Event) => {
        const ce = e as unknown as { code?: number; reason?: string };
        self.events.onClose?.(ce.code ?? 1000, ce.reason ?? "");
        self.ws = null;
        self.failAll(new SendClosedError(`connection closed (${ce.code ?? 1000})`));
        settle_err(new SendClosedError(`connection closed (${ce.code ?? 1000})`));
      };
      const on_first = (ev: MessageEvent) => {
        void (async () => {
          try {
            const frame = readServerFrame(JSON.parse(String(ev.data)));
            if (frame.type === "challenge") {
              const nonce = b64uDecode(frame.nonce);
              const sig = popSign(self.grant.cnfSk, nonce, self.grant.jti);
              send(ws, { v: 1, type: "authenticate", jti: self.grant.jti, sig: b64uEncode(sig) });
              return;
            }
            if (frame.type === "ready") {
              settle_ok({ role: frame.role, forgeOnline: frame.forge_online });
              return;
            }
            if (frame.type === "error") {
              settle_err(new Error(`${frame.code}: ${frame.message}`));
              return;
            }
          } catch (e) {
            settle_err(e instanceof Error ? e : new Error(String(e)));
          }
        })();
      };
      const on_open = () => {
        send(ws, { v: 1, type: "hello", grant: self.grant.jwt });
      };
      ws.addEventListener("message", on_first as EventListener);
      ws.addEventListener("open", on_open as EventListener);
      ws.addEventListener("error", on_error as EventListener);
      ws.addEventListener("close", on_close as EventListener);
    });
    return Effect.runPromiseExit(program).then((exit) => {
      if (Exit.isSuccess(exit)) return exit.value;
      const failure = Cause.failureOption(exit.cause);
      if (Option.isSome(failure)) throw failure.value;
      throw Cause.squash(exit.cause);
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
        Effect.runSync(this.release_window_effect(frame.channel, frame.seq));
        return;
      case "channel-closed":
        this.events.onChannelClosed?.(frame.channel, frame.reason);
        Effect.runSync(this.fail_channel_effect(frame.channel, new SendClosedError(`channel closed: ${frame.reason}`)));
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
    const self = this;
    return Effect.runSync(
      self.stateSem.withPermits(1)(
        Effect.gen(function* () {
          const st = yield* self.send_state_for(channel);
          const { b64, bytes } = encodeBody(body);
          if (!self.window_has_space(st, bytes)) return "dropped-window-full" as SendStatus;
          // Fire-and-forget: still tracked so the window reflects reality; the
          // waiter is never observed (no completion contract on this path).
          // WARNING (ciphertext lifecycle): a "dropped-window-full" return means
          // the caller sealed bytes that will NEVER be delivered. The E2E session
          // is thereby unusable (fail-closed gap) — re-handshake on a fresh
          // channel, never retry the ciphertext. Prefer sendAcked()/sendApp().
          const done = yield* Deferred.make<void, SendFailure>();
          const entry: TrackedSend = { b64, seq: null, bytes, done };
          yield* self.emit_tracked(channel, st, entry);
          return "sent" as SendStatus;
        }),
      ),
    );
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
    const self = this;
    const program = self.stateSem.withPermits(1)(
      Effect.gen(function* () {
        if (!self.ws) {
          return yield* Effect.fail(new SendClosedError("not connected"));
        }
        const st = yield* self.send_state_for(channel);
        const { b64, bytes } = encodeBody(body);
        const done = yield* Deferred.make<void, SendFailure>();
        const entry: TrackedSend = { b64, seq: null, bytes, done };
        if (self.window_has_space(st, bytes)) {
          yield* self.emit_tracked(channel, st, entry);
        } else if (yield* Queue.isFull(st.parked)) {
          return yield* Effect.fail(new SendQueueFullError());
        } else {
          yield* Queue.offer(st.parked, entry);
        }
        return entry;
      }),
    ).pipe(
      Effect.flatMap((entry) => {
        if (!(timeoutMs > 0)) return Deferred.await(entry.done);
        const deadline = Effect.timeoutFail(Deferred.await(entry.done), {
          duration: timeoutMs,
          onTimeout: () => new SendTimeoutError(),
        });
        return Effect.tapError(deadline, (e) =>
          e instanceof SendTimeoutError
            ? self.fail_channel_effect(channel, e)
            : Effect.void);
      }),
    );
    // Thin Promise facade: unwrap the Exit cause so callers observe the raw
    // Send* error instances (instanceof preserved), never a FiberFailure.
    // Internal Effect E stays fully typed (no catchAll discarding E).
    return Effect.runPromiseExit(program).then((exit) => {
      if (Exit.isSuccess(exit)) return undefined;
      const failure = Cause.failureOption(exit.cause);
      if (Option.isSome(failure)) throw failure.value;
      throw Cause.squash(exit.cause);
    });
  }

  /** Unacked volume per channel (pacing observability). */
  pendingCount(channel: string): { frames: number; bytes: number; queued: number } {
    const st = this.sendState.get(channel);
    if (!st) return { frames: 0, bytes: 0, queued: 0 };
    const queued = Effect.runSync(Queue.size(st.parked));
    return { frames: st.unacked.length, bytes: st.unackedBytes, queued };
  }

  /**
   * Peek: would `encodedBytes` (base64url body length — see sealedFrameSize
   * in channel.ts for the exact pre-seal computation) fit the window now?
   * Pure predicate for throws-before-consume flows (sendApp).
   */
  willFit(channel: string, encodedBytes: number): boolean {
    const st = this.sendState.get(channel);
    if (!st) return encodedBytes <= SEND_WINDOW_BYTES;
    const self = this;
    return Effect.runSync(
      self.stateSem.withPermits(1)(Effect.sync(() => self.window_has_space(st, encodedBytes))),
    );
  }

  private send_state_for(channel: string): Effect.Effect<ChannelSendState> {
    const existing = this.sendState.get(channel);
    if (existing) return Effect.succeed(existing);
    const self = this;
    return Effect.map(Queue.bounded<TrackedSend>(SEND_QUEUE_MAX), (parked) => {
      const st: ChannelSendState = { unacked: [], unackedBytes: 0, parked };
      self.sendState.set(channel, st);
      return st;
    });
  }

  private window_has_space(st: ChannelSendState, bytes: number): boolean {
    return st.unacked.length < SEND_WINDOW_FRAMES && st.unackedBytes + bytes <= SEND_WINDOW_BYTES;
  }

  /**
   * Emit one tracked entry now: assign seq, send, register unacked.
   * Send transport errors settle the entry immediately (the frame never
   * left, so Relay holds nothing — credit is freed, unlike timeouts).
   */
  private emit_tracked(channel: string, st: ChannelSendState, entry: TrackedSend): Effect.Effect<void> {
    const ws = this.ws;
    if (!ws) {
      return this.drop_tracked(st, entry, new SendClosedError("not connected"));
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
      return this.drop_tracked(st, entry, e instanceof Error ? e : new Error(String(e)));
    }
    return Effect.void;
  }

  /** Remove one tracked send from wherever it sits and fail it. */
  private drop_tracked(st: ChannelSendState, entry: TrackedSend, e: Error): Effect.Effect<void> {
    const self = this;
    const as_failure = e instanceof SendClosedError || e instanceof SendTimeoutError || e instanceof SendQueueFullError
      ? e
      : new SendClosedError(e.message);
    const i = st.unacked.indexOf(entry);
    if (i !== -1) {
      st.unacked.splice(i, 1);
      st.unackedBytes = Math.max(0, st.unackedBytes - entry.bytes);
      return Deferred.fail(entry.done, as_failure);
    }
    return Effect.flatMap(Queue.takeAll(st.parked), (drained_chunk) => {
      const drained = [...drained_chunk];
      const kept = drained.filter((x) => x !== entry);
      const found = kept.length !== drained.length;
      return Effect.zipRight(
        Effect.forEach(kept, (x) => Queue.offer(st.parked, x), { discard: true }),
        found ? Deferred.fail(entry.done, as_failure) : Effect.void,
      );
    });
  }

  /** Slide the send window on a cumulative ack; resolve covered sends. */
  private release_window_effect(channel: string, ackSeq: number): Effect.Effect<void> {
    const self = this;
    return self.stateSem.withPermits(1)(
      Effect.gen(function* () {
        const st = self.sendState.get(channel);
        if (!st) return;
        let slid = false;
        while (st.unacked.length > 0 && (st.unacked[0]?.seq ?? Infinity) <= ackSeq) {
          const done = st.unacked.shift();
          if (!done) break;
          st.unackedBytes = Math.max(0, st.unackedBytes - done.bytes);
          yield* Deferred.succeed(done.done, undefined);
          slid = true;
        }
        if (slid) {
          self.events.onAck?.(channel, ackSeq);
          yield* self.drain_queue(channel, st);
        }
      }),
    );
  }

  /**
   * Send queued waiters while window space allows. FIFO order is preserved:
   * takeAll removes in order, the fitting prefix emits, the remainder
   * (starting at the first unfit head) goes back in order.
   */
  private drain_queue(channel: string, st: ChannelSendState): Effect.Effect<void> {
    const self = this;
    return Effect.gen(function* () {
      if (!self.ws) return;
      const drained = [...(yield* Queue.takeAll(st.parked))];
      const rest: TrackedSend[] = [];
      for (const next of drained) {
        if (rest.length === 0 && self.window_has_space(st, next.bytes)) {
          yield* self.emit_tracked(channel, st, next);
        } else {
          rest.push(next);
        }
      }
      yield* Effect.forEach(rest, (x) => Queue.offer(st.parked, x), { discard: true });
    });
  }

  /** Reject everything outstanding for a channel (close/loss). */
  private fail_channel_effect(channel: string, e: SendClosedError | SendTimeoutError): Effect.Effect<void> {
    const self = this;
    return self.stateSem.withPermits(1)(
      Effect.gen(function* () {
        const st = self.sendState.get(channel);
        if (!st) return;
        for (const u of st.unacked.splice(0, st.unacked.length)) {
          yield* Deferred.fail(u.done, e);
        }
        const queued = [...(yield* Queue.takeAll(st.parked))];
        for (const q of queued) {
          yield* Deferred.fail(q.done, e);
        }
        st.unackedBytes = 0;
      }),
    );
  }

  /** Reject everything outstanding on every channel (socket gone). */
  private failAll(e: Error): void {
    const self = this;
    const as_failure = e instanceof SendClosedError || e instanceof SendTimeoutError
      ? e
      : new SendClosedError(e.message);
    Effect.runSync(
      self.stateSem.withPermits(1)(
        Effect.gen(function* () {
          for (const channel of [...self.sendState.keys()]) {
            const st = self.sendState.get(channel);
            if (!st) continue;
            for (const u of st.unacked.splice(0, st.unacked.length)) {
              yield* Deferred.fail(u.done, as_failure);
            }
            const queued = [...(yield* Queue.takeAll(st.parked))];
            for (const q of queued) {
              yield* Deferred.fail(q.done, as_failure);
            }
            st.unackedBytes = 0;
          }
        }),
      ),
    );
  }

  private failChannel(channel: string, e: Error): void {
    Effect.runSync(
      this.fail_channel_effect(
        channel,
        e instanceof SendClosedError || e instanceof SendTimeoutError ? e : new SendClosedError(e.message),
      ),
    );
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
