// Client helpers for Forge daemons, browser Editors, and native clients.
// Transport framing + admission live here; application payloads are produced
// and consumed as opaque E2E ciphertext via src/e2e.ts (or the Rust side).

import { readServerFrame } from "./schema.ts";
import type { ClientFrame } from "./schema.ts";
import { b64uDecode, b64uEncode } from "./jwt.ts";
import { encodeUtf8, popSign } from "./e2e.ts";
import { NoiseChannel } from "./channel.ts";
import type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt } from "./channel.ts";

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
}

function send(ws: WebSocket, frame: ClientFrame): void {
  ws.send(JSON.stringify(frame));
}

/** Shared admission + framing. Subclass per role for clarity. */
export class RelaySocket {
  protected ws: WebSocket | null = null;
  private seqByChannel = new Map<string, number>();

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
      case "channel-closed":
        this.events.onChannelClosed?.(frame.channel, frame.reason);
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

  /** Send an opaque E2E body. Transport seq enforced by Relay per direction. */
  sendOpaque(channel: string, body: Uint8Array): void {
    const ws = this.ws;
    if (!ws) throw new Error("not connected");
    const seq = (this.seqByChannel.get(channel) ?? -1) + 1;
    this.seqByChannel.set(channel, seq);
    send(ws, { v: 1, type: "data", channel, seq, body: b64uEncode(body) });
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

  destroy(): void {
    this.noise.destroy();
    this.appOut = [];
  }
}
