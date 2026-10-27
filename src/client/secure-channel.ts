import { b64uDecode, b64uEncode } from "../b64u.ts";
import { encodeUtf8, popSign } from "../e2e.ts";
import { NoiseChannel } from "../channel/session.ts";
import { sealedFrameSize } from "../channel/framing.ts";
import type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt } from "../channel/context.ts";
import type { RelaySocket } from "./relay-socket.ts";
import { SendWouldBlockError } from "./relay-socket.ts";

export type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt };
export { NoiseChannel, sealedFrameSize };

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
