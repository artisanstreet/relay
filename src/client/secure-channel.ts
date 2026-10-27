import { Either } from "effect";
import { b64u_decode, b64u_encode } from "../b64u.ts";
import { encode_utf8, pop_sign } from "../e2e.ts";
import { NoiseChannel } from "../channel/session.ts";
import { sealed_frame_size } from "../channel/framing.ts";
import type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt } from "../channel/context.ts";
import type { RelaySocket } from "./relay-socket.ts";
import { SendWouldBlockError } from "./relay-socket.ts";

export type { ChannelCtx, NoiseKeypairBytes, VerifyChannelJwt };
export { NoiseChannel, sealed_frame_size };

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
  private app_out: Uint8Array[] = [];

  private constructor(noise: NoiseChannel) {
    this.noise = noise;
  }

  static initiate(
    static_keypair: NoiseKeypairBytes,
    opts: { cnf_sign_key: Uint8Array; expected_forge_cnf: Uint8Array; own_grant_jwt: string; ctx: ChannelCtx },
  ): SecureChannel {
    return new SecureChannel(
      new NoiseChannel({
        initiator: true,
        static_keypair,
        cnf_sign_key: opts.cnf_sign_key,
        expected_responder_cnf: opts.expected_forge_cnf,
        own_grant_jwt: opts.own_grant_jwt,
        ctx: opts.ctx,
      }),
    );
  }

  static accept(
    static_keypair: NoiseKeypairBytes,
    opts: { cnf_sign_key: Uint8Array; verify_channel_jwt: VerifyChannelJwt; ctx: ChannelCtx },
  ): SecureChannel {
    return new SecureChannel(
      new NoiseChannel({
        initiator: false,
        static_keypair,
        cnf_sign_key: opts.cnf_sign_key,
        verify_channel_jwt: opts.verify_channel_jwt,
        ctx: opts.ctx,
      }),
    );
  }

  is_open(): boolean {
    return this.noise.get_phase() === "open";
  }

  /**
   * Produce outbound Relay bodies (handshake message, confirm frames, or
   * queued app data) in send order. Call after open(), after every
   * handle_incoming(), and after queue_app().
   */
  pump_outbound(): Uint8Array[] {
    const out: Uint8Array[] = [];
    out.push(...this.noise.take_outbound());
    out.push(...this.app_out.splice(0, this.app_out.length));
    if (this.noise.get_phase() === "handshake") {
      void Either.try({ try: () => out.push(this.noise.next_handshake_message()), catch: () => undefined });
    }
    return out;
  }

  /**
   * Feed one inbound Relay data body. Returns app plaintext when a data
   * frame arrives, null for handshake/confirm traffic.
   */
  handle_incoming(body: Uint8Array): Uint8Array | null {
    const phase = this.noise.get_phase();
    if (phase === "handshake") {
      this.noise.receive_handshake_message(body);
      return null;
    }
    if (phase !== "confirm" && phase !== "open") throw new Error("channel closed");
    return this.noise.receive_transport(body);
  }

  /** Queue app plaintext for the next pump_outbound(). */
  queue_app(plaintext: Uint8Array | string): void {
    const pt = typeof plaintext === "string" ? encode_utf8(plaintext) : plaintext;
    const { ct } = this.noise.seal(pt);
    this.app_out.push(ct);
  }

  /**
   * Seal + send with throws-before-consume pacing (the correct upload
   * primitive; browsers use this, not raw send_opaque):
   *  1. compute the EXACT encoded size pre-seal (sealed_frame_size);
   *  2. if the link window lacks space, throw SendWouldBlockError with
   *     NOTHING consumed (no Noise nonce spent — safe to retry after acks);
   *  3. otherwise seal and send_acked (resolves on recipient ack).
   * Any later rejection (timeout/close/loss) invalidates the E2E session:
   * re-handshake on a fresh channel, never retry ciphertext.
   */
  async send_app(
    link: RelaySocket,
    channel: string,
    plaintext: Uint8Array | string,
    opts: { timeout_ms?: number } = {},
  ): Promise<void> {
    const pt = typeof plaintext === "string" ? encode_utf8(plaintext) : plaintext;
    if (channel !== this.noise.ctx.channel) throw new Error("wrong channel");
    if (!link.will_fit(channel, sealed_frame_size(channel, pt.length))) {
      throw new SendWouldBlockError();
    }
    const { ct } = this.noise.seal(pt);
    await link.send_acked(channel, ct, opts);
  }

  destroy(): void {
    this.noise.destroy();
    this.app_out = [];
  }
}
