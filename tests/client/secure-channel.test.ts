import { describe, expect, it } from "vitest";
import { SecureChannel } from "../../src/client/secure-channel.ts";
import { RelaySocket } from "../../src/client/relay-socket.ts";
import { static_keypair_from_secret } from "../../src/channel/context.ts";
import { new_ed25519_keypair } from "../../src/e2e.ts";
import { SendWouldBlockError } from "../../src/client/relay-socket.ts";
import { sealed_frame_size } from "../../src/channel/framing.ts";

describe("secure channel pacing (no resend, no nonce advance on block)", () => {
  it("throws-before-consume leaves Noise counters untouched", async () => {
    const initiator_keys = new_ed25519_keypair();
    const responder_keys = new_ed25519_keypair();
    const initiator_static = static_keypair_from_secret(new Uint8Array(32).fill(7));
    const responder_static = static_keypair_from_secret(new Uint8Array(32).fill(9));
    const ctx = { account: "acct1", machine: "forge1", channel: "ch1" };
    const initiator = SecureChannel.initiate(initiator_static, {
      cnf_sign_key: initiator_keys.sk,
      expected_forge_cnf: responder_keys.pk,
      own_grant_jwt: "stub-jwt",
      ctx,
    });
    void responder_static;
    void responder_keys;
    const before = initiator.noise.counters();
    const big = new Uint8Array(60_000);
    const size = sealed_frame_size("ch1", big.length);
    const link = { will_fit: (_c: string, _n: number) => false } as unknown as RelaySocket;
    void size;
    await expect(initiator.send_app(link, "ch1", big)).rejects.toBeInstanceOf(SendWouldBlockError);
    expect(initiator.noise.counters()).toEqual(before);
    initiator.destroy();
  });


});
