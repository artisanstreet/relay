import { describe, expect, it } from "vitest";
import { SecureChannel } from "../../src/client/secure-channel.ts";
import { EditorLink } from "../../src/client/relay-socket.ts";
import { RelaySocket } from "../../src/client/relay-socket.ts";
import { staticKeypairFromSecret } from "../../src/channel/context.ts";
import { newEd25519Keypair } from "../../src/e2e.ts";
import { SendWouldBlockError } from "../../src/client/relay-socket.ts";
import { sealedFrameSize } from "../../src/channel/framing.ts";

describe("secure channel pacing (no resend, no nonce advance on block)", () => {
  it("throws-before-consume leaves Noise counters untouched", async () => {
    const initiator_keys = newEd25519Keypair();
    const responder_keys = newEd25519Keypair();
    const initiator_static = staticKeypairFromSecret(new Uint8Array(32).fill(7));
    const responder_static = staticKeypairFromSecret(new Uint8Array(32).fill(9));
    const ctx = { account: "acct1", machine: "forge1", channel: "ch1" };
    const initiator = SecureChannel.initiate(initiator_static, {
      cnfSignKey: initiator_keys.sk,
      expectedForgeCnf: responder_keys.pk,
      ownGrantJwt: "stub-jwt",
      ctx,
    });
    void responder_static;
    void responder_keys;
    const before = initiator.noise.counters();
    const big = new Uint8Array(60_000);
    const size = sealedFrameSize("ch1", big.length);
    const link = { willFit: (_c: string, _n: number) => false } as unknown as RelaySocket;
    void size;
    await expect(initiator.sendApp(link, "ch1", big)).rejects.toBeInstanceOf(SendWouldBlockError);
    expect(initiator.noise.counters()).toEqual(before);
    initiator.destroy();
  });

  it("EditorLink stays constructible via compat facade", () => {
    expect(typeof EditorLink).toBe("function");
  });
});
