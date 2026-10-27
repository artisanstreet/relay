// Client send-window: pacing, completion, and ciphertext lifecycle.
// RelaySocket drives a FakeLinkSocket (deterministic, no server) for
// timeout/queue unit paths, plus a real RoomState path for ack release.

import { describe, expect, it } from "vitest";
import { EditorLink, SEND_QUEUE_MAX, SEND_WINDOW_BYTES, SEND_WINDOW_FRAMES } from "../src/client.ts";
import { SendClosedError, SendQueueFullError, SendTimeoutError, SendWouldBlockError } from "../src/client.ts";
import type { GrantMaterial } from "../src/client.ts";
import { MAX_UNACKED_BYTES, MAX_UNACKED_FRAMES } from "../src/room.ts";
import { NoiseChannel, sealedFrameSize, staticKeypairFromSecret } from "../src/channel.ts";
import { makeChannelJwtVerifier } from "../src/channel-verify.ts";
import { SecureChannel } from "../src/client.ts";
import { newEd25519Keypair } from "../src/e2e.ts";
import { randomBytes } from "@noble/hashes/utils.js";
import { mintGrant, stubFetch, testCoreKey, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";

describe("window parity (client MUST equal room)", () => {
  it("constants match exactly", () => {
    expect(SEND_WINDOW_FRAMES).toBe(MAX_UNACKED_FRAMES);
    expect(SEND_WINDOW_BYTES).toBe(MAX_UNACKED_BYTES);
  });
});

// Deterministic link socket: answers hello with ready, drops data
// (never acks) unless told to ack. No server involved.
class FakeLinkSocket {
  url: string;
  sent: string[] = [];
  private listeners = new Map<string, Set<(ev: unknown) => void>>();
  onclose: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    queueMicrotask(() => this.emit("open", {}));
  }
  addEventListener(type: string, fn: (ev: unknown) => void): void {
    let set = this.listeners.get(type);
    if (!set) this.listeners.set(type, (set = new Set()));
    set.add(fn);
  }
  removeEventListener(type: string, fn: (ev: unknown) => void): void {
    this.listeners.get(type)?.delete(fn);
  }
  emit(type: string, ev: unknown): void {
    this.listeners.get(type)?.forEach((fn) => fn(ev));
  }
  serverSend(obj: unknown): void {
    queueMicrotask(() => this.emit("message", { data: JSON.stringify(obj) }));
  }
  send(data: string): void {
    this.sent.push(data);
    const f = JSON.parse(data) as { type: string; channel?: string; seq?: number };
    if (f.type === "hello") {
      this.serverSend({ v: 1, type: "ready", role: "client", account: "a", machine: "m", forge_online: true });
    }
  }
  close(): void {
    queueMicrotask(() => this.emit("close", { code: 1000, reason: "bye" }));
  }
}

async function connectedLink(events = {}): Promise<EditorLink> {
  const grant: GrantMaterial = { jwt: "unused", jti: "unused", cnfSk: new Uint8Array(32) };
  const link = new EditorLink("ws://x", grant, events, FakeLinkSocket as unknown as typeof WebSocket);
  await link.connect();
  return link;
}

describe("client send window", () => {
  it("sendOpaque drops exactly at 64 unacked, resumes after acks", async () => {
    const link = await connectedLink();
    const results: string[] = [];
    for (let i = 0; i < 64; i++) results.push(link.sendOpaque("ch", new Uint8Array([1])));
    expect(new Set(results)).toEqual(new Set(["sent"]));
    expect(link.sendOpaque("ch", new Uint8Array([1]))).toBe("dropped-window-full");
    expect(link.pendingCount("ch")).toMatchObject({ frames: 64, queued: 0 });
    // Server acks everything (cumulative): window slides, sending resumes.
    const ws = (link as unknown as { ws: FakeLinkSocket }).ws;
    ws.serverSend({ v: 1, type: "ack", channel: "ch", seq: 63 });
    await new Promise((r) => setTimeout(r, 10));
    expect(link.pendingCount("ch").frames).toBe(0);
    expect(link.sendOpaque("ch", new Uint8Array([1]))).toBe("sent");
  });

  it("sendAcked resolves on ack and rejects on close", async () => {
    const link = await connectedLink();
    const ws = (link as unknown as { ws: FakeLinkSocket }).ws;
    const p = link.sendAcked("ch", new Uint8Array([9]));
    ws.serverSend({ v: 1, type: "ack", channel: "ch", seq: 0 });
    await expect(p).resolves.toBeUndefined();
    const p2 = link.sendAcked("ch", new Uint8Array([9]));
    link.close();
    await expect(p2).rejects.toBeInstanceOf(SendClosedError);
  });

  it("sendAcked times out via fail-channel (no silent credit free)", async () => {
    const link = await connectedLink();
    // Never acked (FakeLinkSocket drops data): 20ms timeout must reject.
    await expect(link.sendAcked("ch", new Uint8Array([9]), { timeoutMs: 20 })).rejects.toBeInstanceOf(
      SendTimeoutError,
    );
    // Fail-closed: the whole channel's outstanding state was dropped.
    expect(link.pendingCount("ch")).toMatchObject({ frames: 0, queued: 0 });
  });

  it("send queue is bounded", async () => {
    const link = await connectedLink();
    // Fill window (64) then park SEND_QUEUE_MAX waiters; the next rejects.
    for (let i = 0; i < 64; i++) link.sendOpaque("ch", new Uint8Array([1]));
    const parked: Promise<void>[] = [];
    for (let i = 0; i < SEND_QUEUE_MAX; i++) {
      parked.push(link.sendAcked("ch", new Uint8Array([1]), { timeoutMs: 0 }));
    }
    await expect(link.sendAcked("ch", new Uint8Array([1]), { timeoutMs: 0 })).rejects.toBeInstanceOf(
      SendQueueFullError,
    );
    expect(link.pendingCount("ch").queued).toBe(SEND_QUEUE_MAX);
    link.close(); // settle everything
    await expect(Promise.allSettled(parked)).resolves.toBeDefined();
  });

  it("sealedFrameSize exactly predicts sealed bodies (willFit is exact)", async () => {
    const core = testCoreKey();
    const forgeCnf = newEd25519Keypair();
    const editorCnf = newEd25519Keypair();
    const ctx = { account: "a", machine: "m", channel: "chan-9" };
    // Grant MUST bind the channel context (sub/mid), or the responder
    // rejects the confirm — the exact bug this line documents.
    const g = await mintGrant(core, { account: ctx.account, machine: ctx.machine, cnfSk: editorCnf.sk });
    const verify = makeChannelJwtVerifier(
      { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
      stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const init = new NoiseChannel({
      initiator: true,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: editorCnf.sk,
      expectedResponderCnf: forgeCnf.pk,
      ownGrantJwt: g.jwt,
      ctx,
    });
    const resp = new NoiseChannel({
      initiator: false,
      staticKeypair: staticKeypairFromSecret(randomBytes(32)),
      cnfSignKey: forgeCnf.sk,
      verifyChannelJwt: verify,
      ctx,
    });
    const m1 = init.nextHandshakeMessage();
    resp.receiveHandshakeMessage(m1);
    const m2 = resp.nextHandshakeMessage();
    init.receiveHandshakeMessage(m2);
    const m3 = init.nextHandshakeMessage();
    resp.receiveHandshakeMessage(m3);
    const [cInit] = init.takeOutbound();
    resp.receiveTransport(cInit as Uint8Array);
    for (let i = 0; i < 50 && resp.getPhase() !== "open"; i++) await new Promise((r) => setImmediate(r));
    const [cResp] = resp.takeOutbound();
    init.receiveTransport(cResp as Uint8Array);
    for (let i = 0; i < 50 && init.getPhase() !== "open"; i++) await new Promise((r) => setImmediate(r));
    expect(init.getPhase()).toBe("open");

    for (const len of [0, 1, 100, 1000, 59999, 60000]) {
      const pt = new Uint8Array(len);
      const predicted = sealedFrameSize("chan-9", len);
      const { ct } = init.seal(pt);
      const actual = Buffer.from(ct).toString("base64url").length;
      expect(actual, `len ${len}`).toBe(predicted);
    }
  });

  it("sendApp throws SendWouldBlockError before consuming a nonce", async () => {
    const link = await connectedLink();
    // Build an open SecureChannel (loopback pair, same as above).
    const core = testCoreKey();
    const forgeCnf = newEd25519Keypair();
    const editorCnf = newEd25519Keypair();
    const verify = makeChannelJwtVerifier(
      { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
      stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const ctx = { account: "a", machine: "m", channel: "wb" };
    const g = await mintGrant(core, { account: ctx.account, machine: ctx.machine, cnfSk: editorCnf.sk });
    const a = SecureChannel.initiate(staticKeypairFromSecret(randomBytes(32)), {
      cnfSignKey: editorCnf.sk, expectedForgeCnf: forgeCnf.pk, ownGrantJwt: g.jwt, ctx,
    });
    const b = SecureChannel.accept(staticKeypairFromSecret(randomBytes(32)), {
      cnfSignKey: forgeCnf.sk, verifyChannelJwt: verify, ctx,
    });
    // Open via direct pump (no Relay involved).
    for (let i = 0; i < 200 && (!a.isOpen() || !b.isOpen()); i++) {
      for (const body of a.pumpOutbound()) {
        const r = b.handleIncoming(body);
        void r;
      }
      for (const body of b.pumpOutbound()) {
        const r = a.handleIncoming(body);
        void r;
      }
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(a.isOpen()).toBe(true);
    // Fill the LINK window with raw frames (no Noise involved).
    for (let i = 0; i < 64; i++) expect(link.sendOpaque("wb", new Uint8Array([i % 256]))).toBe("sent");
    const sentBefore = a.noise.counters().sent;
    await expect(a.sendApp(link, "wb", new Uint8Array([1, 2, 3]))).rejects.toBeInstanceOf(SendWouldBlockError);
    // Nothing consumed: Noise send counter unchanged, safe to retry later.
    expect(a.noise.counters().sent).toBe(sentBefore);
  });
});
