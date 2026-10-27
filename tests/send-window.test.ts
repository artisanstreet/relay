// Client send-window: pacing, completion, and ciphertext lifecycle.
// RelaySocket drives a FakeLinkSocket (deterministic, no server) for
// timeout/queue unit paths, plus a real RoomState path for ack release.

import { describe, expect, it } from "vitest";
import { EditorLink, SEND_QUEUE_MAX, SEND_WINDOW_BYTES, SEND_WINDOW_FRAMES } from "../src/client.ts";
import { SendClosedError, SendQueueFullError, SendTimeoutError, SendWouldBlockError } from "../src/client.ts";
import type { GrantMaterial } from "../src/client.ts";
import { MAX_UNACKED_BYTES, MAX_UNACKED_FRAMES } from "../src/room.ts";
import { NoiseChannel, sealed_frame_size, static_keypair_from_secret } from "../src/channel.ts";
import { make_channel_jwt_verifier } from "../src/channel-verify.ts";
import { SecureChannel } from "../src/client.ts";
import { new_ed25519_keypair } from "../src/e2e.ts";
import { randomBytes as random_bytes } from "@noble/hashes/utils.js";
import { mint_grant, stub_fetch, test_core_key, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";

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
  server_send(obj: unknown): void {
    queueMicrotask(() => this.emit("message", { data: JSON.stringify(obj) }));
  }
  send(data: string): void {
    this.sent.push(data);
    const f = JSON.parse(data) as { type: string; channel?: string; seq?: number };
    if (f.type === "hello") {
      this.server_send({ v: 1, type: "ready", role: "client", account: "a", machine: "m", forge_online: true });
    }
  }
  close(): void {
    queueMicrotask(() => this.emit("close", { code: 1000, reason: "bye" }));
  }
}

async function connected_link(events = {}): Promise<EditorLink> {
  const grant: GrantMaterial = { jwt: "unused", jti: "unused", cnf_sk: new Uint8Array(32) };
  const link = new EditorLink("ws://x", grant, events, FakeLinkSocket as unknown as typeof WebSocket);
  await link.connect();
  return link;
}

describe("client send window", () => {
  it("send_opaque drops exactly at 64 unacked, resumes after acks", async () => {
    const link = await connected_link();
    const results: string[] = [];
    for (let i = 0; i < 64; i++) results.push(link.send_opaque("ch", new Uint8Array([1])));
    expect(new Set(results)).toEqual(new Set(["sent"]));
    expect(link.send_opaque("ch", new Uint8Array([1]))).toBe("dropped-window-full");
    expect(link.pending_count("ch")).toMatchObject({ frames: 64, queued: 0 });
    // Server acks everything (cumulative): window slides, sending resumes.
    const ws = (link as unknown as { ws: FakeLinkSocket }).ws;
    ws.server_send({ v: 1, type: "ack", channel: "ch", seq: 63 });
    await new Promise((r) => setTimeout(r, 10));
    expect(link.pending_count("ch").frames).toBe(0);
    expect(link.send_opaque("ch", new Uint8Array([1]))).toBe("sent");
  });

  it("send_acked resolves on ack and rejects on close", async () => {
    const link = await connected_link();
    const ws = (link as unknown as { ws: FakeLinkSocket }).ws;
    const p = link.send_acked("ch", new Uint8Array([9]));
    ws.server_send({ v: 1, type: "ack", channel: "ch", seq: 0 });
    await expect(p).resolves.toBeUndefined();
    const p2 = link.send_acked("ch", new Uint8Array([9]));
    link.close();
    await expect(p2).rejects.toBeInstanceOf(SendClosedError);
  });

  it("send_acked times out via fail-channel (no silent credit free)", async () => {
    const link = await connected_link();
    // Never acked (FakeLinkSocket drops data): 20ms timeout must reject.
    await expect(link.send_acked("ch", new Uint8Array([9]), { timeout_ms: 20 })).rejects.toBeInstanceOf(
      SendTimeoutError,
    );
    // Fail-closed: the whole channel's outstanding state was dropped.
    expect(link.pending_count("ch")).toMatchObject({ frames: 0, queued: 0 });
  });

  it("send queue is bounded", async () => {
    const link = await connected_link();
    // Fill window (64) then park SEND_QUEUE_MAX waiters; the next rejects.
    for (let i = 0; i < 64; i++) link.send_opaque("ch", new Uint8Array([1]));
    const parked: Promise<void>[] = [];
    for (let i = 0; i < SEND_QUEUE_MAX; i++) {
      parked.push(link.send_acked("ch", new Uint8Array([1]), { timeout_ms: 0 }));
    }
    await expect(link.send_acked("ch", new Uint8Array([1]), { timeout_ms: 0 })).rejects.toBeInstanceOf(
      SendQueueFullError,
    );
    expect(link.pending_count("ch").queued).toBe(SEND_QUEUE_MAX);
    link.close(); // settle everything
    await expect(Promise.allSettled(parked)).resolves.toBeDefined();
  });


/** Real-deadline wait for Noise confirm completion (async JWT verify). */
async function wait_open(ch: { get_phase(): string }, label: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const got = ch.get_phase();
    if (got === "open") return;
    if (got === "closed") throw new Error(`${label}: session closed while waiting for open`);
    if (Date.now() > deadline) throw new Error(`${label}: timed out waiting for open, stuck at ${got}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

  it("sealed_frame_size exactly predicts sealed bodies (will_fit is exact)", async () => {
    const core = test_core_key();
    const forge_cnf = new_ed25519_keypair();
    const editor_cnf = new_ed25519_keypair();
    const ctx = { account: "a", machine: "m", channel: "chan-9" };
    // Grant MUST bind the channel context (sub/mid), or the responder
    // rejects the confirm — the exact bug this line documents.
    const g = await mint_grant(core, { account: ctx.account, machine: ctx.machine, cnf_sk: editor_cnf.sk });
    const verify = make_channel_jwt_verifier(
      { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
      stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const init = new NoiseChannel({
      initiator: true,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: editor_cnf.sk,
      expected_responder_cnf: forge_cnf.pk,
      own_grant_jwt: g.jwt,
      ctx,
    });
    const resp = new NoiseChannel({
      initiator: false,
      static_keypair: static_keypair_from_secret(random_bytes(32)),
      cnf_sign_key: forge_cnf.sk,
      verify_channel_jwt: verify,
      ctx,
    });
    const m1 = init.next_handshake_message();
    resp.receive_handshake_message(m1);
    const m2 = resp.next_handshake_message();
    init.receive_handshake_message(m2);
    const m3 = init.next_handshake_message();
    resp.receive_handshake_message(m3);
    const [c_init] = init.take_outbound();
    resp.receive_transport(c_init as Uint8Array);
    await wait_open(resp, "responder confirm");
    const taken = resp.take_outbound();
    if (taken.length === 0) throw new Error("responder confirm: no outbound after open");
    init.receive_transport(taken[0] as Uint8Array);
    await wait_open(init, "initiator confirm");
    expect(init.get_phase()).toBe("open");

    for (const len of [0, 1, 100, 1000, 59999, 60000]) {
      const pt = new Uint8Array(len);
      const predicted = sealed_frame_size("chan-9", len);
      const { ct } = init.seal(pt);
      const actual = Buffer.from(ct).toString("base64url").length;
      expect(actual, `len ${len}`).toBe(predicted);
    }
  });

  it("send_app throws SendWouldBlockError before consuming a nonce", async () => {
    const link = await connected_link();
    // Build an open SecureChannel (loopback pair, same as above).
    const core = test_core_key();
    const forge_cnf = new_ed25519_keypair();
    const editor_cnf = new_ed25519_keypair();
    const verify = make_channel_jwt_verifier(
      { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
      stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    const ctx = { account: "a", machine: "m", channel: "wb" };
    const g = await mint_grant(core, { account: ctx.account, machine: ctx.machine, cnf_sk: editor_cnf.sk });
    const a = SecureChannel.initiate(static_keypair_from_secret(random_bytes(32)), {
      cnf_sign_key: editor_cnf.sk, expected_forge_cnf: forge_cnf.pk, own_grant_jwt: g.jwt, ctx,
    });
    const b = SecureChannel.accept(static_keypair_from_secret(random_bytes(32)), {
      cnf_sign_key: forge_cnf.sk, verify_channel_jwt: verify, ctx,
    });
    // Open via direct pump (no Relay involved).
    for (let i = 0; i < 200 && (!a.is_open() || !b.is_open()); i++) {
      for (const body of a.pump_outbound()) {
        const r = b.handle_incoming(body);
        void r;
      }
      for (const body of b.pump_outbound()) {
        const r = a.handle_incoming(body);
        void r;
      }
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(a.is_open()).toBe(true);
    // Fill the LINK window with raw frames (no Noise involved).
    for (let i = 0; i < 64; i++) expect(link.send_opaque("wb", new Uint8Array([i % 256]))).toBe("sent");
    const sent_before = a.noise.counters().sent;
    await expect(a.send_app(link, "wb", new Uint8Array([1, 2, 3]))).rejects.toBeInstanceOf(SendWouldBlockError);
    // Nothing consumed: Noise send counter unchanged, safe to retry later.
    expect(a.noise.counters().sent).toBe(sent_before);
  });
});
