// Full-stack integration through a REAL RoomState with REAL grants,
// REAL proof-of-possession, and REAL Noise E2E sessions on both ends.
// FakeWS wires RelaySocket (client.ts) to the room; SecureChannel pumps
// handshake/confirm/app bytes as data frames with room-enforced seq.
// The room sees only opaque bodies: asserted byte-exact below.

import { describe, expect, it } from "vitest";
import { RoomState } from "../src/room.ts";
import type { RoomSocket } from "../src/room.ts";
import { EditorLink, ForgeLink, SecureChannel } from "../src/client.ts";
import type { GrantMaterial } from "../src/client.ts";
import { staticKeypairFromSecret } from "../src/channel.ts";
import { makeChannelJwtVerifier } from "../src/channel-verify.ts";
import { newEd25519Keypair } from "../src/e2e.ts";
import { randomBytes } from "@noble/hashes/utils.js";
import { mintGrant, stubFetch, testCoreKey, testVerifier, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";

class FakeWS {
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  private listeners = new Map<string, Set<(ev: unknown) => void>>();
  static rooms = new Map<string, RoomState>();
  private connId: string;
  closed = false;

  constructor(_url: string) {
    this.connId = `conn-${Math.random().toString(36).slice(2)}`;
    const room = FakeWS.rooms.get("acct1/forge1");
    if (!room) throw new Error("no room registered");
    const socket: RoomSocket = {
      send: (data: string) => {
        queueMicrotask(() => {
          this.emit("message", { data });
          this.onmessage?.({ data });
        });
      },
      close: () => {
        this.closed = true;
        queueMicrotask(() => {
          this.emit("close", {});
          this.onclose?.();
        });
      },
    };
    room.onConnect(this.connId, socket);
    queueMicrotask(() => {
      this.readyState = 1;
      this.emit("open", {});
      this.onopen?.();
    });
  }
  addEventListener(type: string, fn: (ev: unknown) => void): void {
    let set = this.listeners.get(type);
    if (!set) this.listeners.set(type, (set = new Set()));
    set.add(fn);
  }
  removeEventListener(type: string, fn: (ev: unknown) => void): void {
    this.listeners.get(type)?.delete(fn);
  }
  private emit(type: string, ev: unknown): void {
    this.listeners.get(type)?.forEach((fn) => fn(ev));
  }
  send(data: string): void {
    const room = FakeWS.rooms.get("acct1/forge1");
    if (!room || this.closed) return;
    void room.onMessage(this.connId, data);
  }
  close(): void {
    const room = FakeWS.rooms.get("acct1/forge1");
    this.closed = true;
    if (room) room.onClose(this.connId);
    queueMicrotask(() => {
      this.emit("close", {});
      this.onclose?.();
    });
  }
}

async function waitFor(cond: () => boolean, label: string): Promise<void> {
  const deadline = Date.now() + 8000;
  for (;;) {
    if (cond()) return;
    if (Date.now() > deadline) throw new Error(`timeout: ${label}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("end-to-end through the room", () => {
  it("forge + editor connect, open a secure channel, and exchange secrets the room cannot read", async () => {
    const core = testCoreKey();
    const room = new RoomState("acct1", "forge1", testVerifier(core), () => Date.now());
    FakeWS.rooms.set("acct1/forge1", room);
    try {
      const forgeCnf = newEd25519Keypair(); // enrolled machine key (stable)
      const editorCnf = newEd25519Keypair(); // ephemeral per-grant key
      const forgeGrant = await mintGrant(core, {
        role: "forge", scope: ["relay:connect", "forge:execute", "machine:sync"], cnfSk: forgeCnf.sk,
      });
      const editorGrant = await mintGrant(core, { role: "client", scope: ["relay:connect"], cnfSk: editorCnf.sk });
      const forgeMat: GrantMaterial = { jwt: forgeGrant.jwt, jti: forgeGrant.jti, cnfSk: forgeCnf.sk };
      const editorMat: GrantMaterial = { jwt: editorGrant.jwt, jti: editorGrant.jti, cnfSk: editorCnf.sk };

      const forgeInbox: Uint8Array[] = [];
      const editorInbox: Uint8Array[] = [];
      const forgeLink = new ForgeLink(
        "ws://relay/v1/route/acct1/forge1", forgeMat,
        { onData: (_ch, _seq, body) => forgeInbox.push(body) },
        FakeWS as unknown as typeof WebSocket,
      );
      const editorLink = new EditorLink(
        "ws://relay/v1/route/acct1/forge1", editorMat,
        { onData: (_ch, _seq, body) => editorInbox.push(body) },
        FakeWS as unknown as typeof WebSocket,
      );
      expect((await forgeLink.connect()).role).toBe("forge");
      expect((await editorLink.connect()).role).toBe("client");
      expect(room.presence()).toEqual({ forge_online: true, clients: 1 });

      const CTX = { account: "acct1", machine: "forge1", channel: "exec-1" };
      const verifyJwt = makeChannelJwtVerifier(
        { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec: 300 },
        stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
      );
      const editorCh = SecureChannel.initiate(staticKeypairFromSecret(randomBytes(32)), {
        cnfSignKey: editorCnf.sk, expectedForgeCnf: forgeCnf.pk, ownGrantJwt: editorGrant.jwt, ctx: CTX,
      });
      const forgeCh = SecureChannel.accept(staticKeypairFromSecret(randomBytes(32)), {
        cnfSignKey: forgeCnf.sk, verifyChannelJwt: verifyJwt, ctx: CTX,
      });

      const routedBodies: string[] = [];
      const sendAll = async (
        link: ForgeLink | EditorLink, ch: SecureChannel, inbox: Uint8Array[],
      ): Promise<(Uint8Array | null)[]> => {
        for (const body of ch.pumpOutbound()) {
          routedBodies.push(Buffer.from(body).toString("base64url"));
          link.sendOpaque("exec-1", body);
        }
        // Let FakeWS microtasks deliver through the room first.
        await new Promise((r) => setTimeout(r, 5));
        const results: (Uint8Array | null)[] = [];
        for (const b of inbox.splice(0, inbox.length)) results.push(ch.handleIncoming(b));
        return results;
      };

      editorLink.open("exec-1");
      for (let i = 0; i < 30 && (!editorCh.isOpen() || !forgeCh.isOpen()); i++) {
        await sendAll(editorLink, editorCh, editorInbox);
        await sendAll(forgeLink, forgeCh, forgeInbox);
      }
      expect(editorCh.isOpen()).toBe(true);
      expect(forgeCh.isOpen()).toBe(true);
      expect(editorCh.noise.handshakeHashHex()).toBe(forgeCh.noise.handshakeHashHex());

      const SECRET = "agent-transcript-bytes: run echo pwned";
      editorCh.queueApp(SECRET);
      await sendAll(editorLink, editorCh, editorInbox);
      const atForge = (await sendAll(forgeLink, forgeCh, forgeInbox)).filter((r) => r !== null);
      expect(atForge.length).toBe(1);
      expect(new TextDecoder().decode(atForge[0] as Uint8Array)).toBe(SECRET);

      forgeCh.queueApp("result: exit 0");
      await sendAll(forgeLink, forgeCh, forgeInbox);
      const atEditor = (await sendAll(editorLink, editorCh, editorInbox)).filter((r) => r !== null);
      expect(atEditor.length).toBe(1);
      expect(new TextDecoder().decode(atEditor[0] as Uint8Array)).toBe("result: exit 0");

      const roomSeesPlaintext = routedBodies.some((b) => {
        const raw = Buffer.from(b, "base64url").toString("binary");
        return raw.includes(SECRET) || raw.includes("exit 0");
      });
      expect(roomSeesPlaintext).toBe(false);

      // Revocation closes the live editor connection via the key list.
      expect(room.setRevocations([], [Buffer.from(editorGrant.cnfPk).toString("base64url")])).toBe(true);
      expect(room.presence().clients).toBe(0);
    } finally {
      FakeWS.rooms.delete("acct1/forge1");
    }
  });
});
