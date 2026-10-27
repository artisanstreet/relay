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
import { static_keypair_from_secret } from "../src/channel.ts";
import { make_channel_jwt_verifier } from "../src/channel-verify.ts";
import { new_ed25519_keypair } from "../src/e2e.ts";
import { randomBytes as random_bytes } from "@noble/hashes/utils.js";
import { mint_grant, stub_fetch, test_core_key, test_verifier, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";

class FakeWS {
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  private listeners = new Map<string, Set<(ev: unknown) => void>>();
  static rooms = new Map<string, RoomState>();
  private conn_id: string;
  closed = false;

  constructor(_url: string) {
    this.conn_id = `conn-${Math.random().toString(36).slice(2)}`;
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
    room.on_connect(this.conn_id, socket);
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
    void room.on_message(this.conn_id, data);
  }
  close(): void {
    const room = FakeWS.rooms.get("acct1/forge1");
    this.closed = true;
    if (room) room.on_close(this.conn_id);
    queueMicrotask(() => {
      this.emit("close", {});
      this.onclose?.();
    });
  }
}

async function wait_for(cond: () => boolean, label: string): Promise<void> {
  const deadline = Date.now() + 8000;
  for (;;) {
    if (cond()) return;
    if (Date.now() > deadline) throw new Error(`timeout: ${label}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("end-to-end through the room", () => {
  it("forge + editor connect, open a secure channel, and exchange secrets the room cannot read", async () => {
    const core = test_core_key();
    const room = new RoomState("acct1", "forge1", test_verifier(core), () => Date.now());
    FakeWS.rooms.set("acct1/forge1", room);
    try {
      const forge_cnf = new_ed25519_keypair(); // enrolled machine key (stable)
      const editor_cnf = new_ed25519_keypair(); // ephemeral per-grant key
      const forgeGrant = await mint_grant(core, {
        role: "forge", scope: ["relay:connect", "forge:execute", "machine:sync"], cnf_sk: forge_cnf.sk,
      });
      const editorGrant = await mint_grant(core, { role: "client", scope: ["relay:connect", "forge:execute"], cnf_sk: editor_cnf.sk });
      const forge_mat: GrantMaterial = { jwt: forgeGrant.jwt, jti: forgeGrant.jti, cnf_sk: forge_cnf.sk };
      const editor_mat: GrantMaterial = { jwt: editorGrant.jwt, jti: editorGrant.jti, cnf_sk: editor_cnf.sk };

      const forge_inbox: Uint8Array[] = [];
      const editor_inbox: Uint8Array[] = [];
      const forge_link = new ForgeLink(
        "ws://relay/v1/route/acct1/forge1", forge_mat,
        { on_data: (_ch, _seq, body) => forge_inbox.push(body) },
        FakeWS as unknown as typeof WebSocket,
      );
      const editor_link = new EditorLink(
        "ws://relay/v1/route/acct1/forge1", editor_mat,
        { on_data: (_ch, _seq, body) => editor_inbox.push(body) },
        FakeWS as unknown as typeof WebSocket,
      );
      expect((await forge_link.connect()).role).toBe("forge");
      expect((await editor_link.connect()).role).toBe("client");
      expect(room.presence()).toEqual({ forge_online: true, clients: 1 });

      const CTX = { account: "acct1", machine: "forge1", channel: "exec-1" };
      const verify_jwt = make_channel_jwt_verifier(
        { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec: 300 },
        stub_fetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
      );
      const editorCh = SecureChannel.initiate(static_keypair_from_secret(random_bytes(32)), {
        cnf_sign_key: editor_cnf.sk, expected_forge_cnf: forge_cnf.pk, own_grant_jwt: editorGrant.jwt, ctx: CTX,
      });
      const forgeCh = SecureChannel.accept(static_keypair_from_secret(random_bytes(32)), {
        cnf_sign_key: forge_cnf.sk, verify_channel_jwt: verify_jwt, ctx: CTX,
      });

      const routed_bodies: string[] = [];
      const send_all = async (
        link: ForgeLink | EditorLink, ch: SecureChannel, inbox: Uint8Array[],
      ): Promise<(Uint8Array | null)[]> => {
        for (const body of ch.pump_outbound()) {
          routed_bodies.push(Buffer.from(body).toString("base64url"));
          link.send_opaque("exec-1", body);
        }
        // Let FakeWS microtasks deliver through the room first.
        await new Promise((r) => setTimeout(r, 5));
        const results: (Uint8Array | null)[] = [];
        for (const b of inbox.splice(0, inbox.length)) results.push(ch.handle_incoming(b));
        return results;
      };

      editor_link.open("exec-1");
      for (let i = 0; i < 30 && (!editorCh.is_open() || !forgeCh.is_open()); i++) {
        await send_all(editor_link, editorCh, editor_inbox);
        await send_all(forge_link, forgeCh, forge_inbox);
      }
      expect(editorCh.is_open()).toBe(true);
      expect(forgeCh.is_open()).toBe(true);
      expect(editorCh.noise.handshake_hash_hex()).toBe(forgeCh.noise.handshake_hash_hex());

      const SECRET = "agent-transcript-bytes: run echo pwned";
      editorCh.queue_app(SECRET);
      await send_all(editor_link, editorCh, editor_inbox);
      const at_forge = (await send_all(forge_link, forgeCh, forge_inbox)).filter((r) => r !== null);
      expect(at_forge.length).toBe(1);
      expect(new TextDecoder().decode(at_forge[0] as Uint8Array)).toBe(SECRET);

      forgeCh.queue_app("result: exit 0");
      await send_all(forge_link, forgeCh, forge_inbox);
      const at_editor = (await send_all(editor_link, editorCh, editor_inbox)).filter((r) => r !== null);
      expect(at_editor.length).toBe(1);
      expect(new TextDecoder().decode(at_editor[0] as Uint8Array)).toBe("result: exit 0");

      const room_sees_plaintext = routed_bodies.some((b) => {
        const raw = Buffer.from(b, "base64url").toString("binary");
        return raw.includes(SECRET) || raw.includes("exit 0");
      });
      expect(room_sees_plaintext).toBe(false);

      // Revocation closes the live editor connection via the key list.
      expect(room.set_revocations([], [Buffer.from(editorGrant.cnf_pk).toString("base64url")])).toBe(true);
      expect(room.presence().clients).toBe(0);
    } finally {
      FakeWS.rooms.delete("acct1/forge1");
    }
  });
});
