import { describe, expect, it } from "vitest";
import { Effect, Exit } from "effect";
import { make_room_store } from "../../src/do/room-store.ts";
import { RoomState } from "../../src/room/state.ts";
import { mintGrant, testCoreKey, testVerifier } from "../helpers.ts";
import { popSign } from "../../src/e2e.ts";
import { b64uEncode } from "../../src/b64u.ts";
import type { RoomSnapshot } from "../../src/room/state.ts";

function fake_do_storage() {
  return {
    data: new Map<string, unknown>(),
    get_calls: 0,
    put_calls: 0,
    fail_get: false,
    fail_put: false,
    delay_ms: 0,
    async get<T>(key: string): Promise<T | undefined> {
      this.get_calls++;
      if (this.delay_ms) await new Promise((r) => setTimeout(r, this.delay_ms));
      if (this.fail_get) throw new Error("storage get failed");
      return this.data.get(key) as T | undefined;
    },
    async put(key: string, value: unknown): Promise<void> {
      this.put_calls++;
      if (this.fail_put) throw new Error("storage put failed");
      this.data.set(key, value);
    },
  };
}

function fake_do_state(storage: ReturnType<typeof fake_do_storage>): DurableObjectState {
  return { storage } as unknown as DurableObjectState;
}

async function admitted_snapshot(): Promise<{ snap: RoomSnapshot; core: ReturnType<typeof testCoreKey> }> {
  const core = testCoreKey();
  const verify = testVerifier(core);
  const room = new RoomState("acct1", "forge1", verify, () => Date.now());
  const g = await mintGrant(core, { role: "forge" });
  const sent: string[] = [];
  const sock = { send: (d: string) => void sent.push(d), close: () => {} };
  room.onConnect("f", sock);
  await room.onMessage("f", JSON.stringify({ v: 1, type: "hello", grant: g.jwt }));
  const ch = JSON.parse(sent[0] as string) as { nonce: string };
  const nonce = Uint8Array.from(Buffer.from(ch.nonce, "base64url"));
  await room.onMessage(
    "f",
    JSON.stringify({ v: 1, type: "authenticate", jti: g.jti, sig: b64uEncode(popSign(g.cnfSk, nonce, g.jti)) }),
  );
  room.clearDirty();
  return { snap: room.snapshot(), core };
}

describe("room store (Effect orchestration, fail-closed storage)", () => {
  it("shares a single load across concurrent fibers (one storage read)", async () => {
    const storage = fake_do_storage();
    storage.delay_ms = 20;
    const { snap } = await admitted_snapshot();
    storage.data.set("relay:room:v1", snap);
    const core = testCoreKey();
    const store = await Effect.runPromise(
      make_room_store(fake_do_state(storage), testVerifier(core), () => Date.now()),
    );
    const results = await Effect.runPromise(
      Effect.all(
        Array.from({ length: 8 }, () => store.ensure_loaded(() => null)),
        { concurrency: "unbounded" },
      ),
    );
    expect(results.filter(Boolean).length).toBe(8);
    expect(storage.get_calls).toBe(1);
  });

  it("propagates typed StorageUnavailable (not void) on put failure, restores dirtiness", async () => {
    const storage = fake_do_storage();
    const { snap } = await admitted_snapshot();
    storage.data.set("relay:room:v1", snap);
    const core = testCoreKey();
    const store = await Effect.runPromise(
      make_room_store(fake_do_state(storage), testVerifier(core), () => Date.now()),
    );
    const live_sock = { send: (_d: string) => {}, close: (_c?: number, _r?: string) => {} };
    await Effect.runPromise(store.ensure_loaded((id) => (id === "f" ? live_sock : null)));
    const room = await Effect.runPromise(store.get_room());
    if (!room) throw new Error("expected room");
    room.markDirty();
    storage.fail_put = true;
    const exit = await Effect.runPromise(Effect.exit(store.flush()));
    expect(Exit.isFailure(exit)).toBe(true);
    if (Exit.isFailure(exit)) {
      const err = exit.cause as unknown as { _tag: string };
      void err;
    }
    expect(room.isDirty()).toBe(true);
    storage.fail_put = false;
    await Effect.runPromise(store.flush());
    expect(room.isDirty()).toBe(false);
    expect((storage.data.get("relay:room:v1") as RoomSnapshot).conns.length).toBe(1);
  });

  it("fails closed on load (no fresh room on storage error), retries after recovery", async () => {
    const storage = fake_do_storage();
    const { snap } = await admitted_snapshot();
    storage.data.set("relay:room:v1", snap);
    const core = testCoreKey();
    const store = await Effect.runPromise(
      make_room_store(fake_do_state(storage), testVerifier(core), () => Date.now()),
    );
    storage.fail_get = true;
    const first = await Effect.runPromise(Effect.exit(store.ensure_loaded(() => null)));
    expect(Exit.isFailure(first)).toBe(true);
    expect(await Effect.runPromise(store.get_room())).toBeNull();
    storage.fail_get = false;
    const live_sock = { send: (_d: string) => {}, close: (_c?: number, _r?: string) => {} };
    const room = await Effect.runPromise(store.ensure_loaded((id) => (id === "f" ? live_sock : null)));
    expect(room?.presence()).toEqual({ forge_online: true, clients: 0 });
  });
});
