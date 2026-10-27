import { Deferred, Effect, Ref } from "effect";
import { RoomState } from "../room/state.ts";
import type { RoomSnapshot, RoomSocket, VerifyGrant } from "../room/state.ts";
import { StorageUnavailable } from "../errors.ts";

const SNAP_KEY = "relay:room:v1";

export interface RoomStoreApi {
  readonly ensure_loaded: (
    socket_for: (conn_id: string) => RoomSocket | null,
  ) => Effect.Effect<RoomState | null, StorageUnavailable>;
  readonly get_room: () => Effect.Effect<RoomState | null>;
  readonly set_fresh_room: (room: RoomState) => Effect.Effect<void>;
  readonly flush: () => Effect.Effect<void, StorageUnavailable>;
}

interface StoreState {
  room: RoomState | null;
  loading: Deferred.Deferred<RoomState | null, StorageUnavailable> | null;
}

export function make_room_store(
  do_state: DurableObjectState,
  verify: VerifyGrant,
  now_ms: () => number,
): Effect.Effect<RoomStoreApi> {
  return Effect.gen(function* () {
    const ref = yield* Ref.make<StoreState>({ room: null, loading: null });
    const sem = yield* Effect.makeSemaphore(1);

    const do_load = (
      socket_for: (conn_id: string) => RoomSocket | null,
    ): Effect.Effect<RoomState | null, StorageUnavailable> =>
      Effect.gen(function* () {
        const snap = yield* Effect.tryPromise({
          try: () => do_state.storage.get<RoomSnapshot>(SNAP_KEY),
          catch: (cause) => new StorageUnavailable({ reason: "storage get failed", cause }),
        }).pipe(
          Effect.tapError(() => Effect.logError("storage get failed")),
        );
        if (!snap) return null;
        const room = new RoomState(snap.account, snap.machine, verify, now_ms);
        try {
          room.restore(snap, socket_for);
        } catch {
          yield* Effect.logError("snapshot restore failed: mismatch");
          return yield* Effect.fail(new StorageUnavailable({ reason: "snapshot mismatch" }));
        }
        yield* Ref.update(ref, (s) => ({ ...s, room }));
        return room;
      });

    const ensure_loaded: RoomStoreApi["ensure_loaded"] = (socket_for) =>
      Effect.uninterruptibleMask((restore) =>
        Effect.gen(function* () {
          const deferred: Deferred.Deferred<RoomState | null, StorageUnavailable> =
            yield* Deferred.make<RoomState | null, StorageUnavailable>();
          type Claim =
            | { readonly tag: "have-room"; readonly room: RoomState }
            | { readonly tag: "await"; readonly loading: Deferred.Deferred<RoomState | null, StorageUnavailable> }
            | { readonly tag: "claimed"; readonly deferred: Deferred.Deferred<RoomState | null, StorageUnavailable> };
          const action: Claim = yield* Ref.modify(ref, (s): readonly [Claim, StoreState] => {
            if (s.room) return [{ tag: "have-room", room: s.room } as const, s];
            if (s.loading) return [{ tag: "await", loading: s.loading } as const, s];
            return [{ tag: "claimed", deferred } as const, { ...s, loading: deferred }];
          });
          if (action.tag === "have-room") return action.room;
          if (action.tag === "await") return yield* restore(Deferred.await(action.loading));
          const result = yield* restore(Effect.exit(do_load(socket_for)));
          yield* Deferred.done(deferred, result);
          yield* Ref.update(ref, (s) => ({ ...s, loading: null }));
          return yield* result;
        })
      );

    const persist_once = (): Effect.Effect<void, StorageUnavailable> =>
      sem.withPermits(1)(
        Effect.gen(function* () {
          for (let i = 0; i < 4; i++) {
            const room = (yield* Ref.get(ref)).room;
            if (!room || !room.isDirty()) return;
            room.clearDirty();
            const snap = room.snapshot();
            const put_result = yield* Effect.exit(
              Effect.tryPromise({
                try: () => do_state.storage.put(SNAP_KEY, snap),
                catch: (cause) => new StorageUnavailable({ reason: "storage put failed", cause }),
              }),
            );
            if (put_result._tag === "Failure") {
              room.markDirty();
              yield* Effect.logError("storage put failed");
              return yield* put_result;
            }
          }
        }),
      );

    return {
      ensure_loaded,
      get_room: () => Effect.map(Ref.get(ref), (s) => s.room),
      set_fresh_room: (room: RoomState) => Ref.update(ref, (s) => ({ ...s, room })),
      flush: () => persist_once(),
    } satisfies RoomStoreApi;
  });
}
