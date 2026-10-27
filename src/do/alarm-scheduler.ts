import { Effect } from "effect";
import type { RoomState } from "../room/state.ts";

export function next_wake_ms(
  room: RoomState | null,
  last_rev_fetch: number,
  poll_ms: number,
): number | null {
  const room_next = room?.next_deadline_ms() ?? null;
  let next = room_next;
  if (room && (room.presence().clients > 0 || room.presence().forge_online)) {
    const poll_at = last_rev_fetch + poll_ms;
    next = next === null ? poll_at : Math.min(next, poll_at);
  }
  return next;
}

export const schedule_alarm = (
  do_state: DurableObjectState,
  next: number | null,
): Effect.Effect<void> =>
  Effect.gen(function* () {
    const result = yield* Effect.exit(
      Effect.tryPromise({
        try: async () => {
          if (next === null) await do_state.storage.deleteAlarm();
          else await do_state.storage.setAlarm(next);
        },
        catch: () => undefined,
      }),
    );
    if (result._tag === "Failure") {
      yield* Effect.logError("alarm schedule failed");
    }
  });
