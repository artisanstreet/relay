import { Effect, Ref } from "effect";
import type { RoomState } from "../room/state.ts";
import { RelayEnv } from "../config/relay.ts";
import { RevocationClient } from "../services/revocations.ts";

/**
 * Bounded revocation poll. Fail-OPEN on fetch failure (stale list):
 * grants still expire on their own TTL (fail-closed overall). Next alarm
 * retries. Do NOT tighten to fail-closed on poll.
 */
export function refresh_revocations(
  get_room: () => Effect.Effect<RoomState | null>,
  last_fetch_ref: Ref.Ref<number>,
  now_ms: () => number,
): Effect.Effect<void, never, RelayEnv | RevocationClient> {
  return Effect.gen(function* () {
    const cfg = yield* RelayEnv;
    const now = now_ms();
    const last = yield* Ref.get(last_fetch_ref);
    if (now - last < cfg.poll_ms) return;
    yield* Ref.set(last_fetch_ref, now);
    const client = yield* RevocationClient;
    const result = yield* Effect.exit(client.fetch_revocations());
    if (result._tag === "Failure") return;
    const room = yield* get_room();
    room?.setRevocations(result.value.machines, result.value.keys);
  });
}
