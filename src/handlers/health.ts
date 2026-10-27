import { Effect } from "effect";
import { HttpServerResponse } from "@effect/platform";

export function handle_health(): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  return Effect.succeed(
    HttpServerResponse.unsafeJson({ ok: true, service: "artisan-relay", v: 1 }),
  );
}
