import { Effect } from "effect";
import { HttpServerResponse } from "@effect/platform";

export const handle_health = Effect.succeed(
  HttpServerResponse.unsafeJson({ ok: true, service: "artisan-relay", v: 1 }),
);
