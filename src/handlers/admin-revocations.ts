import { Effect } from "effect";
import { HttpServerResponse } from "@effect/platform";

const gone_body = { error: "gone: revocation is poll-based, see contracts/grant.md" };

export function handle_admin_gone(): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  return Effect.succeed(HttpServerResponse.unsafeJson(gone_body, { status: 410 }));
}
