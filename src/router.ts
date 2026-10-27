import { Effect } from "effect";
import { HttpRouter, HttpServerResponse } from "@effect/platform";
import { handle_health } from "./handlers/health.ts";
import { handle_presence } from "./handlers/presence.ts";
import { handle_admin_gone } from "./handlers/admin-revocations.ts";

export const router = HttpRouter.empty.pipe(
  HttpRouter.get("/v1/health", handle_health),
  HttpRouter.get(
    "/v1/presence/:account/:machine",
    Effect.gen(function* () {
      const params = yield* HttpRouter.params;
      const account = params["account"] ?? "";
      const machine = params["machine"] ?? "";
      return yield* handle_presence(account, machine);
    }),
  ),
  HttpRouter.post("/v1/admin/revocations", handle_admin_gone),
  HttpRouter.post("/v1/admin/revocations/:account/:machine", handle_admin_gone),
  HttpRouter.all(
    "*",
    Effect.succeed(
      HttpServerResponse.unsafeJson({ error: "not found" }, { status: 404 }),
    ),
  ),
);
