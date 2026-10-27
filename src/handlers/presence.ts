import { Effect, Option } from "effect";
import { Headers, HttpServerRequest, HttpServerResponse } from "@effect/platform";
import { RelayEnv, room_id } from "../config/relay.ts";
import { StorageUnavailable } from "../errors.ts";
import { GrantVerifier, has_scope } from "../services/grants/verifier.ts";

const id_re = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;

function bearer_token(req: HttpServerRequest.HttpServerRequest): string | null {
  const found = Headers.get(req.headers, "authorization");
  if (Option.isNone(found)) return null;
  const m = found.value.match(/^Bearer (.+)$/);
  const token = m?.[1];
  return token ? token.trim() || null : null;
}

const error_json = (
  data: unknown,
  status: number,
): Effect.Effect<HttpServerResponse.HttpServerResponse> =>
  HttpServerResponse.unsafeJson(data, { status });

export const handle_presence = (account: string, machine: string) =>
  Effect.gen(function* () {
    if (!id_re.test(account) || !id_re.test(machine)) {
      return yield* error_json({ error: "bad room id" }, 400);
    }
    const req = yield* HttpServerRequest.HttpServerRequest;
    const token = bearer_token(req);
    if (!token) return yield* error_json({ error: "bearer grant required" }, 401);
    const verifier = yield* GrantVerifier;
    const grant = yield* Effect.option(verifier.verify_grant(token));
    if (Option.isNone(grant)) return yield* error_json({ error: "bad grant" }, 401);
    const g = grant.value;
    if (g.claims.sub !== account || g.claims.mid !== machine) {
      return yield* error_json({ error: "forbidden" }, 403);
    }
    if (!has_scope(g, "relay:connect")) return yield* error_json({ error: "forbidden" }, 403);
    const cfg = yield* RelayEnv;
    const stub = cfg.raw_env.MACHINE_ROOM.get(room_id(cfg.raw_env.MACHINE_ROOM, account, machine));
    const fetch_presence = Effect.gen(function* () {
      const res = yield* Effect.tryPromise({
        try: () => stub.fetch("https://relay/presence"),
        catch: (cause) => new StorageUnavailable({ reason: "presence upstream unreachable", cause }),
      });
      const body = (yield* Effect.tryPromise({
        try: () => res.json() as Promise<unknown>,
        catch: (cause) => new StorageUnavailable({ reason: "presence decode failed", cause }),
      })) as unknown;
      return { status: res.status, body };
    });
    return yield* Effect.matchEffect(fetch_presence, {
      onFailure: () => error_json({ error: "storage unavailable" }, 500),
      onSuccess: ({ status, body }) =>
        status < 200 || status >= 300
          ? error_json(body ?? { error: "storage unavailable" }, status)
          : error_json(body, 200),
    });
  });
