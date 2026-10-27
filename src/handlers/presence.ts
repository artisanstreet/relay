import { Effect, Option } from "effect";
import { Headers, HttpServerRequest, HttpServerResponse } from "@effect/platform";
import { RelayEnv, room_id } from "../config/relay.ts";
import { GrantAuthority, GrantVerifier, has_scope } from "../services/grants/verifier.ts";

const id_re = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;

function bearer_token(req: HttpServerRequest.HttpServerRequest): string | null {
  const found = Headers.get(req.headers, "authorization");
  if (Option.isNone(found)) return null;
  const m = found.value.match(/^Bearer (.+)$/);
  const token = m?.[1];
  return token ? token.trim() || null : null;
}

function error_json(data: unknown, status: number): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  return HttpServerResponse.unsafeJson(data, { status });
}

export function handle_presence(
  account: string,
  machine: string,
): Effect.Effect<
  HttpServerResponse.HttpServerResponse,
  never,
  HttpServerRequest.HttpServerRequest | RelayEnv | GrantVerifier | GrantAuthority
> {
  return Effect.gen(function* () {
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
    const upstream = yield* Effect.match(
      Effect.tryPromise({
        try: () => stub.fetch("https://relay/presence"),
        catch: (cause) => String(cause),
      }),
      {
        onFailure: () => null as Response | null,
        onSuccess: (r: Response) => r as Response | null,
      },
    );
    if (upstream === null) return yield* error_json({ error: "storage unavailable" }, 500);
    const status = upstream.status;
    let body: unknown = null;
    try {
      body = (yield* Effect.promise(() => upstream.json() as Promise<unknown>)) as unknown;
    } catch {
      return yield* error_json({ error: "storage unavailable" }, 500);
    }
    if (status < 200 || status >= 300) {
      const payload = body ?? { error: "storage unavailable" };
      return yield* error_json(payload, status);
    }
    return yield* error_json(body, 200);
  });
}
