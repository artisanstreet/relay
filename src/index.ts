import { Effect, Layer, ManagedRuntime } from "effect";
import { FetchHttpClient, HttpServerRequest, HttpServerResponse } from "@effect/platform";
import { parse_env, type Env } from "./config/relay.ts";
import { router } from "./router.ts";
import { handle_health } from "./handlers/health.ts";
import { handle_route_upgrade } from "./handlers/route.ts";
import { RelayEnv } from "./config/relay.ts";
import { GrantAuthority } from "./services/grants/verifier.ts";
import type { GrantAuthorityConfig } from "./services/grants/verifier.ts";
import { GrantVerifierLive } from "./services/grants/verifier.ts";
import { RevocationClientLive } from "./services/revocations.ts";
import { corsPreflight, corsResponseHeaders } from "./cors.ts";

export type { Env };
export { MachineRoom } from "./do/machine-room.ts";

const HttpLive = FetchHttpClient.layer;
const BaseServices = Layer.mergeAll(
  Layer.provide(GrantVerifierLive, HttpLive),
  Layer.provide(RevocationClientLive, HttpLive),
  HttpLive,
);

// Once per Worker isolate with proper ownership: the ManagedRuntime keeps
// its scope open for isolate lifetime (no closed-scope use). Shared JWKS
// sets keyed by URL + stateless HttpClient inside; no request data captured
// (RelayEnv stays per-request). jose cooldown + coalescing preserved.
const isolate_runtime = ManagedRuntime.make(BaseServices);

function with_cors(res: Response, req: Request, portal_origin: string | null): Response {
  const out = new Response(res.body, res);
  out.headers.set("Vary", "Origin");
  const h = corsResponseHeaders(req, portal_origin);
  if (h) {
    out.headers.set("Access-Control-Allow-Origin", h.get("Access-Control-Allow-Origin") as string);
  }
  return out;
}

function error_json(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export default {
  fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    const pipeline = Effect.gen(function* () {
      const cfg = yield* Effect.match(parse_env(env), {
        onFailure: () => null,
        onSuccess: (c) => c as RelayEnv["Type"] | null,
      });
      const portal_origin = cfg?.portal_origin ?? null;

      const preflight = corsPreflight(req, /^\/(v1\/presence\/[^/]+\/[^/]+|v1\/health)$/, portal_origin);
      if (preflight) return preflight;

      const route = path.match(/^\/v1\/route\/([^/]+)\/([^/]+)$/);
      if (route) {
        const [, account = "", machine = ""] = route;
        if (!cfg) return error_json({ error: "relay misconfigured" }, 500);
        return yield* handle_route_upgrade(req, account, machine).pipe(
          Effect.provideService(RelayEnv, cfg),
        );
      }

      if (!cfg) {
        if (req.method === "GET" && path === "/v1/health") {
          const healthy = yield* handle_health;
          return with_cors(HttpServerResponse.toWeb(healthy), req, portal_origin);
        }
        return error_json({ error: "relay misconfigured" }, 500);
      }

      const http_req = HttpServerRequest.fromWeb(req);
      const authority: GrantAuthorityConfig = {
        jwks_url: cfg.jwks_url,
        core_iss: cfg.core_iss,
        relay_aud: cfg.relay_aud,
        max_ttl_sec: cfg.max_ttl_sec,
      };
      const http_res: HttpServerResponse.HttpServerResponse = yield* Effect.provideService(
        router,
        HttpServerRequest.HttpServerRequest,
        http_req,
      ).pipe(
        Effect.provideService(GrantAuthority, authority),
        Effect.provideService(RelayEnv, cfg),
        Effect.catchTag("RouteNotFound", () =>
          Effect.succeed(HttpServerResponse.unsafeJson({ error: "not found" }, { status: 404 }))),
        Effect.catchAll(() =>
          Effect.as(
            Effect.logError("worker request failed"),
            HttpServerResponse.unsafeJson({ error: "internal error" }, { status: 500 }),
          )),
      );
      const res = HttpServerResponse.toWeb(http_res);
      if (
        (req.method === "GET" && path === "/v1/health") ||
        (req.method === "GET" && path.startsWith("/v1/presence/"))
      ) {
        return with_cors(res, req, portal_origin);
      }
      return res;
    });
    return isolate_runtime.runPromise(pipeline as Effect.Effect<Response, never, never>);
  },
} satisfies ExportedHandler<Env>;
