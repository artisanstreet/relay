import { Cause, Effect, Exit, Layer, ManagedRuntime, Option } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse } from "@effect/platform";
import { GrantVerifierLive, has_scope } from "./services/grants/verifier.ts";
import type { VerifiedGrant } from "./services/grants/verifier.ts";
import { GrantVerifier } from "./services/grants/verifier.ts";
import { RelayEnv } from "./config/relay.ts";

export { b64uDecode, b64uEncode } from "./b64u.ts";
export type { VerifiedGrant };

export interface GrantVerifierOptions {
  jwksUrl: string;
  expectedIss: string;
  expectedAud: string;
  maxTtlSec: number;
}

export type VerifyGrant = (jwt: string, nowSec?: number) => Promise<VerifiedGrant>;

export function createGrantVerifier(
  opts: GrantVerifierOptions,
  fetchImpl?: (url: string, options: { headers: Headers; method: "GET"; redirect: "manual"; signal: AbortSignal }) => Promise<Response>,
): VerifyGrant {
  const cfg = {
    jwks_url: opts.jwksUrl,
    core_iss: opts.expectedIss,
    relay_aud: opts.expectedAud,
    max_ttl_sec: opts.maxTtlSec,
    revocations_url: `${opts.expectedIss.replace(/\/$/, "")}/v1/grants/revocations`,
    poll_ms: 60_000,
    portal_origin: null as string | null,
    raw_env: {} as never,
  };
  const http_layer = fetchImpl
    ? Layer.succeed(
        HttpClient.HttpClient,
        {
          execute: (req: HttpClientRequest.HttpClientRequest) =>
            Effect.flatMap(
              Effect.tryPromise({
                try: () =>
                  fetchImpl(req.url, {
                    headers: new Headers({ accept: "application/json" }),
                    method: "GET",
                    redirect: "manual",
                    signal: new AbortController().signal,
                  }),
                catch: (cause) => new Error(`jwks fetch failed: ${String(cause)}`),
              }),
              (web_res) =>
                web_res.ok
                  ? Effect.succeed(HttpClientResponse.fromWeb(req, web_res))
                  : Effect.fail(new Error(`jwks fetch failed: ${web_res.status}`)),
            ),
        } as unknown as HttpClient.HttpClient,
      )
    : FetchHttpClient.layer;
  const runtime = ManagedRuntime.make(
    Layer.mergeAll(
      Layer.provide(GrantVerifierLive, http_layer),
      Layer.succeed(RelayEnv, cfg),
    ),
  );
  // Thin Promise facade: unwrap the Exit cause so callers observe the raw
  // verification Error (message-matched by tests, e.g. /ttl/, as the
  // pre-Effect implementation threw), never a FiberFailure. The typed
  // failure is preserved as `cause`. Internal Effect E stays fully typed.
  return (jwt: string, nowSec?: number): Promise<VerifiedGrant> =>
    runtime.runPromiseExit(
      Effect.flatMap(GrantVerifier, (api) => api.verify_grant(jwt, nowSec)),
    ).then((exit) => {
      if (Exit.isSuccess(exit)) return exit.value;
      const failure = Cause.failureOption(exit.cause);
      if (Option.isSome(failure)) {
        const v = failure.value as unknown;
        const reason = (v as unknown as { reason?: unknown }).reason;
        if (v instanceof Error && typeof reason === "string") {
          throw new Error(reason, { cause: v });
        }
        throw v;
      }
      throw Cause.squash(exit.cause);
    });
}

export function hasScope(g: VerifiedGrant, scope: string): boolean {
  return has_scope(g, scope);
}
