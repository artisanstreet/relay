import { Cause, Effect, Exit, Layer, ManagedRuntime, Option } from "effect";
import { FetchHttpClient } from "@effect/platform";
import { GrantAuthority, GrantVerifier, GrantVerifierLive } from "./services/grants/verifier.ts";
export { has_scope } from "./services/grants/verifier.ts";
import type { VerifiedGrant } from "./services/grants/verifier.ts";

export { b64u_decode, b64u_encode } from "./b64u.ts";
export type { VerifiedGrant };

export interface GrantVerifierOptions {
  jwks_url: string;
  expected_iss: string;
  expected_aud: string;
  max_ttl_sec: number;
}

export type VerifyGrant = (jwt: string, now_sec?: number) => Promise<VerifiedGrant>;

export function create_grant_verifier(
  opts: GrantVerifierOptions,
  fetch_impl?: (url: string, options: { headers: Headers; method: "GET"; redirect: "manual"; signal: AbortSignal }) => Promise<Response>,
): VerifyGrant {
  const authority = {
    jwks_url: opts.jwks_url,
    core_iss: opts.expected_iss,
    relay_aud: opts.expected_aud,
    max_ttl_sec: opts.max_ttl_sec,
  };
  const fetch_layer = fetch_impl
    ? Layer.succeed(
        FetchHttpClient.Fetch,
        (async (url: string | URL | Request, init?: RequestInit): Promise<Response> =>
          fetch_impl(String(url), {
            headers: new Headers(init?.headers),
            method: "GET",
            redirect: "manual",
            signal: init?.signal as AbortSignal,
          })) as typeof fetch,
      )
    : Layer.empty;
  const runtime = ManagedRuntime.make(
    Layer.mergeAll(
      Layer.provide(GrantVerifierLive, Layer.provide(FetchHttpClient.layer, fetch_layer)),
      Layer.succeed(GrantAuthority, authority),
    ),
  );
  // Thin Promise facade: unwrap the Exit cause so callers observe the raw
  // verification Error (message-matched by tests, e.g. /ttl/, as the
  // pre-Effect implementation threw), never a FiberFailure. The typed
  // failure is preserved as `cause`. Internal Effect E stays fully typed.
  return (jwt: string, now_sec?: number): Promise<VerifiedGrant> =>
    runtime.runPromiseExit(
      Effect.flatMap(GrantVerifier, (api) => api.verify_grant(jwt, now_sec)),
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
