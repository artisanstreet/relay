import { Clock, Context, Effect, Layer } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "@effect/platform";
import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { check_grant_claims } from "./checks.ts";
import type { GrantClaims } from "../../schema.ts";
import { GrantVerificationFailed } from "../../errors.ts";

export interface VerifiedGrant {
  claims: GrantClaims;
  kid: string;
  cnfPk: Uint8Array;
  scopes: Set<string>;
}

export function has_scope(g: VerifiedGrant, scope: string): boolean {
  return g.scopes.has(scope);
}

export type VerifyGrant = (jwt: string, now_sec?: number) => Promise<VerifiedGrant>;

export interface GrantAuthorityConfig {
  readonly jwks_url: string;
  readonly core_iss: string;
  readonly relay_aud: string;
  readonly max_ttl_sec: number;
}

export class GrantAuthority extends Context.Tag("GrantAuthority")<GrantAuthority, GrantAuthorityConfig>() {}

export interface GrantVerifierApi {
  readonly verify_grant: (
    jwt: string,
    now_sec?: number,
  ) => Effect.Effect<VerifiedGrant, GrantVerificationFailed, GrantAuthority>;
}

export class GrantVerifier extends Context.Tag("GrantVerifier")<GrantVerifier, GrantVerifierApi>() {}

export const GrantVerifierLive: Layer.Layer<GrantVerifier, never, HttpClient.HttpClient> = Layer.effect(
  GrantVerifier,
  Effect.gen(function* () {
    const http_client = yield* HttpClient.HttpClient;
    const sets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

    const set_for = (jwks_url: string) => {
      const hit = sets.get(jwks_url);
      if (hit) return hit;
      // SDK boundary adapter (Promise execution allowed here): ONE scoped
      // Effect covers request + body read (no detached work outliving auth),
      // wired to the SDK abort signal with a bounded timeout. Caller headers
      // pass through; the SDK redirect mode is preserved verbatim via the
      // fetch RequestInit (authoritative jose policy untouched).
      const fetch_via_client = (
        url: string,
        options: { headers: Headers; method: "GET"; redirect: "manual"; signal: AbortSignal },
      ): Promise<Response> => {
        const header_record: Record<string, string> = {};
        options.headers.forEach((value, key) => {
          header_record[key] = value;
        });
        return Effect.runPromise(
          Effect.gen(function* () {
            const req = HttpClientRequest.get(url, {
              headers: { accept: "application/json", ...header_record },
            });
            const res = yield* http_client.execute(req).pipe(
              Effect.provideService(FetchHttpClient.RequestInit, { redirect: options.redirect }),
            );
            if (res.status < 200 || res.status >= 300) {
              return yield* Effect.fail(new Error("jwks fetch failed"));
            }
            const body: unknown = yield* res.json;
            return new Response(JSON.stringify(body), {
              status: res.status,
              headers: { "content-type": "application/json" },
            });
          }).pipe(
            Effect.timeoutFail({
              duration: 10_000,
              onTimeout: () => new Error("jwks fetch timed out"),
            }),
          ),
          { signal: options.signal },
        );
      };
      const set = createRemoteJWKSet(new URL(jwks_url), {
        cacheMaxAge: 10 * 60 * 1000,
        [customFetch]: fetch_via_client,
      });
      sets.set(jwks_url, set);
      if (sets.size > 16) {
        const first = sets.keys().next().value;
        if (first !== undefined) sets.delete(first);
      }
      return set;
    };

    const verify_grant: GrantVerifierApi["verify_grant"] = (jwt, now_sec) =>
      Effect.gen(function* () {
        const cfg = yield* GrantAuthority;
        const now = now_sec ?? Math.floor((yield* Clock.currentTimeMillis) / 1000);
        const jwks = set_for(cfg.jwks_url);
        const verified = yield* Effect.tryPromise({
          try: () =>
            jwtVerify(jwt, jwks, {
              issuer: cfg.core_iss,
              audience: cfg.relay_aud,
              algorithms: ["EdDSA"],
              clockTolerance: 60,
              currentDate: new Date(now * 1000),
            }),
          catch: (cause) => new GrantVerificationFailed({ reason: "grant verification failed", cause }),
        });
        if (verified.protectedHeader.alg !== "EdDSA") {
          return yield* Effect.fail(new GrantVerificationFailed({ reason: "unexpected alg" }));
        }
        if (typeof verified.protectedHeader.kid !== "string" || verified.protectedHeader.kid.length === 0) {
          return yield* Effect.fail(new GrantVerificationFailed({ reason: "missing kid" }));
        }
        try {
          const checked = check_grant_claims(verified.payload, now, cfg.max_ttl_sec);
          return {
            claims: checked.claims,
            kid: verified.protectedHeader.kid,
            cnfPk: checked.cnf_pk,
            scopes: checked.scopes,
          } satisfies VerifiedGrant;
        } catch (cause) {
          return yield* Effect.fail(
            new GrantVerificationFailed({
              reason: cause instanceof Error ? cause.message : "bad claims",
              cause,
            }),
          );
        }
      });
    return GrantVerifier.of({ verify_grant });
  }),
);
