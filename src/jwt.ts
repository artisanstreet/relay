// Grant JWT verification: real JWT + JWKS, no custom token format.
// Issuer: Core only. Relay fetches Core's JWKS (cached) and verifies
// EdDSA signatures, audience, expiry, then decodes claims strictly via
// Effect Schema (unknown top-level claims rejected at v=1).

import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { decodeGrantClaims, type GrantClaims } from "./schema.ts";
import { b64uDecode } from "./b64u.ts";

export { b64uDecode, b64uEncode } from "./b64u.ts";

export interface GrantVerifierOptions {
  jwksUrl: string;
  expectedIss: string;
  expectedAud: string;
  maxTtlSec: number;
  cacheMaxAgeMs?: number;
}

export interface VerifiedGrant {
  claims: GrantClaims;
  /** Core signing key id (JWT header kid). */
  kid: string;
  /** Raw cnf Ed25519 public key bytes (32). */
  cnfPk: Uint8Array;
  scopes: Set<string>;
}

export type VerifyGrant = (jwt: string, nowSec?: number) => Promise<VerifiedGrant>;

/** Create a verifier. Remote JWKS is cached; pass a custom fetch in tests. */
export function createGrantVerifier(
  opts: GrantVerifierOptions,
  fetchImpl?: (url: string, options: { headers: Headers; method: "GET"; redirect: "manual"; signal: AbortSignal }) => Promise<Response>,
): VerifyGrant {
  const jwks = createRemoteJWKSet(new URL(opts.jwksUrl), {
    // Core §4: cache JWKS 10 min; unknown kid refetches (jose built-in).
    cacheMaxAge: opts.cacheMaxAgeMs ?? 10 * 60 * 1000,
    ...(fetchImpl ? { [customFetch]: fetchImpl } : {}),
  });

  return async (jwt: string, nowSec?: number): Promise<VerifiedGrant> => {
    const now = nowSec ?? Math.floor(Date.now() / 1000);
    const { payload, protectedHeader } = await jwtVerify(jwt, jwks, {
      issuer: opts.expectedIss,
      audience: opts.expectedAud,
      // Core §4: exp/nbf checked with ≤60 s clock skew.
      clockTolerance: 60,
      currentDate: new Date(now * 1000),
    });
    if (protectedHeader.alg !== "EdDSA") throw new Error("unexpected alg");
    if (typeof protectedHeader.kid !== "string" || protectedHeader.kid.length === 0) {
      throw new Error("missing kid");
    }
    const claims = decodeGrantClaims(payload);
    const ttl = claims.exp - claims.iat;
    if (ttl <= 0 || ttl > opts.maxTtlSec) throw new Error("grant ttl out of bounds");
    if (now < claims.nbf) throw new Error("grant not yet valid");
    if (now >= claims.exp) throw new Error("grant expired");
    if (claims.scope.length === 0) throw new Error("grant has no scope");
    const cnfPk = b64uDecode(claims.cnf.jwk.x);
    if (cnfPk.length !== 32) throw new Error("cnf key must be 32 bytes");
    return { claims, kid: protectedHeader.kid, cnfPk, scopes: new Set(claims.scope) };
  };
}

/** Audience check helper shared by HTTP + WS paths. */
export function hasScope(g: VerifiedGrant, scope: string): boolean {
  return g.scopes.has(scope);
}
