// Grant JWT verification: real JWT + JWKS, no custom token format.
// Issuer: Core only. Relay fetches Core's JWKS (cached) and verifies
// EdDSA signatures, audience, expiry, then decodes claims strictly via
// Effect Schema (unknown top-level claims rejected at v=1).

import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { decodeGrantClaims, type GrantClaims } from "./schema.ts";

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

const b64uRe = /^[A-Za-z0-9_-]+$/;

export function b64uDecode(s: string): Uint8Array {
  if (!b64uRe.test(s) || s.length === 0 || s.length % 4 === 1) {
    throw new Error("invalid base64url");
  }
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64uEncode(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 8192) {
    s += String.fromCharCode(...b.subarray(i, i + 8192));
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Create a verifier. Remote JWKS is cached; pass a custom fetch in tests. */
export function createGrantVerifier(
  opts: GrantVerifierOptions,
  fetchImpl?: (url: string, options: { headers: Headers; method: "GET"; redirect: "manual"; signal: AbortSignal }) => Promise<Response>,
): VerifyGrant {
  const jwks = createRemoteJWKSet(new URL(opts.jwksUrl), {
    cacheMaxAge: opts.cacheMaxAgeMs ?? 5 * 60 * 1000,
    ...(fetchImpl ? { [customFetch]: fetchImpl } : {}),
  });

  return async (jwt: string, nowSec?: number): Promise<VerifiedGrant> => {
    const now = nowSec ?? Math.floor(Date.now() / 1000);
    const { payload, protectedHeader } = await jwtVerify(jwt, jwks, {
      issuer: opts.expectedIss,
      audience: opts.expectedAud,
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
