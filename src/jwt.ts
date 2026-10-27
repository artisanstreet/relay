import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { check_grant_claims } from "./services/grants/checks.ts";
import type { GrantClaims } from "./schema.ts";

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
  kid: string;
  cnfPk: Uint8Array;
  scopes: Set<string>;
}

export type VerifyGrant = (jwt: string, nowSec?: number) => Promise<VerifiedGrant>;

export function createGrantVerifier(
  opts: GrantVerifierOptions,
  fetchImpl?: (url: string, options: { headers: Headers; method: "GET"; redirect: "manual"; signal: AbortSignal }) => Promise<Response>,
): VerifyGrant {
  const jwks = createRemoteJWKSet(new URL(opts.jwksUrl), {
    cacheMaxAge: opts.cacheMaxAgeMs ?? 10 * 60 * 1000,
    ...(fetchImpl ? { [customFetch]: fetchImpl } : {}),
  });

  return async (jwt: string, nowSec?: number): Promise<VerifiedGrant> => {
    const now = nowSec ?? Math.floor(Date.now() / 1000);
    const { payload, protectedHeader } = await jwtVerify(jwt, jwks, {
      issuer: opts.expectedIss,
      audience: opts.expectedAud,
      algorithms: ["EdDSA"],
      clockTolerance: 60,
      currentDate: new Date(now * 1000),
    });
    if (protectedHeader.alg !== "EdDSA") throw new Error("unexpected alg");
    if (typeof protectedHeader.kid !== "string" || protectedHeader.kid.length === 0) {
      throw new Error("missing kid");
    }
    const checked = check_grant_claims(payload, now, opts.maxTtlSec);
    return { claims: checked.claims, kid: protectedHeader.kid, cnfPk: checked.cnf_pk, scopes: checked.scopes };
  };
}

export function hasScope(g: VerifiedGrant, scope: string): boolean {
  return g.scopes.has(scope);
}
