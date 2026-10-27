import { decode_grant_claims, type GrantClaims } from "../../schema.ts";
import { b64u_decode } from "../../b64u.ts";

export interface CheckedGrant {
  readonly claims: GrantClaims;
  readonly cnf_pk: Uint8Array;
  readonly scopes: Set<string>;
}

export function check_grant_claims(
  payload: unknown,
  now_sec: number,
  max_ttl_sec: number,
): CheckedGrant {
  const claims = decode_grant_claims(payload);
  const ttl = claims.exp - claims.iat;
  if (ttl <= 0 || ttl > max_ttl_sec) throw new Error("grant ttl out of bounds");
  if (now_sec < claims.nbf) throw new Error("grant not yet valid");
  if (now_sec >= claims.exp) throw new Error("grant expired");
  if (claims.scope.length === 0) throw new Error("grant has no scope");
  const cnf_pk = b64u_decode(claims.cnf.jwk.x);
  if (cnf_pk.length !== 32) throw new Error("cnf key must be 32 bytes");
  return { claims, cnf_pk, scopes: new Set(claims.scope) };
}
