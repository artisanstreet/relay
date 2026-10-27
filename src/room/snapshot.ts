import { Either } from "effect";
import { b64u_decode } from "../b64u.ts";
import type { VerifiedGrant } from "../services/grants/verifier.ts";
import { filter_known_scopes } from "./revocation.ts";
import type { SnapshotConn } from "./types.ts";

export function restored_grant(
  account: string,
  machine: string,
  c: SnapshotConn,
): VerifiedGrant | null {
  if (!Array.isArray((c as { scope?: unknown }).scope)) return null;
  const scope = filter_known_scopes(c.scope);
  if (!scope.includes("relay:connect")) return null;
  const cnf_pk = Either.try({
    try: () => b64u_decode(c.cnfX),
    catch: () => new Uint8Array(32),
  }).pipe(
    Either.map((b) => (b.length !== 32 ? new Uint8Array(32) : b)),
    Either.getOrElse((fallback) => fallback),
  );
  const typed_scope = scope as VerifiedGrant["claims"]["scope"];
  return {
    claims: {
      v: 1,
      iss: "",
      aud: "",
      sub: account,
      mid: machine,
      jti: c.jti,
      iat: 0,
      nbf: 0,
      exp: c.exp,
      role: c.role,
      scope: typed_scope,
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: c.cnfX } },
    },
    kid: c.kid,
    cnf_pk: cnf_pk,
    scopes: new Set<string>(scope),
  };
}
