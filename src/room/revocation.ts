import { sha256 } from "@noble/hashes/sha2.js";
import { b64uEncode } from "../b64u.ts";
import type { VerifiedGrant } from "../services/grants/verifier.ts";

const KNOWN_SCOPES = new Set(["relay:connect", "forge:execute", "machine:sync"]);

export function filter_known_scopes(scope: unknown): string[] {
  if (!Array.isArray(scope)) return [];
  return scope.filter((s): s is string => typeof s === "string" && KNOWN_SCOPES.has(s));
}

function key_forms(kid: string, cnf_pk: Uint8Array): string[] {
  const digest = sha256(cnf_pk);
  const hex_fpr = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  let s = "";
  for (let i = 0; i < digest.length; i += 8192) {
    s += String.fromCharCode(...digest.subarray(i, i + 8192));
  }
  const b64_fpr = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return [kid, b64uEncode(cnf_pk), hex_fpr, b64_fpr];
}

export function matches_revoked_keys(
  kid: string,
  cnf_pk: Uint8Array,
  revoked_keys: Set<string>,
): boolean {
  return key_forms(kid, cnf_pk).some((f) => revoked_keys.has(f));
}

export function is_revoked(
  grant: VerifiedGrant,
  revoked_machines: Set<string>,
  revoked_keys: Set<string>,
): boolean {
  if (revoked_machines.has(grant.claims.mid)) return true;
  return matches_revoked_keys(grant.kid, grant.cnfPk, revoked_keys);
}
