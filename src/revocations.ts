// Core v1 revocation list client (authoritative: Core docs/contracts.md §4,
// src/services/grants.ts): GET /v1/grants/revocations emits camelCase
// {revokedMachineIds, revokedKeyIds, asOf}. This module matches those EXACT
// field names (no self-defined variants); unknown fields are ignored
// (forward-compatible response reads). No epochs, no admin push: short
// grant expiry + this poll.

import { Schema } from "effect";
import type { Env } from "./index.ts";

const RevId = Schema.String.pipe(Schema.maxLength(256));

const RevocationsResponse = Schema.Struct({
  revokedMachineIds: Schema.optional(Schema.Array(RevId)),
  revokedKeyIds: Schema.optional(Schema.Array(RevId)),
  asOf: Schema.optional(Schema.Union(Schema.String, Schema.Number)),
});

export type RevocationsResponse = typeof RevocationsResponse.Type;

export const REVOCATION_POLL_MS = 60_000;

export function revocationsUrl(env: Env): string {
  if (env.CORE_REVOCATIONS_URL) return env.CORE_REVOCATIONS_URL;
  return `${env.CORE_ISS.replace(/\/$/, "")}/v1/grants/revocations`;
}

/** Pure parse of a Core revocations payload (shared by fetch + tests). */
export function parseRevocationsResponse(jsonBody: unknown): { machines: string[]; keys: string[] } {
  const parsed = Schema.decodeUnknownSync(RevocationsResponse)(jsonBody);
  return {
    machines: [...(parsed.revokedMachineIds ?? [])],
    keys: [...(parsed.revokedKeyIds ?? [])],
  };
}

export async function fetchRevocations(env: Env): Promise<{ machines: string[]; keys: string[] }> {
  const res = await fetch(revocationsUrl(env), { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`revocations fetch failed: ${res.status}`);
  const jsonBody: unknown = await res.json();
  return parseRevocationsResponse(jsonBody);
}
