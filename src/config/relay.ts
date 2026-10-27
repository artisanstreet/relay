import { Context, Effect } from "effect";
import { normalizePortalOrigin } from "../cors.ts";
import { RelayMisconfigured } from "../errors.ts";

export interface Env {
  MACHINE_ROOM: DurableObjectNamespace;
  CORE_JWKS_URL: string;
  CORE_ISS: string;
  RELAY_AUD?: string;
  GRANT_MAX_TTL_S?: string;
  CORE_REVOCATIONS_URL?: string;
  REVOCATION_POLL_MS?: string;
  RELAY_PORTAL_ORIGIN?: string;
}

export interface RelayConfig {
  readonly jwks_url: string;
  readonly core_iss: string;
  readonly relay_aud: string;
  readonly max_ttl_sec: number;
  readonly revocations_url: string;
  readonly poll_ms: number;
  readonly portal_origin: string | null;
  readonly raw_env: Env;
}

export class RelayEnv extends Context.Tag("RelayEnv")<RelayEnv, RelayConfig>() {}

export const REVOCATION_POLL_MS_DEFAULT = 60_000;

export function parse_env(env: Env): Effect.Effect<RelayConfig, RelayMisconfigured> {
  return Effect.gen(function* () {
    if (!env.CORE_JWKS_URL || !env.CORE_ISS) {
      return yield* Effect.fail(
        new RelayMisconfigured({ reason: "relay misconfigured" }),
      );
    }
    const max_ttl_raw = Number(env.GRANT_MAX_TTL_S ?? 300);
    const max_ttl_sec = Number.isFinite(max_ttl_raw) && max_ttl_raw > 0
      ? max_ttl_raw
      : 300;
    const poll_raw = Number(env.REVOCATION_POLL_MS ?? REVOCATION_POLL_MS_DEFAULT);
    const poll_ms = Number.isFinite(poll_raw) && poll_raw >= 1000
      ? poll_raw
      : REVOCATION_POLL_MS_DEFAULT;
    const revocations_url = env.CORE_REVOCATIONS_URL ??
      `${env.CORE_ISS.replace(/\/$/, "")}/v1/grants/revocations`;
    return {
      jwks_url: env.CORE_JWKS_URL,
      core_iss: env.CORE_ISS,
      relay_aud: env.RELAY_AUD ?? "ast-relay",
      max_ttl_sec,
      revocations_url,
      poll_ms,
      portal_origin: normalizePortalOrigin(env.RELAY_PORTAL_ORIGIN),
      raw_env: env,
    } satisfies RelayConfig;
  });
}

export function room_id(
  ns: DurableObjectNamespace,
  account: string,
  machine: string,
): DurableObjectId {
  return ns.idFromName(`${account}/${machine}`);
}
