// Relay infra config: single source of truth for deploy inputs.
// Pure (no Alchemy imports) so vitest runs fully offline without cloud.
// alchemy.run.ts imports everything below; tests import it too — never
// mirror these literals anywhere else.

/** Alchemy stack name. Distinct from Core's stack; both share the default
 *  account-level Cloudflare state store, isolated by (stack, stage). */
export const STACK_NAME = "artisan-relay";

/** Logical ID of the Relay Worker resource within the stack. */
export const WORKER_LOGICAL_ID = "Relay";

/** Durable Object binding name exposed on the Worker env. */
export const DO_BINDING_NAME = "MACHINE_ROOM";

/** Durable Object class name exported by ../src/index.ts. */
export const DO_CLASS_NAME = "MachineRoom";

/** Entry module bundled intact (Effect worker, NOT Alchemy runtime classes). */
export const WORKER_MAIN = "../src/index.ts";

/** Must match wrangler.toml compatibility_date (local/test parity). */
export const COMPATIBILITY_DATE = "2026-10-26";

/** Fixed non-secret Worker vars (exact values). */
export const RELAY_AUD = "ast-relay";
export const GRANT_MAX_TTL_S = "300";
export const REVOCATION_POLL_MS = "60000";

/** Deploy input env var names (public origins, NOT secrets). */
export const CORE_ORIGIN_VAR = "AST_CORE_ORIGIN";
export const RELAY_ORIGIN_VAR = "AST_RELAY_ORIGIN";

/**
 * Validate an exact https origin: single `https://host[:port]`, no path,
 * query, hash, userinfo, or trailing content. Returns the normalized
 * origin (`scheme://host[:port]`, default ports stripped, no trailing `/`).
 * Throws with the var name on any violation (fail closed).
 */
export function parse_https_origin(raw: string, var_name: string): string {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error(`${var_name} is required (exact https origin)`);
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error(`${var_name} must be an exact https origin, got unparsable value`);
  }
  if (url.protocol !== "https:") {
    throw new Error(`${var_name} must be https (no http, no wildcards)`);
  }
  // URL parses wildcards (`https://*.example.com`, `%2A` normalizes to `*`):
  // reject explicitly — origins here become single-owner custom domains.
  if (url.hostname.includes("*")) {
    throw new Error(`${var_name} must be exact (no wildcards)`);
  }
  if (url.username || url.password) {
    throw new Error(`${var_name} must not contain userinfo`);
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new Error(`${var_name} must be a bare origin (no path)`);
  }
  if (url.search || url.hash) {
    throw new Error(`${var_name} must be a bare origin (no query/hash)`);
  }
  if (!url.hostname) throw new Error(`${var_name} must include a hostname`);
  // Normalize: strip the default https port, drop any trailing slash.
  const port = url.port === "443" ? "" : url.port ? `:${url.port}` : "";
  return `https://${url.hostname}${port}`;
}

/** Hostname for the `domain` prop (zone inferred from it, must pre-exist). */
export function get_hostname(origin: string): string {
  return new URL(origin).hostname;
}

export interface RelayVars {
  CORE_JWKS_URL: string;
  CORE_ISS: string;
  CORE_REVOCATIONS_URL: string;
  RELAY_PORTAL_ORIGIN: string;
}

/** Derive exact Worker vars from the validated Core origin. */
export function derive_relay_vars(core_origin: string): RelayVars {
  return {
    CORE_JWKS_URL: `${core_origin}/.well-known/jwks.json`,
    CORE_ISS: core_origin,
    CORE_REVOCATIONS_URL: `${core_origin}/v1/grants/revocations`,
    RELAY_PORTAL_ORIGIN: core_origin,
  };
}

export interface DeployOrigins {
  core_origin: string;
  relay_origin: string;
}

/**
 * Validate BOTH deploy origins together. Rejects identical origins: Core and
 * Relay are separate custom-domain Workers and two Workers cannot own the
 * same host (a preview stage reusing prod domains would fight production for
 * its custom domain despite isolated Worker names and DO state).
 */
export function parse_deploy_origins(core_raw: string, relay_raw: string): DeployOrigins {
  const core_origin = parse_https_origin(core_raw, CORE_ORIGIN_VAR);
  const relay_origin = parse_https_origin(relay_raw, RELAY_ORIGIN_VAR);
  // Custom-domain ownership is HOSTNAME, not origin: same host with different
  // ports still maps both `domain` props onto one custom domain (and Core is
  // adopting the same explicit custom-domain convention on every stage).
  if (get_hostname(core_origin) === get_hostname(relay_origin)) {
    throw new Error(
      `${RELAY_ORIGIN_VAR} must use a different host than ${CORE_ORIGIN_VAR} ` +
        `(two custom-domain Workers cannot own the same hostname, regardless of port)`,
    );
  }
  return { core_origin, relay_origin };
}
