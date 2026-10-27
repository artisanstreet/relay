// Cross-origin browser access for the account portal (narrow scope).
//
// The portal (Core-served SPA) talks to Relay cross-origin: presence reads
// (`Authorization: Bearer <grant>`) need a preflight, so the worker must
// answer OPTIONS and reflect an explicitly configured portal origin.
// Rules:
// - RELAY_PORTAL_ORIGIN is ONE exact https:// origin (host + optional
//   non-default port). No wildcards, no paths, no credentials, no
//   scheme-relative values. Unset or invalid => no CORS headers at all
//   (fail closed); same-origin and native clients are unaffected.
// - Allowed origin => `Access-Control-Allow-Origin: <origin>` (exact echo,
//   never `*`) + `Vary: Origin` on the response. Preflight answers
//   `GET` + `Authorization` (+ `Content-Type` for JSON posts elsewhere),
//   204, `max-age=600`. Disallowed Origin => no CORS headers (browser
//   blocks); the response itself is unchanged.
// - No `Access-Control-Allow-Credentials` ever: Relay auth is Bearer
//   grants, never cookies. Nothing here reads or writes cookies.
// - WebSocket upgrades: browsers always send Origin; native clients send
//   none. When a portal origin is configured and an Origin IS present, it
//   must match, otherwise the upgrade is refused (4403 room-side would be
//   wrong here: this is admission, so 403 JSON). Absent Origin always
//   proceeds to grant+PoP admission (native clients unaffected).

import { Either } from "effect";

/** Normalized `scheme://host[:port]`, or null when unset/invalid. */
export function normalize_portal_origin(raw: string | undefined): string | null {
  if (!raw) return null;
  const v = raw.trim().replace(/\/+$/, "");
  if (!v || v.includes("*")) return null;
  return Either.match(Either.try({ try: () => new URL(v), catch: () => null }), {
    onLeft: () => null,
    onRight: (u) => {
      if (u.protocol !== "https:" && u.protocol !== "http:") return null;
      if (u.username || u.password) return null;
      if (u.pathname !== "/" && u.pathname !== "") return null;
      if (u.search || u.hash) return null;
      const def_port = u.protocol === "https:" ? "443" : "80";
      const port = u.port && u.port !== def_port ? `:${u.port}` : "";
      const host = u.hostname.toLowerCase();
      if (!host) return null;
      return `${u.protocol}//${host}${port}`;
    },
  });
}

/** Exact-match check of a request Origin against the configured portal. */
export function is_allowed_origin(request_origin: string | null, portal_origin: string | null): boolean {
  if (!portal_origin) return false;
  if (!request_origin) return false;
  return normalize_portal_origin(request_origin) === portal_origin;
}

const CORS_METHODS = "GET, OPTIONS";
const CORS_HEADERS = "Authorization, Content-Type";

/**
 * CORS headers for an actual response. Returns null when no CORS headers
 * apply (no Origin, no configured portal, or disallowed origin).
 */
export function cors_response_headers(req: Request, portal_origin: string | null): Headers | null {
  const origin = req.headers.get("Origin");
  if (!is_allowed_origin(origin, portal_origin)) return null;
  const h = new Headers();
  h.set("Access-Control-Allow-Origin", portal_origin as string);
  h.set("Vary", "Origin");
  return h;
}

/** Standalone preflight answer, or null when this request is not an allowed preflight. */
export function cors_preflight(req: Request, allowed_paths: RegExp, portal_origin: string | null): Response | null {
  if (req.method !== "OPTIONS") return null;
  const origin = req.headers.get("Origin");
  if (!origin) return null;
  if (!new URL(req.url, "https://relay.invalid").pathname.match(allowed_paths)) return null;
  if (!portal_origin || !is_allowed_origin(origin, portal_origin)) return null;
  const want_method = (req.headers.get("Access-Control-Request-Method") ?? "GET").toUpperCase();
  if (want_method !== "GET" && want_method !== "OPTIONS") return null;
  const want_headers = (req.headers.get("Access-Control-Request-Headers") ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const allowed = new Set(["authorization", "content-type"]);
  if (want_headers.some((h) => !allowed.has(h))) return null;
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": portal_origin,
      "Access-Control-Allow-Methods": CORS_METHODS,
      "Access-Control-Allow-Headers": CORS_HEADERS,
      "Access-Control-Max-Age": "600",
      Vary: "Origin",
    },
  });
}

/**
 * WebSocket-upgrade Origin gate. Returns an error Response to send instead
 * of upgrading, or null to proceed to grant+PoP admission. Native clients
 * (no Origin) always proceed.
 */
export function ws_origin_gate(req: Request, portal_origin: string | null): Response | null {
  if (!portal_origin) return null;
  const origin = req.headers.get("Origin");
  if (!origin) return null;
  if (normalize_portal_origin(origin) === portal_origin) return null;
  return new Response(JSON.stringify({ error: "forbidden origin" }), {
    status: 403,
    headers: { "content-type": "application/json" },
  });
}
