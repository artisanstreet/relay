// CORS + WebSocket Origin handling for the configured portal origin.
// Part A: pure unit tests (no worker). Part B: worker-level tests through
// Miniflare dispatchFetch with exact browser header sets (node fetch
// cannot set Origin — it is a forbidden header — so dispatchFetch carries
// the crafted Requests). Real-Chromium coverage lives in
// test/cors-browser.test.ts.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { mintGrant, testCoreKey, TEST_AUD, TEST_ISS, TEST_KID } from "./helpers.ts";
import {
  corsPreflight,
  corsResponseHeaders,
  isAllowedOrigin,
  normalizePortalOrigin,
  wsOriginGate,
} from "../src/cors.ts";

const PORTAL = "https://portal.test:8443";
const EVIL = "https://evil.test";

describe("portal origin normalization", () => {
  it("accepts exact https origins, normalizing case and default ports", () => {
    expect(normalizePortalOrigin("https://portal.test:8443")).toBe("https://portal.test:8443");
    expect(normalizePortalOrigin("https://portal.test:8443/")).toBe("https://portal.test:8443");
    expect(normalizePortalOrigin("HTTPS://Portal.TEST:443")).toBe("https://portal.test");
    expect(normalizePortalOrigin("http://127.0.0.1:8787")).toBe("http://127.0.0.1:8787");
    expect(normalizePortalOrigin("http://127.0.0.1:80")).toBe("http://127.0.0.1");
  });

  it("rejects wildcards, paths, credentials, non-http schemes, empties", () => {
    expect(normalizePortalOrigin(undefined)).toBeNull();
    expect(normalizePortalOrigin("")).toBeNull();
    expect(normalizePortalOrigin("https://*.test")).toBeNull();
    expect(normalizePortalOrigin("https://portal.test/app")).toBeNull();
    expect(normalizePortalOrigin("https://user:pass@portal.test")).toBeNull();
    expect(normalizePortalOrigin("wss://portal.test")).toBeNull();
    expect(normalizePortalOrigin("portal.test")).toBeNull();
    expect(normalizePortalOrigin("https://portal.test?q=1")).toBeNull();
  });

  it("matches exactly after normalization", () => {
    expect(isAllowedOrigin("https://portal.test:8443", PORTAL)).toBe(true);
    expect(isAllowedOrigin("https://portal.test:8443/", PORTAL)).toBe(true);
    expect(isAllowedOrigin(EVIL, PORTAL)).toBe(false);
    expect(isAllowedOrigin("https://portal.test.evil.test", PORTAL)).toBe(false);
    expect(isAllowedOrigin(null, PORTAL)).toBe(false);
    expect(isAllowedOrigin("https://portal.test:8443", null)).toBe(false);
  });
});

describe("preflight + response headers (pure)", () => {
  const preflightReq = (origin: string | null, extra: Record<string, string> = {}) =>
    new Request("https://relay.invalid/v1/presence/acct1/mch1", {
      method: "OPTIONS",
      headers: {
        ...(origin ? { Origin: origin } : {}),
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
        ...extra,
      },
    });

  it("answers allowed preflights with a tight allow-list", () => {
    const res = corsPreflight(preflightReq(PORTAL), /^\/(v1\/presence\/[^/]+\/[^/]+|v1\/health)$/, PORTAL);
    expect(res).not.toBeNull();
    expect(res!.status).toBe(204);
    expect(res!.headers.get("Access-Control-Allow-Origin")).toBe(PORTAL);
    expect(res!.headers.get("Access-Control-Allow-Methods")).toBe("GET, OPTIONS");
    expect(res!.headers.get("Access-Control-Allow-Headers")).toContain("Authorization");
    expect(res!.headers.get("Access-Control-Allow-Credentials")).toBeNull();
    expect(res!.headers.get("Vary")).toBe("Origin");
  });

  it("refuses disallowed origins, wrong methods, and excess headers", () => {
    expect(corsPreflight(preflightReq(EVIL), /./, PORTAL)).toBeNull();
    expect(corsPreflight(preflightReq(null), /./, PORTAL)).toBeNull();
    expect(corsPreflight(preflightReq(PORTAL), /./, null)).toBeNull();
    expect(corsPreflight(preflightReq(PORTAL, { "Access-Control-Request-Method": "DELETE" }), /./, PORTAL)).toBeNull();
    expect(
      corsPreflight(preflightReq(PORTAL, { "Access-Control-Request-Headers": "authorization, x-evil" }), /./, PORTAL),
    ).toBeNull();
    expect(corsPreflight(preflightReq(PORTAL), /^\/other/, PORTAL)).toBeNull();
  });

  it("reflects only the allowed origin on actual responses", () => {
    const ok = new Request("https://relay.invalid/v1/presence/a/m", { headers: { Origin: PORTAL } });
    const h = corsResponseHeaders(ok, PORTAL);
    expect(h?.get("Access-Control-Allow-Origin")).toBe(PORTAL);
    const evil = new Request("https://relay.invalid/v1/presence/a/m", { headers: { Origin: EVIL } });
    expect(corsResponseHeaders(evil, PORTAL)).toBeNull();
    const none = new Request("https://relay.invalid/v1/presence/a/m");
    expect(corsResponseHeaders(none, PORTAL)).toBeNull();
  });
});

describe("websocket origin gate (pure)", () => {
  const upgrade = (origin: string | null) =>
    new Request("wss://relay.invalid/v1/route/acct1/mch1", {
      headers: {
        Upgrade: "websocket",
        ...(origin ? { Origin: origin } : {}),
      },
    });

  it("lets matching and absent origins through, refuses mismatches", () => {
    expect(wsOriginGate(upgrade(PORTAL), PORTAL)).toBeNull();
    expect(wsOriginGate(upgrade(null), PORTAL)).toBeNull();
    expect(wsOriginGate(upgrade("https://portal.test:8443"), null)).toBeNull();
    const blocked = wsOriginGate(upgrade(EVIL), PORTAL);
    expect(blocked?.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// Worker level: exact browser header sets through a real workerd instance.
// ---------------------------------------------------------------------------

let mf: Miniflare;
let jwksServer: ReturnType<typeof createServer>;
let base = "";
const core = testCoreKey();
const PORTAL_HTTP = "http://127.0.0.1:18091";

beforeAll(async () => {
  jwksServer = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }],
    }));
  });
  await new Promise<void>((r) => jwksServer.listen(0, "127.0.0.1", () => r()));
  const jwksPort = (jwksServer.address() as AddressInfo).port;

  await build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["workerd", "worker", "browser"],
    outfile: "dist/worker.mjs",
    allowOverwrite: true,
    logLevel: "warning",
  });
  mf = new Miniflare({
    modules: true,
    scriptPath: "dist/worker.mjs",
    durableObjects: { MACHINE_ROOM: "MachineRoom" },
    bindings: {
      CORE_JWKS_URL: `http://127.0.0.1:${jwksPort}/jwks.json`,
      CORE_ISS: TEST_ISS,
      RELAY_AUD: TEST_AUD,
      GRANT_MAX_TTL_S: "300",
      CORE_REVOCATIONS_URL: `http://127.0.0.1:${jwksPort}/v1/grants/revocations`,
      REVOCATION_POLL_MS: "60000",
      RELAY_PORTAL_ORIGIN: PORTAL_HTTP,
    },
  });
  base = String(await mf.ready);
}, 120_000);

afterAll(async () => {
  await mf?.dispose();
  jwksServer?.close();
});

function dispatch(path: string, init: { method?: string; headers?: Record<string, string> }): Promise<Response> {
  // dispatchFetch (not global fetch): undici fetch() strips the forbidden
  // Origin header, but the Dispatcher preserves a Request's origin — which
  // is exactly the browser behavior under test. Cast past the nominal
  // workerd/DOM type split; only status/headers/body are consumed.
  const f = mf.dispatchFetch as unknown as (url: string, init: unknown) => Promise<Response>;
  return f(`${base}${path}`, init);
}

describe("worker CORS behavior (miniflare)", () => {
  it("answers allowed preflights; disallowed origins get nothing", async () => {
    const ok = await dispatch("/v1/presence/acct1/forge1", {
      method: "OPTIONS",
      headers: {
        Origin: PORTAL_HTTP,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
      },
    });
    expect(ok.status).toBe(204);
    expect(ok.headers.get("Access-Control-Allow-Origin")).toBe(PORTAL_HTTP);
    expect(ok.headers.get("Access-Control-Allow-Headers")).toContain("Authorization");
    expect(ok.headers.get("Access-Control-Allow-Credentials")).toBeNull();

    const evil = await dispatch("/v1/presence/acct1/forge1", {
      method: "OPTIONS",
      headers: {
        Origin: "http://evil.test",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
      },
    });
    expect(evil.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("reflects the portal origin on authed presence reads only", async () => {
    const g = await mintGrant(core, {});
    const good = await dispatch("/v1/presence/acct1/forge1", {
      headers: { Origin: PORTAL_HTTP, Authorization: `Bearer ${g.jwt}` },
    });
    expect(good.status).toBe(200);
    expect(good.headers.get("Access-Control-Allow-Origin")).toBe(PORTAL_HTTP);
    expect(good.headers.get("Vary")).toContain("Origin");

    const evil = await dispatch("/v1/presence/acct1/forge1", {
      headers: { Origin: "http://evil.test", Authorization: `Bearer ${g.jwt}` },
    });
    expect(evil.status).toBe(200);
    expect(evil.headers.get("Access-Control-Allow-Origin")).toBeNull();

    const plain = await dispatch("/v1/presence/acct1/forge1", {
      headers: { Authorization: `Bearer ${g.jwt}` },
    });
    expect(plain.status).toBe(200);
    expect(plain.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("refuses mismatched-Origin upgrades pre-handshake, lets others through", async () => {
    const blocked = await dispatch("/v1/route/acct1/forge1", {
      headers: { Upgrade: "websocket", Origin: "http://evil.test" },
    });
    expect(blocked.status).toBe(403);

    // Matching Origin proceeds past the gate (into the DO upgrade path,
    // which needs a real socket — here we only assert it is NOT the
    // origin gate rejecting).
    const allowed = await dispatch("/v1/route/acct1/forge1", {
      headers: { Upgrade: "websocket", Origin: PORTAL_HTTP },
    });
    expect(allowed.status).not.toBe(403);

    const native = await dispatch("/v1/route/acct1/forge1", {
      headers: { Upgrade: "websocket" },
    });
    expect(native.status).not.toBe(403);
  });
});
