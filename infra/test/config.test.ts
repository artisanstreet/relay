// Behavioral tests for deploy-input validation (offline, no cloud).
// Every case exercises real behavior used by alchemy.run.ts: origin parsing,
// Core/Relay distinctness, var derivation. Literals below come from the task
// spec / Cloudflare constraints — not from the implementation.
import { describe, expect, test } from "vitest";
import {
  GRANT_MAX_TTL_S,
  RELAY_AUD,
  REVOCATION_POLL_MS,
  deriveRelayVars,
  getHostname,
  parseDeployOrigins,
  parseHttpsOrigin,
} from "../config.ts";

describe("origins (exact https, fail closed)", () => {
  test("accepts bare origins and normalizes", () => {
    expect(parseHttpsOrigin("https://core.example.com", "V")).toBe("https://core.example.com");
    expect(parseHttpsOrigin("https://core.example.com/", "V")).toBe("https://core.example.com");
    expect(parseHttpsOrigin("  https://core.example.com  ", "V")).toBe("https://core.example.com");
    expect(parseHttpsOrigin("https://core.example.com:8443", "V")).toBe(
      "https://core.example.com:8443",
    );
    // Default port is stripped.
    expect(parseHttpsOrigin("https://core.example.com:443", "V")).toBe(
      "https://core.example.com",
    );
  });

  test("rejects non-origins and wildcards", () => {
    for (const bad of [
      "",
      "   ",
      "http://core.example.com",
      "https://core.example.com/api",
      "https://core.example.com/v1/grants",
      "https://core.example.com?x=1",
      "https://core.example.com#frag",
      "https://user@core.example.com/",
      "https://*.example.com",
      "https://%2A.example.com",
      "https://foo.*.example.com",
      "not-a-url",
      "ftp://core.example.com",
    ]) {
      expect(() => parseHttpsOrigin(bad, "V"), JSON.stringify(bad)).toThrow();
    }
  });
});

describe("deploy origins (Core vs Relay must differ)", () => {
  test("accepts two distinct origins", () => {
    expect(
      parseDeployOrigins("https://core.example.com", "https://relay.example.com"),
    ).toEqual({
      coreOrigin: "https://core.example.com",
      relayOrigin: "https://relay.example.com",
    });
  });

  test("rejects identical origins (normalization-aware)", () => {
    expect(() =>
      parseDeployOrigins("https://x.example.com", "https://x.example.com"),
    ).toThrow();
    expect(() =>
      parseDeployOrigins("https://x.example.com", "https://x.example.com/"),
    ).toThrow();
  });

  test("rejects when either side is invalid", () => {
    expect(() =>
      parseDeployOrigins("http://core.example.com", "https://relay.example.com"),
    ).toThrow();
    expect(() =>
      parseDeployOrigins("https://core.example.com", "https://*.example.com"),
    ).toThrow();
  });
});

describe("derived Relay vars (exact)", () => {
  test("Core-derived endpoints use the validated origin verbatim", () => {
    const v = deriveRelayVars("https://core.example.com");
    expect(v.CORE_ISS).toBe("https://core.example.com");
    expect(v.CORE_JWKS_URL).toBe("https://core.example.com/.well-known/jwks.json");
    expect(v.CORE_REVOCATIONS_URL).toBe("https://core.example.com/v1/grants/revocations");
    expect(v.RELAY_PORTAL_ORIGIN).toBe("https://core.example.com");
  });

  test("fixed vars are exact", () => {
    expect(RELAY_AUD).toBe("ast-relay");
    expect(GRANT_MAX_TTL_S).toBe("300");
    expect(REVOCATION_POLL_MS).toBe("60000");
  });
});

describe("domain", () => {
  test("domain is the relay origin hostname (zone inferred, must pre-exist)", () => {
    expect(getHostname("https://relay.example.com")).toBe("relay.example.com");
    expect(getHostname("https://relay.example.com:8443")).toBe("relay.example.com");
  });
});
