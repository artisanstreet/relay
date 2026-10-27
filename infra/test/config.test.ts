import { describe, expect, test } from "vitest";
import {
  COMPATIBILITY_DATE,
  DO_BINDING_NAME,
  DO_CLASS_NAME,
  GRANT_MAX_TTL_S,
  RELAY_AUD,
  REVOCATION_POLL_MS,
  STACK_NAME,
  WORKER_LOGICAL_ID,
  WORKER_MAIN,
  deriveRelayVars,
  getHostname,
  isValidStage,
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

  test("rejects non-origins", () => {
    for (const bad of [
      "",
      "   ",
      "http://core.example.com",
      "https://core.example.com/api",
      "https://core.example.com/v1/grants",
      "https://core.example.com?x=1",
      "https://core.example.com#frag",
      "https://user@core.example.com/",
      "not-a-url",
      "ftp://core.example.com",
    ]) {
      expect(() => parseHttpsOrigin(bad, "V"), JSON.stringify(bad)).toThrow();
    }
  });

  test("production origins must be exact https (no http, no path)", () => {
    expect(() => parseHttpsOrigin("http://relay.example.com", "AST_RELAY_ORIGIN")).toThrow();
    expect(() => parseHttpsOrigin("https://relay.example.com/extra", "AST_RELAY_ORIGIN")).toThrow();
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

describe("domain / stage separation", () => {
  test("domain is the relay origin hostname (zone inferred, must pre-exist)", () => {
    expect(getHostname("https://relay.example.com")).toBe("relay.example.com");
    expect(getHostname("https://relay.example.com:8443")).toBe("relay.example.com");
  });

  test("stage names follow Alchemy's [a-z0-9][-_a-z0-9]* rule", () => {
    for (const ok of ["prod", "staging", "pr-42", "live_sam", "dev_sam", "test_sam"]) {
      expect(isValidStage(ok), ok).toBe(true);
    }
    for (const bad of ["", "Prod", "pr/42", "live sam", "-lead", "_lead"]) {
      expect(isValidStage(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  test("stack identity is Relay-owned and distinct from Core", () => {
    expect(STACK_NAME).toBe("artisan-relay");
    expect(WORKER_LOGICAL_ID).toBe("Relay");
    expect(WORKER_MAIN).toBe("../src/index.ts");
    expect(COMPATIBILITY_DATE).toBe("2026-10-26");
  });

  test("DO identity is stable: MACHINE_ROOM -> MachineRoom (SQLite, hibernation in runtime)", () => {
    expect(DO_BINDING_NAME).toBe("MACHINE_ROOM");
    expect(DO_CLASS_NAME).toBe("MachineRoom");
  });
});
