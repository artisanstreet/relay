// Grant JWT verification: real jose verify against a stub JWKS endpoint.
// Every rejection path is exercised; nothing here trusts test-only code.

import { describe, expect, it } from "vitest";
import { createGrantVerifier } from "../src/jwt.ts";
import { mintGrant, stubFetch, testCoreKey, TEST_AUD, TEST_ISS, TEST_JWKS_URL, TEST_KID } from "./helpers.ts";

function verifier(core = testCoreKey(), maxTtlSec = 300) {
  return createGrantVerifier(
    { jwksUrl: TEST_JWKS_URL, expectedIss: TEST_ISS, expectedAud: TEST_AUD, maxTtlSec },
    stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }] }),
  );
}

function tamperHeaderAlg(jwt: string, alg: string): string {
  const [h, p, s] = jwt.split(".");
  const hdr = JSON.parse(Buffer.from(h as string, "base64url").toString());
  hdr.alg = alg;
  return `${Buffer.from(JSON.stringify(hdr)).toString("base64url")}.${p}.${s}`;
}

describe("grant JWT verification", () => {
  it("accepts a well-formed Core grant", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { role: "forge", scope: ["relay:connect", "forge:execute", "machine:sync"] });
    const v = await verifier(core)(g.jwt);
    expect(v.claims.sub).toBe("acct1");
    expect(v.claims.mid).toBe("forge1");
    expect(v.claims.role).toBe("forge");
    expect(v.cnfPk.length).toBe(32);
  });

  it("rejects expired grants", async () => {
    const core = testCoreKey();
    const now = Math.floor(Date.now() / 1000);
    const g = await mintGrant(core, { iat: now - 400, exp: now - 100 });
    await expect(verifier(core)(g.jwt, now)).rejects.toThrow();
  });

  it("rejects not-yet-valid grants", async () => {
    const core = testCoreKey();
    const now = Math.floor(Date.now() / 1000);
    const g = await mintGrant(core, { iat: now + 60, nbf: now + 60, exp: now + 180 });
    await expect(verifier(core)(g.jwt, now)).rejects.toThrow();
  });

  it("rejects TTL over the bound", async () => {
    const core = testCoreKey();
    const now = Math.floor(Date.now() / 1000);
    const g = await mintGrant(core, { iat: now, exp: now + 3600 });
    await expect(verifier(core)(g.jwt, now)).rejects.toThrow(/ttl/);
  });

  it("rejects wrong issuer", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core);
    const bad = createGrantVerifier(
      { jwksUrl: TEST_JWKS_URL, expectedIss: "https://evil.test/", expectedAud: TEST_AUD, maxTtlSec: 300 },
      stubFetch({ keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }] }),
    );
    await expect(bad(g.jwt)).rejects.toThrow();
  });

  it("rejects wrong audience", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { aud: "ast-other" });
    await expect(verifier(core)(g.jwt)).rejects.toThrow();
  });

  it("rejects a non-EdDSA alg header", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core);
    await expect(verifier(core)(tamperHeaderAlg(g.jwt, "none"))).rejects.toThrow();
  });

  it("rejects missing kid", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { kid: null });
    await expect(verifier(core)(g.jwt)).rejects.toThrow();
  });

  it("rejects unknown top-level claims (strict v1)", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { extraClaims: { future_field: "x" } });
    await expect(verifier(core)(g.jwt)).rejects.toThrow();
  });

  it("rejects empty scope", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { scope: [] });
    await expect(verifier(core)(g.jwt)).rejects.toThrow();
  });

  it("rejects unknown scope values", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { scope: ["relay:teleport"] });
    await expect(verifier(core)(g.jwt)).rejects.toThrow();
  });

  it("rejects signatures from another Core key", async () => {
    const real = testCoreKey(0x42);
    const impostor = testCoreKey(0x99);
    const g = await mintGrant(impostor);
    await expect(verifier(real)(g.jwt)).rejects.toThrow();
  });

  it("rejects malformed compact JWTs", async () => {
    await expect(verifier()("not.a.jwt")).rejects.toThrow();
    await expect(verifier()("")).rejects.toThrow();
  });
});
