// Real Core artifact verification (release-copy path).
//
// Uses contracts/fixtures/core-issued.json — a BYTE-EXACT copy of
// core/fixtures/v1/core-issued.json made by scripts/copy-core-fixture.mjs
// (see core-issued.meta.json for source hash). No hand edits, no mirrored
// values: whatever Core emitted is what we verify (signature via the
// artifact JWKS, claim names, revocation enforcement in rooms built from
// the artifact's own sub/mid).
//
// NOTE for root/Core: the artifact's `expected.cnf` block is double-nested
// ({jwk:{jwk:{...}}}) while the actual JWT claims (and contracts.md §4)
// use single nesting ({jwk:{...}}). This test asserts the ACTUAL claims;
// the quirk is documented, not worked around.

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createGrantVerifier } from "../src/jwt.ts";
import { parseRevocationsResponse } from "../src/revocations.ts";
import { makeRoom, send, fakeSocket, stubFetch } from "./helpers.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ARTIFACT = join(root, "contracts", "fixtures", "core-issued.json");

interface CoreIssued {
  note: string;
  issuer: string;
  audience: string;
  accountId: string;
  machineId: string;
  issuedAt: string;
  expiresAt: string;
  expected: Record<string, unknown>;
  grant: string;
  jwks: { keys: { kty: string; crv: string; x: string; kid: string; alg: string; use: string }[] };
  revocations: { revokedMachineIds: string[]; revokedKeyIds: string[]; asOf: string };
  machineProof: { headers: Record<string, string>; method: string; pathAndQuery: string; rawBody: string };
}

const hasArtifact = existsSync(ARTIFACT);

function payloadOf(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString());
}

describe.runIf(hasArtifact)("core-issued artifact (release copy)", () => {
  it("verifies the Core-signed grant against the artifact JWKS", async () => {
    const fx = JSON.parse(readFileSync(ARTIFACT, "utf8")) as CoreIssued;
    for (const f of ["grant", "issuer", "audience", "jwks", "revocations", "accountId", "machineId"] as const) {
      expect(fx[f], `artifact field ${f}`).toBeDefined();
    }
    const unverified = payloadOf(fx.grant);
    const nowSec = (unverified["iat"] as number) + 60; // inside the artifact TTL
    const verify = createGrantVerifier(
      { jwksUrl: "https://core.invalid/jwks", expectedIss: fx.issuer, expectedAud: fx.audience, maxTtlSec: 300 },
      stubFetch(fx.jwks),
    );
    const g = await verify(fx.grant, nowSec);
    // Claim names per Core docs/contracts.md §4 (actual JWT, not the
    // double-nested `expected.cnf` quirk noted above).
    expect(g.claims.v).toBe(1);
    expect(g.claims.iss).toBe(fx.issuer);
    expect(g.claims.aud).toBe(fx.audience);
    expect(g.claims.sub).toBe(fx.accountId);
    expect(g.claims.mid).toBe(fx.machineId);
    expect(g.claims.role).toBe((fx.expected as Record<string, unknown>)["role"]);
    expect([...g.scopes].sort()).toEqual(
      ((fx.expected as Record<string, unknown>)["scope"] as string[]).slice().sort(),
    );
    expect(g.claims.cnf.jwk.kty).toBe("OKP");
    expect(g.claims.cnf.jwk.crv).toBe("Ed25519");
    expect(g.cnfPk.length).toBe(32);
    expect(g.kid).toBe(fx.jwks.keys[0]?.kid);
  });

  it("artifact revocation payload parses to enforcement inputs", () => {
    const fx = JSON.parse(readFileSync(ARTIFACT, "utf8")) as CoreIssued;
    const list = parseRevocationsResponse(fx.revocations);
    expect(list).toEqual({ machines: fx.revocations.revokedMachineIds, keys: fx.revocations.revokedKeyIds });
    expect(typeof fx.revocations.asOf).toBe("string");
  });

  it("artifact machine-proof documents the §3 format (informational)", () => {
    const fx = JSON.parse(readFileSync(ARTIFACT, "utf8")) as CoreIssued;
    expect(typeof fx.machineProof.method).toBe("string");
    expect(fx.machineProof.pathAndQuery.startsWith("/v1/")).toBe(true);
    const lower: Record<string, string> = {};
    for (const [k, v] of Object.entries(fx.machineProof.headers)) lower[k.toLowerCase()] = v;
    for (const h of ["x-ast-machine", "x-ast-timestamp", "x-ast-nonce", "authorization"]) {
      expect(lower[h], `proof header ${h}`).toBeDefined();
    }
    expect(lower["authorization"]?.startsWith("AST-Machine ")).toBe(true);
    expect(lower["x-ast-machine"]).toBe(fx.machineId);
  });

  it("artifact grant admits cleanly, and is rejected once its machine is listed", async () => {
    const fx = JSON.parse(readFileSync(ARTIFACT, "utf8")) as CoreIssued;
    const verify = createGrantVerifier(
      { jwksUrl: "https://core.invalid/jwks", expectedIss: fx.issuer, expectedAud: fx.audience, maxTtlSec: 300 },
      stubFetch(fx.jwks),
    );
    const nowSec = (payloadOf(fx.grant)["iat"] as number) + 60;
    const g = await verify(fx.grant, nowSec);

    // Clean room (artifact revocations are empty): hello reaches challenge.
    const h1 = makeRoom(verify, g.claims.sub, g.claims.mid, nowSec * 1000);
    const s1 = fakeSocket();
    h1.room.onConnect("c", s1);
    await send(h1.room, "c", { v: 1, type: "hello", grant: fx.grant });
    expect(s1.closed).toBeNull();

    // Separate room instance (fresh jti cache) with the artifact machine
    // listed: the SAME real bytes are rejected at hello.
    const h2 = makeRoom(verify, g.claims.sub, g.claims.mid, nowSec * 1000);
    h2.room.setRevocations([g.claims.mid], []);
    const s2 = fakeSocket();
    h2.room.onConnect("c", s2);
    await send(h2.room, "c", { v: 1, type: "hello", grant: fx.grant });
    expect(s2.closed?.code).toBe(4002);
  });
});

describe.skipIf(hasArtifact)("core-issued artifact (release copy)", () => {
  it("WAITING on Core: core/fixtures/v1/core-issued.json absent", () => {
    console.log("skip: run scripts/copy-core-fixture.mjs once Core emits the artifact");
  });
});
