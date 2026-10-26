// Real Core artifact verification (release-copy path).
//
// Uses contracts/fixtures/core-issued.json — a BYTE-EXACT copy of
// core/fixtures/v1/core-issued.json made by scripts/copy-core-fixture.mjs.
// No hand edits, no mirrored values: whatever Core emitted is what we
// verify (signature via the artifact JWKS, claim names, revocation
// enforcement in a room built from the artifact's own sub/mid).
//
// Skips cleanly (reported, exit 0) while the sibling artifact is absent.
// This is intentional: the shape-mirror test (core-contract.test.ts) pins
// field names meanwhile, but proves nothing about Core's real bytes.

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
  origin: string;
  iss: string;
  aud: string;
  grantJwt: string;
  jwks: { keys: { kty: string; crv: string; x: string; kid: string; alg: string; use: string }[] };
  revocations: { revokedMachineIds: string[]; revokedKeyIds: string[]; asOf: string };
  nowSec: number;
}

const hasArtifact = existsSync(ARTIFACT);

describe.runIf(hasArtifact)("core-issued artifact (release copy)", () => {
  it("verifies the Core-signed grant against the artifact JWKS", async () => {
    const fx = JSON.parse(readFileSync(ARTIFACT, "utf8")) as CoreIssued;
    for (const f of ["grantJwt", "iss", "aud", "jwks", "revocations", "nowSec"] as const) {
      expect(fx[f], `artifact field ${f}`).toBeDefined();
    }
    const verify = createGrantVerifier(
      { jwksUrl: "https://core.invalid/jwks", expectedIss: fx.iss, expectedAud: fx.aud, maxTtlSec: 300 },
      stubFetch(fx.jwks),
    );
    const g = await verify(fx.grantJwt, fx.nowSec);
    for (const c of ["v", "sub", "mid", "jti", "iat", "nbf", "exp", "role", "scope", "cnf"] as const) {
      expect((g.claims as Record<string, unknown>)[c], `claim ${c}`).toBeDefined();
    }
    expect(typeof g.claims.sub).toBe("string");
    expect(typeof g.claims.mid).toBe("string");
  });

  it("artifact revocation entries drive enforcement in a matching room", async () => {
    const fx = JSON.parse(readFileSync(ARTIFACT, "utf8")) as CoreIssued;
    const verify = createGrantVerifier(
      { jwksUrl: "https://core.invalid/jwks", expectedIss: fx.iss, expectedAud: fx.aud, maxTtlSec: 300 },
      stubFetch(fx.jwks),
    );
    const g = await verify(fx.grantJwt, fx.nowSec);
    const list = parseRevocationsResponse(fx.revocations);
    // Same matching the room performs (kid, raw cnf key, SHA-256 fingerprint).
    const { sha256 } = await import("@noble/hashes/sha2.js");
    const { b64uEncode } = await import("../src/jwt.ts");
    const fpr = [...sha256(g.cnfPk)].map((b) => b.toString(16).padStart(2, "0")).join("");
    const revoked =
      list.machines.includes(g.claims.mid) ||
      list.keys.includes(g.kid) ||
      list.keys.includes(b64uEncode(g.cnfPk)) ||
      list.keys.includes(fpr);
    const h = makeRoom(verify, g.claims.sub, g.claims.mid, fx.nowSec * 1000);
    h.room.setRevocations(list.machines, list.keys);
    const s = fakeSocket();
    h.room.onConnect("c", s);
    // Single hello: consumes the artifact jti one way or the other.
    await send(h.room, "c", { v: 1, type: "hello", grant: fx.grantJwt });
    if (revoked) {
      expect(s.closed?.code).toBe(4002);
    } else {
      expect(s.closed).toBeNull();
    }
  });
});

describe.skipIf(hasArtifact)("core-issued artifact (release copy)", () => {
  it("WAITING on Core: core/fixtures/v1/core-issued.json absent", () => {
    console.log("skip: run scripts/copy-core-fixture.mjs once Core emits the artifact");
  });
});
