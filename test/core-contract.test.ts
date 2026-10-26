// Cross-repo contract fixture: Core v1 grant + JWKS + revocations JSON in
// Core's EXACT wire shapes (Core docs/contracts.md §4,
// src/services/grants.ts): camelCase revokedMachineIds/revokedKeyIds/asOf,
// standard JWT claims + JWKS.
//
// Provenance (honest): Relay-authored shape mirror, signed by a TEST key.
// NOT Core-signed. When Core publishes real artifacts, replace this file's
// values (same field names) — these tests will then verify the real thing.
// Regenerate with UPDATE_CORE_FIXTURE=1 (byte-stable: fixed key/times).

import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createGrantVerifier } from "../src/jwt.ts";
import { parseRevocationsResponse } from "../src/revocations.ts";
import { RoomState } from "../src/room.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { mintGrant, stubFetch, testCoreKey, TEST_KID, makeRoom, send, fakeSocket } from "./helpers.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_PATH = join(root, "contracts", "fixtures", "core-v1.json");

const CORE = testCoreKey(0x1d);
const CNF_SK = hexToBytes("ab".repeat(32));
const NOW_SEC = 2_000_000_000;
const ISS = "https://ast.example.invalid";
const AUD = "ast-relay";
// Account id in Core's documented shape (acct_ + ULID; canonical spec
// example value — recognizable as non-production). Machine id format is
// NOT yet confirmed with Core, so it stays an explicitly fake value that
// still satisfies the relay charset (never presented as Core-shaped).
const ACCT = "acct_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const MACHINE = "fixture-forge";

interface CoreFixture {
  origin: string;
  standIn: false;
  requiresCoreArtifact: string;
  schemaNotes: string;
  grantJwt: string;
  jwks: { keys: { kty: string; crv: string; x: string; kid: string; alg: string; use: string }[] };
  revocations: {
    revokedMachineIds: string[];
    revokedKeyIds: string[];
    asOf: string;
    // unknown future field proves forward-compatible reads:
    futureField: string;
  };
  expect: { sub: string; mid: string; role: string; scope: string[]; nowSec: number };
}

async function buildFixture(): Promise<CoreFixture> {
  const cnfPk = ed25519.getPublicKey(CNF_SK);
  const { jwt } = await mintGrant(CORE, {
    iss: ISS,
    account: ACCT,
    machine: MACHINE,
    role: "client",
    scope: ["relay:connect"],
    cnfSk: CNF_SK,
    iat: NOW_SEC,
    nbf: NOW_SEC,
    exp: NOW_SEC + 120,
    jti: "core-fixture-001",
  });
  return {
    origin: "RELAY-AUTHORED SHAPE MIRROR ONLY — not a Core artifact and not a stand-in for one. Field names mirror Core docs/contracts.md §4; signatures are test-key; ids are documented placeholders (see schemaNotes). Do not compare byte outputs with Core-issued bytes.",
    standIn: false,
    requiresCoreArtifact: "core/fixtures/v1/core-issued.json (sibling repo; absent)",
    schemaNotes: "sub uses Core acct_ULID shape (spec example ULID); mid format unconfirmed — explicit placeholder; rev omitted per Core v1; revocation practitioner: exact camelCase names",
    grantJwt: jwt,
    jwks: {
      keys: [
        {
          kty: "OKP",
          crv: "Ed25519",
          x: Buffer.from(CORE.pk).toString("base64url"),
          kid: TEST_KID,
          alg: "EdDSA",
          use: "sig",
        },
      ],
    },
    revocations: {
      revokedMachineIds: [MACHINE],
      revokedKeyIds: [],
      asOf: new Date(NOW_SEC * 1000).toISOString(),
      futureField: "must-be-ignored",
    },
    expect: { sub: ACCT, mid: MACHINE, role: "client", scope: ["relay:connect"], nowSec: NOW_SEC },
  };
}

describe("core v1 contract fixture", () => {
  it("matches committed bytes (or regenerates with UPDATE_CORE_FIXTURE=1)", async () => {
    const built = await buildFixture();
    if (process.env["UPDATE_CORE_FIXTURE"] === "1") {
      mkdirSync(dirname(FIXTURE_PATH), { recursive: true });
      writeFileSync(FIXTURE_PATH, JSON.stringify(built, null, 2) + "\n");
    }
    const committed = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as CoreFixture;
    expect(built).toEqual(committed);
  });

  it("grant verifies against the fixture JWKS with Core claim names", async () => {
    const fx = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as CoreFixture;
    const verify = createGrantVerifier(
      { jwksUrl: "https://core.invalid/jwks", expectedIss: ISS, expectedAud: AUD, maxTtlSec: 300 },
      stubFetch(fx.jwks),
    );
    const g = await verify(fx.grantJwt, fx.expect.nowSec);
    expect(g.claims.sub).toBe(fx.expect.sub);
    expect(g.claims.mid).toBe(fx.expect.mid);
    expect(g.claims.role).toBe(fx.expect.role);
    expect([...g.scopes]).toEqual(fx.expect.scope);
  });

  it("fixture revocation list parses to enforcement inputs (unknown fields ignored)", async () => {
    const fx = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as CoreFixture;
    const list = parseRevocationsResponse(fx.revocations);
    expect(list.machines).toEqual([fx.expect.mid]);
    expect(list.keys).toEqual([]);
  });

  it("fixture machine revocation rejects hello in a matching room", async () => {
    const fx = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as CoreFixture;
    const verify = createGrantVerifier(
      { jwksUrl: "https://core.invalid/jwks", expectedIss: ISS, expectedAud: AUD, maxTtlSec: 300 },
      stubFetch(fx.jwks),
    );
    // Room clock must fall inside the fixture grant window.
    const h = makeRoom(verify, fx.expect.sub, fx.expect.mid, fx.expect.nowSec * 1000);
    const list = parseRevocationsResponse(fx.revocations);
    h.room.setRevocations(list.machines, list.keys);
    const s = fakeSocket();
    h.room.onConnect("c", s);
    await send(h.room, "c", { v: 1, type: "hello", grant: fx.grantJwt });
    expect(s.closed?.code).toBe(4002);
  });
});
