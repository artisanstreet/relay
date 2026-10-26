#!/usr/bin/env node
// Release-copy: Core-issued contract artifact -> Relay fixtures, byte-exact.
//
// Source (sibling repo, owned by Core):
//   core/fixtures/v1/core-issued.json
//     { origin, iss, aud, grantJwt, jwks: {keys: [...]},
//       revocations: {revokedMachineIds, revokedKeyIds, asOf} }
// Destination (this repo, committed):
//   contracts/fixtures/core-issued.json   (byte-exact copy)
//   contracts/fixtures/core-issued.meta.json (source hash + copy date)
//
// Rules: no hand edits to the copy — ever. If it fails verification, the
// artifact (or Relay) is wrong; fix the source, re-copy, re-run.
// Exit 2 when the source artifact is absent (test skips cleanly then).
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(root, "..", "core", "fixtures", "v1", "core-issued.json");
const DST = join(root, "contracts", "fixtures", "core-issued.json");
const META = join(root, "contracts", "fixtures", "core-issued.meta.json");

if (!existsSync(SRC)) {
  console.error(`core artifact absent (waiting on Core): ${SRC}`);
  process.exit(2);
}
const bytes = readFileSync(SRC);
JSON.parse(bytes.toString("utf8")); // must be valid JSON
mkdirSync(dirname(DST), { recursive: true });
copyFileSync(SRC, DST);
writeFileSync(
  META,
  JSON.stringify(
    { source: SRC, sha256: createHash("sha256").update(bytes).digest("hex"), copiedAt: new Date().toISOString() },
    null,
    2,
  ) + "\n",
);
console.log(`copied ${SRC} -> ${DST}`);
