import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root: string = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC: string = join(root, "..", "core", "fixtures", "v1", "core-issued.json");
const DST: string = join(root, "contracts", "fixtures", "core-issued.json");
const META: string = join(root, "contracts", "fixtures", "core-issued.meta.json");

if (!existsSync(SRC)) {
  console.error(`core artifact absent (waiting on Core): ${SRC}`);
  process.exit(2);
}
const bytes: Buffer = readFileSync(SRC);
JSON.parse(bytes.toString("utf8"));
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
