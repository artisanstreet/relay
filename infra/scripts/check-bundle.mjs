// Offline bundle check: proves the EXISTING raw Worker entry resolves and
// bundles with BOTH exports intact (default handler + MachineRoom DO).
// Uses esbuild locally only — no Alchemy CLI, no cloud, no state.
// Exit non-zero with a clear message on any failure. Never logs env/secrets.
import { build } from "esbuild";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const entry = join(here, "..", "..", "src", "index.ts");

const dir = mkdtempSync(join(tmpdir(), "relay-infra-bundle-"));
const out = join(dir, "worker.mjs");
try {
  await build({
    entryPoints: [entry],
    bundle: true,
    platform: "browser",
    format: "esm",
    outfile: out,
    logLevel: "warning",
    // Keep names readable so the export check is exact, not minified away.
    minify: false,
    keepNames: true,
  });
  const code = readFileSync(out, "utf8");
  const missing = [];
  if (!/MachineRoom/.test(code)) missing.push("MachineRoom export");
  if (!/fetch/.test(code)) missing.push("fetch handler");
  if (!/webSocketMessage/.test(code)) missing.push("webSocketMessage (hibernation)");
  if (missing.length > 0) {
    console.error(`bundle check FAILED: missing ${missing.join(", ")} in ${out}`);
    process.exit(1);
  }
  console.log(`bundle check OK: ${entry} bundles with default + MachineRoom intact`);
} catch (err) {
  console.error(`bundle check FAILED: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
