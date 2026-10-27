import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root: string = join(dirname(fileURLToPath(import.meta.url)), "..");

await build({
  entryPoints: [join(root, "src", "index.ts")],
  bundle: true,
  format: "esm",
  platform: "browser",
  conditions: ["workerd", "worker", "browser"],
  outfile: join(root, "dist", "worker.mjs"),
  allowOverwrite: true,
  logLevel: "warning",
});
console.log("built dist/worker.mjs");
