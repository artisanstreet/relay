import { build } from "vite-plus";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root: string = join(dirname(fileURLToPath(import.meta.url)), "..");

await build({
  root,
  logLevel: "warn",
  build: {
    outDir: join(root, "dist"),
    emptyOutDir: false,
    lib: {
      entry: join(root, "src", "client.ts"),
      formats: ["es"],
      fileName: () => "relay-client.mjs",
    },
  },
});
console.log("built dist/relay-client.mjs");
