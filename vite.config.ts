import { defineConfig } from "vite-plus";
import reylo from "reylo/vite";

// The reylo plugin resolves Core's `.sql` imports for the cross-repo
// interop harness (tests/integration), which drives Core's real app +
// PGlite in-process. Relay production code has no `.sql` files and no
// runtime dependency on Core or Reylo.

export default defineConfig({
  plugins: [reylo()],
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    testTimeout: 30_000,
  },
});
