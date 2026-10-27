import { defineConfig } from "vitest/config";
import reylo from "reylo/vite";

// The reylo plugin resolves Core's `.sql` imports for the cross-repo
// smoke harness (relay/integration), which drives Core's real Hono app +
// PGlite in-process. Relay production code has no `.sql` files and no
// runtime dependency on Core or Reylo.

export default defineConfig({
  plugins: [reylo()],
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts", "integration/**/*.test.ts"],
    testTimeout: 30_000,
  },
});
