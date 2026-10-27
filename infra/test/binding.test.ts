// Binding identity + runtime-intact checks (offline, no cloud).
// Imports the single-source constants from ../config.ts and asserts the
// composition root + existing runtime files agree with them. No mirrored
// literals: every expected value comes from the import.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import {
  COMPATIBILITY_DATE,
  DO_BINDING_NAME,
  DO_CLASS_NAME,
  WORKER_MAIN,
} from "../config.ts";

const infraDir = dirname(fileURLToPath(import.meta.url));
const rootDir = join(infraDir, "..");
const relayDir = join(rootDir, "..");

const stackSrc = readFileSync(join(rootDir, "alchemy.run.ts"), "utf8");
// Code only (strip // line comments): boundary assertions must not trip on
// the doc comments that NAME the forbidden resources to forbid them.
const stackCode = stackSrc
  .split("\n")
  .filter((line) => !line.trimStart().startsWith("//"))
  .join("\n");
const wrangler = readFileSync(join(relayDir, "wrangler.toml"), "utf8");
const runtime = readFileSync(join(relayDir, "src", "index.ts"), "utf8");

describe("composition root declares the stable binding", () => {
  test("Worker entry is the existing raw module (not rewritten)", () => {
    expect(stackCode).toContain("WORKER_MAIN");
    expect(stackCode).toMatch(/main:\s*WORKER_MAIN/);
    expect(stackCode).not.toMatch(/class\s+MachineRoom/);
    expect(stackCode).not.toMatch(/RoomState/);
  });

  test("DO binding name -> class name pair is declared (via single-source constants)", () => {
    // alchemy.run.ts references the imported constants — the VALUES are
    // asserted in config.test.ts, so no literals are mirrored here.
    expect(stackCode).toContain("[DO_BINDING_NAME]");
    expect(stackCode).toContain("DO_CLASS_NAME");
    expect(stackCode).toMatch(/Cloudflare\.DurableObject\(DO_CLASS_NAME\)/);
    expect(stackCode).toMatch(/DurableObject\(/);
  });

  test("workers.dev disabled, custom domain from relay origin, no assets", () => {
    expect(stackCode).toMatch(/workersDev:\s*false/);
    expect(stackCode).toMatch(/domain/);
    expect(stackCode).not.toMatch(/assets\s*:/);
  });

  test("no Core-owned resources (no R2/D1/Hyperdrive/Queues, no Core imports)", () => {
    expect(stackCode).not.toMatch(/Cloudflare\.(R2|D1|Hyperdrive|Queues)/);
    expect(stackCode).not.toMatch(/R2\.Bucket|D1\.Database/);
    expect(stackCode).not.toMatch(/from ["']\.\.\/\.\.\/core/);
    expect(stackCode).not.toMatch(/from ["']@artisanstreet\/core/);
  });

  test("default account-level Cloudflare state (distinct stack isolates)", () => {
    expect(stackCode).toMatch(/Cloudflare\.state\(\)/);
    expect(stackCode).not.toMatch(/state\(\s*\{\s*name/);
  });
});

describe("parity with existing local/test files (unchanged runtime)", () => {
  test("wrangler.toml keeps the same binding pair for wrangler dev/miniflare", () => {
    expect(wrangler).toContain(`name = "${DO_BINDING_NAME}"`);
    expect(wrangler).toContain(`class_name = "${DO_CLASS_NAME}"`);
    expect(wrangler).toContain(`new_sqlite_classes = ["${DO_CLASS_NAME}"]`);
    expect(wrangler).toContain(COMPATIBILITY_DATE);
  });

  test("raw Worker still exports default handler + MachineRoom DO", () => {
    expect(runtime).toMatch(/export default/);
    expect(runtime).toContain(`export class ${DO_CLASS_NAME}`);
    expect(runtime).toMatch(/webSocketMessage|webSocketClose/);
  });

  test("entry file resolves from infra/", () => {
    expect(WORKER_MAIN).toBe("../src/index.ts");
  });
});
