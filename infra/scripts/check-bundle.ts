// Offline bundle gate using Alchemy's EXACT deploy bundler — not an
// approximation.
//
// `WorkerBundle` (@alchemy.run/cloudflare/Workers/Sources/Rolldown, pinned
// 2.0.0-beta.84) builds with the same Cloudflare-flavored rolldown plugin
// set (`@alchemy.run/cloudflare-runtime/rolldown`, same compatibility date
// handling) that `alchemy deploy` uses for this Worker. It needs only Effect
// FileSystem+Path (provided by @effect/platform-node layers here) — no
// provider credentials, no cloud calls: `Bundle.build` shells rolldown
// locally and returns in-memory files.
//
// The gate writes those files to a temp dir, imports the entry, and asserts
// the REAL exports execute: `default.fetch` plus `MachineRoom` with its
// hibernation handlers on the prototype. Substring presence is NOT enough.
//
// For `bundle: false` Workers (prebuilt output, e.g. framework builds) the
// deploy-exact collector is instead `readPrebuiltWorkerBundle`
// (@alchemy.run/cloudflare/Workers/Sources/Prebuilt) — not used here because
// Relay bundles from source via `main`.
//
// Exit non-zero on any failure. Never logs env/secrets (options are the
// public entry path + compat date + stack identity only).

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { WorkerBundle } from "@alchemy.run/cloudflare/Workers/Sources/Rolldown";
import { layer as NodeFileSystemLive } from "@effect/platform-node/NodeFileSystem";
import { layer as NodePathLive } from "@effect/platform-node/NodePath";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import {
  COMPATIBILITY_DATE,
  STACK_NAME,
  WORKER_LOGICAL_ID,
  WORKER_MAIN,
} from "../config.ts";

const here = dirname(fileURLToPath(import.meta.url));
// WORKER_MAIN is infra-relative ("../src/index.ts"); resolve from here.
const main = join(here, "..", WORKER_MAIN);

const InfraLive = Layer.merge(NodeFileSystemLive, NodePathLive);

const program = Effect.gen(function* () {
  const bundle = yield* WorkerBundle;
  return yield* bundle.build({
    id: WORKER_LOGICAL_ID,
    main,
    compatibility: { date: COMPATIBILITY_DATE, flags: [] },
    entry: { kind: "external" },
    // Decoupled from real stages: the bundle depends only on source.
    stack: { name: STACK_NAME, stage: "bundle-check" },
    extraOptions: undefined,
  });
});

const failures: string[] = [];
const check = (label: string, cond: boolean): void => {
  if (!cond) failures.push(label);
};

const dir = mkdtempSync(join(tmpdir(), "relay-infra-bundle-"));
try {
  const output = await Effect.runPromise(program.pipe(Effect.provide(InfraLive)));
  check("bundle has an entry file", output.files.length >= 1);
  check("bundle hash present", output.hash.length > 0);
  const entry = output.files[0];
  check("entry content present", !!entry && entry.content.length > 0);

  if (failures.length === 0) {
    for (const file of output.files) {
      writeFileSync(join(dir, file.path), file.content);
    }
    const mod = (await import(pathToFileURL(join(dir, entry.path)).href)) as Record<
      string,
      unknown
    >;
    const names = Object.keys(mod);
    check("named MachineRoom export", names.includes("MachineRoom"));
    check("default export", names.includes("default"));
    const def = mod["default"] as { fetch?: unknown } | undefined;
    check("default.fetch is a function", typeof def?.fetch === "function");
    check("MachineRoom is a class/function", typeof mod["MachineRoom"] === "function");
    const proto = (mod["MachineRoom"] as { prototype?: Record<string, unknown> } | undefined)
      ?.prototype;
    for (const handler of ["fetch", "webSocketMessage", "webSocketClose", "webSocketError", "alarm"]) {
      check(`MachineRoom.prototype.${handler} is a function`, typeof proto?.[handler] === "function");
    }
  }

  if (failures.length > 0) {
    console.error(`bundle check FAILED:\n${failures.map((f) => ` - ${f}`).join("\n")}`);
    process.exit(1);
  }
  console.log(
    "bundle check OK (Alchemy WorkerBundle): default.fetch + MachineRoom(fetch/message/close/error/alarm) intact",
  );
} catch (err) {
  console.error(`bundle check FAILED: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
