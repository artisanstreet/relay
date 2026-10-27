// Artisan Street Relay — Alchemy v2 infrastructure (production source of truth).
//
// Async-Worker pattern (official docs: cloudflare/compute/workers#async-workers):
// the EXISTING raw module ../src/index.ts (default fetch handler + named
// `MachineRoom` export) is bundled intact via `main`. No runtime rewrite to
// Effect, no Alchemy runtime classes in the Worker. Hibernation support lives
// entirely in the existing code (snapshot/restore + alarms); this file only
// declares the deploy-time binding.
//
// DO management (beta>=82): Cloudflare's declarative `exports` map. New
// classes are SQLite-backed; observed namespaces are preserved; a class no
// longer exported STOPS the deploy instead of deleting data. One-way: once a
// script deploys with `exports`, it cannot go back to the legacy `migrations`
// flow. See infra/README.md (safety/migration).
//
// State: default account-level Cloudflare state store (`Cloudflare.state()`
// with no `name`). Core uses the same backend with a distinct stack name;
// isolation is (stack, stage). NOTE: the first plan/dev/deploy against this
// backend BOOTSTRAPS account resources (state-store Worker + secrets) — a
// cloud mutation. Never run plan/dev/deploy casually here; see README.
// CI=true fails on a missing store instead: run `npm run state:bootstrap` once.

import * as Alchemy from "alchemy";
import { Stack } from "alchemy/Stack";
import * as Cloudflare from "@alchemy.run/cloudflare";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import {
  COMPATIBILITY_DATE,
  CORE_ORIGIN_VAR,
  DO_BINDING_NAME,
  DO_CLASS_NAME,
  GRANT_MAX_TTL_S,
  RELAY_AUD,
  RELAY_ORIGIN_VAR,
  REVOCATION_POLL_MS,
  STACK_NAME,
  WORKER_LOGICAL_ID,
  WORKER_MAIN,
  deriveRelayVars,
  getHostname,
  parseDeployOrigins,
} from "./config.ts";

export default Alchemy.Stack(
  STACK_NAME,
  { providers: Cloudflare.providers(), state: Cloudflare.state() },
  Effect.gen(function* () {
    const stack = yield* Stack;
    // Fail closed: missing vars are ConfigErrors; malformed or colliding
    // values throw inside the effect (deploy dies with var name + reason).
    // The pair is validated TOGETHER: identical Core/Relay origins are
    // rejected (two custom-domain Workers cannot own the same host).
    const [coreRaw, relayRaw] = yield* Effect.all([
      Config.String(CORE_ORIGIN_VAR),
      Config.String(RELAY_ORIGIN_VAR),
    ]);
    const { coreOrigin, relayOrigin } = parseDeployOrigins(coreRaw, relayRaw);

    const vars = deriveRelayVars(coreOrigin);
    const domain = getHostname(relayOrigin);

    // Relay owns compute ONLY: one Worker + its hosted DO namespace. No
    // R2/D1/Hyperdrive/Queues, no Core imports, no shared DB. All env values
    // below are public non-secret config (plain_text); there are no secrets.
    const worker = yield* Cloudflare.Worker(WORKER_LOGICAL_ID, {
      main: WORKER_MAIN,
      compatibility: { date: COMPATIBILITY_DATE },
      workersDev: false,
      domain,
      env: {
        [DO_BINDING_NAME]: Cloudflare.DurableObject(DO_CLASS_NAME),
        CORE_JWKS_URL: vars.CORE_JWKS_URL,
        CORE_ISS: vars.CORE_ISS,
        CORE_REVOCATIONS_URL: vars.CORE_REVOCATIONS_URL,
        RELAY_AUD,
        GRANT_MAX_TTL_S,
        REVOCATION_POLL_MS,
        RELAY_PORTAL_ORIGIN: vars.RELAY_PORTAL_ORIGIN,
      },
    });

    return {
      url: worker.url,
      urls: worker.urls,
      workerName: worker.workerName,
      domain,
      stage: stack.stage,
      stack: stack.name,
      coreOrigin,
      relayOrigin,
      doBinding: DO_BINDING_NAME,
      doClass: DO_CLASS_NAME,
    };
  }),
);
