# Relay infra (Alchemy v2) — production source of truth

Independent IaC package for the Relay Worker + `MachineRoom` Durable Object.
Async-Worker pattern: the existing raw module `../src/index.ts` is bundled
intact via `main` — no runtime rewrite, no Effect in the Worker, hibernation
stays in the existing code. See `BOUNDARIES.md` before changing anything.

## Evidence (verified 2026-10-27, UTC)

- npm registry: `alchemy` `latest = 2.0.0-beta.84`, `next = 2.0.0-beta.72`.
- Pins (exact): `alchemy@2.0.0-beta.84`,
  `@alchemy.run/cloudflare@2.0.0-beta.84`, `effect@4.0.6`,
  `@effect/platform-node@4.0.6` (Alchemy peer `effect@^4.0.5`).
  Runtime stays on Effect 3 (`relay/package.json` untouched).
- Official docs (`https://alchemy.run/llms.txt`, fetched 2026-10-27):
  - `cloudflare/compute/workers#async-workers` — plain-module Worker via
    `main` + `env`, typed by `Cloudflare.InferEnv`. No v1 APIs used.
  - `cloudflare/compute/durable-objects` — `env: { MACHINE_ROOM:
    Cloudflare.DurableObject("MachineRoom") }` emits
    `{ type: durable_object_namespace, name: "MACHINE_ROOM",
    className: "MachineRoom" }`; deploys use the declarative `exports` map
    (beta>=82, one-way — no return to the legacy `migrations` flow; a class
    no longer exported STOPS the deploy instead of deleting data; new
    classes are SQLite-backed).
  - `state-store` — `Cloudflare.state()` (default account store
    `alchemy-state-store`) is the recommended backend for Cloudflare-only
    infra. FIRST `plan`/`dev`/`deploy` against it BOOTSTRAPS account
    resources (state Worker + Secrets Store secrets) — a cloud mutation.
    In CI (`CI=true`) a missing store FAILS instead of bootstrapping.
  - `environments/stages` — stage from `--stage` / `$ALCHEMY_STAGE`
    (default `live_$USER` for deploy, `dev_$USER` for dev); names must match
    `[a-z0-9][-_a-z0-9]*`; each stage gets isolated state + physical names.
  - `environments/secrets` + `cloudflare/security/secrets-env` — async
    Workers bind via `env`; literal strings bind as `plain_text`. This stack
    binds ONLY public non-secret config (origins/URLs); there are no secrets.
- Installed-type checks (this package, offline):
  - `Worker` props include `main`, `compatibility.date`, `workersDev`
    (`false` disables the `workers.dev` URL), `domain` (string shorthand for
    `{ name }`, zone inferred, must pre-exist), `env` (DO binding +
    literals). No `assets` (Relay is API-only; Core's `runWorkerFirst:true`
    is a Core concern, not set here).
  - `WorkerBundle.build` (`@alchemy.run/cloudflare/Workers/Sources/Rolldown`,
    via the package `./*` wildcard) needs only Effect FileSystem+Path
    (`@effect/platform-node` `NodeFileSystem`/`NodePath` layers) and returns
    in-memory `{ files, hash }` — invocable offline with zero cloud calls.
    `npm run bundle:check` uses it (the deploy-exact Cloudflare rolldown
    plugin set) and asserts by IMPORTING the built entry: `default.fetch`
    plus `MachineRoom` prototype handlers
    (`fetch`/`webSocketMessage`/`webSocketClose`/`webSocketError`/`alarm`).
    For `bundle: false` Workers the deploy-exact collector is instead
    `readPrebuiltWorkerBundle` (`Workers/Sources/Prebuilt`) — not used here
    since Relay bundles from source.
  - Origin validation rejects wildcards (`*`/`%2A` — `new URL` parses them,
    so the check is explicit) and rejects identical Core/Relay origins (two
    custom-domain Workers cannot own one host).
  - CLI (`alchemy/bin/cli.js`) runs under Bun when present, else Node —
    requires Node 22.22.3 / 24.11.1+. This stack pins `engines.node >= 24.11.1`
    (the CLI minimum accurately encoded; host runs 24.18, aligned with Core
    infra); Bun is not on PATH and is NOT required.

## Prerequisites (external, not installed here)

1. Node >= 24.11.1 (host runs 24.18 — the CLI's minimum on the 24 line;
   aligned with Core infra).
   Bun optional — the Alchemy CLI runs directly under Node, no Bun install needed.
2. Cloudflare account + credentials via `pnpm dlx alchemy profile edit --add Cloudflare`
   (OAuth or API token, interactive) or CI env (`CLOUDFLARE_ACCOUNT_ID` plus
   token). Deploy credentials live in the Alchemy profile, never in the repo.
3. The relay zone already exists in the account (the `domain` hostname's zone
   is inferred; Alchemy does not create zones here).
4. `.env` in `infra/` with the two public origins (see `.env.example`).
   Validate exact `https://host[:port]` — no paths, no http.

## Scripts (reproducible; infra/ has its own lockfile)

| Command | What it does | Cloud? |
|---|---|---|
| `pnpm install --frozen-lockfile` (in `infra/`) | reproducible install from `pnpm-lock.yaml` | no (npm registry only) |
| `pnpm run typecheck` | `tsrs --noEmit` on infra only | no |
| `npm test` | vitest: origin validation (exact-https, wildcards, Core/Relay distinctness), var derivation, domain | no |
| `npm run bundle:check` | Alchemy `WorkerBundle` builds `../src/index.ts`, imports the entry, asserts `default.fetch` + `MachineRoom` hibernation handlers | no |
| `npm run check` | typecheck + test + bundle:check (the full offline gate) | no |
| `npm run plan -- --stage <s>` | `alchemy plan` (preview; see warning) | YES — see below |
| `npm run deploy -- --stage <s> [--profile <p>] [--env-file <f>]` | `alchemy deploy` | YES |
| `npm run destroy -- --stage <s>` | `alchemy destroy` (that stage only) | YES |
| `npm run state:bootstrap` | `alchemy state bootstrap --backend cloudflare` (one-time) | YES |

`pnpm run <script> -- <args>` forwards args to the local `alchemy` binary
(`node_modules/.bin`, installed by `pnpm install` — no global install). The only
bare-`alchemy` form used here is `pnpm dlx --no-install alchemy profile ...`
(`--no-install` guarantees the local binary, never a download).

Root conveniences (`relay/package.json`, deps untouched):
`npm run infra:check`, `npm run infra:plan -- --stage <s>`,
`npm run infra:deploy -- --stage <s>` (delegate with `npm --prefix infra`).
The trailing `--` in the wrapper scripts is load-bearing: without it the
inner npm swallows flags (`--stage`, `--help`) instead of forwarding them to
Alchemy — verified via `--help` reaching `alchemy plan`/`deploy` usage.

## Auth / bootstrap / safety (read before any cloud command)

- Stages: `--stage prod` / `--stage staging` / `--stage pr-42`, or
  `$ALCHEMY_STAGE`. Never reuse a stage name across environments. Default
  `live_$USER` keeps personal sandboxes off shared stages. Destroy is
  per-stage (`npm run destroy -- --stage pr-42` touches only that stage).
  Stage names are validated by the CLI (`[a-z0-9][-_a-z0-9]*`).
- Preview stages MUST use stage-specific origins (never prod domains).
  Isolated Worker names and DO state do NOT isolate the custom domain: the
  `domain` hostname is single-owner, so deploying `--stage pr-42` with prod
  `.env` would move the production domain/DNS/cert onto the preview Worker.
  Keep a separate git-ignored env file per non-prod stage and select it with
  `--env-file` (deploy default is `.env`):
  ```sh
  # .env.preview — this stage's OWN pair (never prod hosts)
  AST_CORE_ORIGIN=https://core-pr-42.example.com
  AST_RELAY_ORIGIN=https://relay-pr-42.example.com
  npm run deploy -- --stage pr-42 --env-file .env.preview
  ```
  The stack additionally refuses identical Core/Relay origins outright.
- State: default `Cloudflare.state()` (account Worker
  `alchemy-state-store`). Core uses the same backend with a DIFFERENT stack
  name — isolation is (stack, stage). Do NOT pass a custom `name` here.
- First-run bootstrap: the first `plan`/`dev`/`deploy` with this backend
  DEPLOYS the state-store Worker + Secrets Store secrets if missing. That is
  why this task runs NO plan/dev/deploy: even `plan` initializes state behind
  the scenes. Provision once explicitly (`npm run state:bootstrap`) with an
  authorized identity, then use CI (`CI=true`) so a missing store fails loudly
  instead of silently creating.
- Migration (DO): Alchemy uploads the declarative `exports` map
  (`MachineRoom`, SQLite). The existing Wrangler `migrations v1
  new_sqlite_classes` flow is superseded on first Alchemy deploy — one-way,
  cannot revert. Fresh stages create fresh namespaces (isolated DO state per
  stage by design). Adopting the live Wrangler script (`name:
  "artisan-relay"` + `--adopt`) is possible but has concrete costs: one
  physical name for all stages (no stage isolation — every stage would target
  the same Worker script and live DO namespaces), the script's `exports` map
  permanently moves to the declarative flow, and the pre-existing custom
  domain attachment is taken over by the adopting stage. Default leaves
  `name` unset so each stage gets its own script; only adopt after weighing
  those consequences for the affected stages.
- Domain: `domain` = relay origin hostname; DNS + edge cert managed by
  Cloudflare; zone must pre-exist. `workersDev: false` (no `workers.dev` URL;
  `worker.url` is the custom domain). Useful non-secret outputs: `url`,
  `urls`, `workerName`, `domain`, `stage`, `stack`, `coreOrigin`,
  `relayOrigin`, `doBinding`, `doClass`.
- Secrets: none. All bound values are public origins/URLs (`plain_text`).
  Never inspect or log secret material; deploy-time origins are non-secret
  and safe in outputs. `.env` (real origins) is git-ignored; only
  `.env.example` is committed.
- Wrangler role: `wrangler.toml` is retained ONLY for local/test
  (`wrangler dev`, miniflare harness parity, `deploy:plan` dry-run). It is
  NOT a deployment path — Alchemy is the production source of truth. Do not
  maintain competing deploy docs.

## Deploy (authorized operators only; nothing here was deployed by this task)

```sh
# From a fresh clone, install BOTH packages first: WorkerBundle builds
# ../src/index.ts, which imports the runtime's dependencies (Effect 3,
# jose, …) from the root node_modules — infra's own install is not enough.
npm ci             # repo root: runtime deps for the bundled Worker source
cd infra
npm ci             # infra: Alchemy/Effect 4 deploy tooling
npm run check            # offline gate, must be green
cp .env.example .env     # fill in the two real https origins (prod pair)
pnpm dlx alchemy profile edit --add Cloudflare   # once per machine/profile
npm run state:bootstrap  # once per account (or rely on CI failure signal)
npm run deploy -- --stage prod --profile prod   # origins via .env
```
Previews: separate origins + `--env-file` (see "Preview stages" above) —
never deploy a non-prod stage against the prod `.env`.
