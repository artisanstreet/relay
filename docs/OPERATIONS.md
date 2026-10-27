# Relay operations

## Deploy (Alchemy is the production source of truth)

Production deploys run from `infra/` (Alchemy v2, isolated package — see
`infra/README.md`). Nothing below has been deployed by the infra task; all
cloud commands require an authorized operator.

1. Cloudflare account + Alchemy profile (`alchemy profile edit --add Cloudflare`)
   or CI env. No secrets in repo (deploy inputs are two public https origins).
2. Public inputs via `infra/.env` (see `infra/.env.example`; stage from CLI):
   - `AST_CORE_ORIGIN` — exact Core origin. Derives `CORE_JWKS_URL`
     (`${AST_CORE_ORIGIN}/.well-known/jwks.json`), `CORE_ISS`
     (`${AST_CORE_ORIGIN}`), `CORE_REVOCATIONS_URL`
     (`${AST_CORE_ORIGIN}/v1/grants/revocations`), `RELAY_PORTAL_ORIGIN`
     (`${AST_CORE_ORIGIN}`). All validated exact-https, fail closed.
   - `AST_RELAY_ORIGIN` — exact Relay origin. Its hostname becomes the
     Worker's custom `domain` (zone must pre-exist); `workersDev: false`.
3. Fixed vars (exact): `RELAY_AUD=ast-relay`, `GRANT_MAX_TTL_S=300`,
   `REVOCATION_POLL_MS=60000` (min 1000).
4. `cd infra && npm ci && npm run check` (offline gate: typecheck + tests +
   bundle — must be green; touches no cloud), then
   `alchemy deploy --stage <prod|staging|pr-N> [--profile <name>]`.
   First-ever run bootstraps the account state store (cloud mutation — do it
   once explicitly via `npm run state:bootstrap`; CI fails loudly if missing).
   Each stage gets an isolated Worker script + isolated DO state. Durable
   Object `MachineRoom` deploys via the declarative `exports` map (SQLite,
   one-way — cannot revert to the legacy `migrations` flow; a removed class
   stops the deploy instead of deleting data). No Hyperdrive/PostgreSQL
   binding: Relay holds no relational state by design (Core owns PG).

`wrangler.toml` is retained ONLY for local/test (`wrangler dev`, miniflare
harness parity, `npm run deploy:plan` dry-run). Never `wrangler deploy` for
releases — it is not a deployment path and must not gain competing docs.

## Runtime behavior

- One DO instance per `{account}/{machine}` (`idFromName`). Idle rooms
  set no alarms (no cost). Alarms fire only on: hello/challenge
  deadlines, ping/pong checks while members exist, grant expiries,
  revocation poll boundary (only with members).
- Storage per room: small snapshot (membership, channels, seq/ack
  high-waters, revocation lists, used jtis). No JWTs, no challenge
  nonces, no payload bytes — ever.
- Logs contain only failure CLASSES (`bad-grant`, `bad-binding`, …),
  close codes, and counts. Tokens, keys, and payloads are never logged
  (there is nothing to log: the room cannot see them).

## Runbooks

- Core key rotation: publish new `kid` in JWKS, keep old during grace;
  Relay caches JWKS 5 min and accepts any cached key id. No restart.
- Revoking a machine/key: add to Core `/v1/grants/revocations`; Relay
  sweeps within poll + alarm (≤ ~90s default). Short grant TTL bounds
  the tail regardless.
- Incident (abuse): revoke at Core (source of truth); rooms sweep
  automatically. No Relay-side kill switch in v1 (documented gap).
- DO storage growth: bounded by caps (64 clients/channels/room, 10k
  revocation entries, jtis expire with grants). No manual cleanup.

## Local verification

- `npm install && npm run typecheck && npm test` (needs network once
  for the snow-peer cargo build; skips cleanly without cargo).
- `UPDATE_FIXTURES=1 npm test -- test/vectors.test.ts` to re-freeze
  vectors after dependency bumps (review the diff!).
- `npm run deploy:plan` for the Workers dry-run (local only, not a release).
- `npm run infra:check` for the infra offline gate (typecheck + config tests
  + raw-Worker bundle intact). `npm run infra:plan` / `infra:deploy` are
  real cloud commands — see `infra/README.md`, never run casually.
