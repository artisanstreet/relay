# Relay operations

## Deploy (real remaining external credentials — nothing deployed yet)

1. Cloudflare account + `wrangler login`. No secrets in repo.
2. Required worker vars (fail-closed `relay misconfigured` without them):
   - `CORE_JWKS_URL` — Core JWKS endpoint (no default).
   - `CORE_ISS` — Core issuer string (no default).
3. Optional vars (defaults shown):
   - `RELAY_AUD=ast-relay`, `GRANT_MAX_TTL_S=300`.
   - `CORE_REVOCATIONS_URL` (default `${CORE_ISS}/v1/grants/revocations`).
   - `REVOCATION_POLL_MS=60000` (min 1000).
   - `RELAY_PORTAL_ORIGIN` (unset by default): exact account-portal origin
     (e.g. `https://core.artisanstreet.dev`) permitted cross-origin browser
     access. When set: presence/version answer CORS preflights and reflect
     the origin (`Access-Control-Allow-Origin`, `Vary: Origin`; allow-list
     is `GET` + `Authorization`); WebSocket upgrades carrying a mismatched
     `Origin` are refused pre-upgrade (403), while requests with no `Origin`
     (native clients, curl) always proceed to grant+PoP admission. No
     wildcards, no `Access-Control-Allow-Credentials` ever (auth is Bearer
     grants, never cookies). Format: single `https://host[:port]`, no path.
4. `wrangler deploy` (dry-run verified: `npm run deploy:plan`).
   Durable Object `MachineRoom` migration `v1` creates SQLite storage
   on first use. No Hyperdrive/PostgreSQL binding: Relay holds no
   relational state by design (Core owns PG).

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
- `npm run deploy:plan` for the Workers dry-run.
