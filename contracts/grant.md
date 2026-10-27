# Grant contract v1 (Core → Relay/Forge)

Reconciled with Core docs/contracts.md per root decision 2026-10-26
(Core owns the doc update; this file tracks the agreed shape).

Grants are real JWTs (not a custom token). Signed by Core with Ed25519
(`alg: EdDSA`, `kid` required). Relay verifies via Core JWKS
(`CORE_JWKS_URL`, 5-minute cache). Forge verifies independently with the
same JWKS — Relay's admission never substitutes for Forge authorization.

Authoritative field validation: `src/schema.ts` `GrantClaims`
(Effect Schema, strict: unknown top-level claims rejected at `v:1`).

## Header

| Field | Value |
|---|---|
| `alg` | `EdDSA` (anything else rejected) |
| `kid` | Core key id, non-empty (rotation grace via cached JWKS) |
| `typ` | `JWT` or absent |

## Claims

| Claim | Type | Rule |
|---|---|---|
| `v` | `1` | contract version; new fields require a version bump |
| `iss` | string | must equal Core issuer (`CORE_ISS`) |
| `aud` | string \| string[] | must contain `ast-relay` (or `ast-core` where Core directs) |
| `sub` | id string | account id (owner) |
| `mid` | id string | EXPLICIT target machine on ALL relay grants, Forge and Editor alike |
| `jti` | string | unique per grant; single-use within TTL (replay cache) |
| `iat` | int (sec) | issued-at |
| `nbf` | int (sec) | not-before (required) |
| `exp` | int (sec) | `0 < exp - iat <= GRANT_MAX_TTL_S` (default 300) |
| `role` | `forge` \| `client` | connection role |
| `scope` | string[] | non-empty subset of `relay:connect`, `forge:execute`, `machine:sync` |
| `cnf` | `{jwk:{kty:OKP, crv:Ed25519, x:b64u}}` | proof-of-possession key (RFC 7800 shape). Forge: enrolled machine key. Editor: ephemeral key, automatic per grant. |
| `rev` | int, optional | LEGACY/ignored: Core v1 has no `rev` claim. Accepted when present (Rust also treats it as optional); never enforced. |

Id charset: `/^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/`.

## Scope semantics (settled: pairing = full Forge trust; scopes name
## capabilities, not read-only tiers)

- `relay:connect` — may open a tunnel through Relay. Required on WS.
  Relay enforces this and nothing else about authorization.
- `forge:execute`, `machine:sync` — opaque to Relay; enforced by Forge
  on the application surface (execution allowed for paired account).
(`relay:admin` was removed 2026-10-27: Core v1 has no admin push.
Unknown scope values fail strict claim decode.)

## Verification steps (Relay, in order)

1. `kid` present, `alg == EdDSA`; JWKS fetch (cached) → `jwtVerify`
   with `issuer`, `audience`, clock.
2. Strict claim decode (unknown fields rejected).
3. TTL bound (`<= GRANT_MAX_TTL_S`), `nbf`/`exp` against Relay clock.
4. Room binding: `sub`/`mid` equal the DO room id. This is what prevents
   cross-account and cross-machine routes.
5. Revocation-list check: `mid` not in revoked machines; signing `kid`
   and `cnf` key (raw + SHA-256 fingerprint forms) not in revoked keys;
   `jti` not reused within its TTL.
6. Challenge-response proof of possession of `cnf` (in-band `hello` →
   `challenge` → `authenticate`; never URL/query/header). The JWT alone
   never admits a connection.

## Machine cnf

A Forge grant's `cnf` key MUST match its enrolled machine key (enforced
by Core at issue; Relay binds the presenter via PoP). An Editor grant's
`cnf` is ephemeral; Core publishes it to the target Forge (see
contracts/e2e.md §5) so Forge can verify channel binding.

## Revocation (Core v1 model, authoritative: Core docs/contracts.md §4)

No epochs, no admin push. Short grant expiry (TTL ≤ 300s, enforced
per-frame AND on every sweep — expired grants cannot act even if an
alarm sleep was missed) plus the polled `GET /v1/grants/revocations`
list (machine ids + key ids). Relay polls every 60s (env-overridable)
and sweeps live connections; new hellos check the last-known list
(stale-while-revalidate; documented bound ≤ poll + alarm).
Response reads match Core's exact snake_case names
(`revoked_machine_ids`/`revoked_key_ids`/`as_of`); unknown fields are ignored.
Key matching tries signing `kid`, raw `cnf` key, and its SHA-256
fingerprint.

Pair status returning `account_id` + verified email to an authenticated
Forge (local-approval UX) is Core↔Forge surface, not Relay.
