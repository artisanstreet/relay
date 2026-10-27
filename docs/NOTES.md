# Relay implementation notes (for collaborators)

## What this repo is

Independent Cloudflare Workers + Durable Objects service. Routes opaque
E2E bytes between account clients (Editors) and Forge machines. No
dependency on sibling repos at runtime (Core/Editor are separate).
Owns: connection admission (JWT + PoP), per-machine routing, presence,
ack-window flow control, Core revocation polling. Does NOT own:
identity, grants, fingerprints (Core), threads/runs/files (Forge).

## Frozen decisions (2026-10-26/27)

- Grants: real JWT (EdDSA + kid) + JWKS, reconciled to Core
  docs/contracts.md via root: `sub`=account, `mid`=target machine on ALL
  grants, `aud`=`ast-relay`, required `nbf`, TTL ≤300s, scopes
  `relay:connect`/`forge:execute`/`machine:sync`. In-band hello auth
  (no credentials in URL/headers). PoP challenge-response binds bearer
  to holder. Single-use jti within TTL.
- Core v1 alignment (2026-10-27, authoritative Core §4): NO `rev` claim
  (accepted-if-present, never enforced), NO admin push (removed; unknown
  scopes rejected). Revocation = short expiry (per-frame + sweep) +
  polled `GET /v1/grants/revocations` emitting Core-exact camelCase
  `{revokedMachineIds, revokedKeyIds, asOf}` (test/core-contract.test.ts
  pins the shape; unknown fields ignored). Env: `CORE_REVOCATIONS_URL`
  (else derived), `REVOCATION_POLL_MS` default 60s.
- E2E: `Noise_XX_25519_ChaChaPoly_BLAKE2b` via pinned
  `noise-handshake@4.2.0` (JS) + `snow` 0.10 (Rust). NO custom
  handshake (an early dual-DH sketch was rejected on review). Fresh
  X25519 statics per channel; identity = Ed25519 binding signatures over
  the transcript hash, keyed to JWT `cnf` (initiator JWT in-band,
  responder = enrolled machine key). Sequential nonces, fail-closed,
  enforced rotation (2^20 msgs / 24h). No PCS claimed.
- Transport: ordered WS, reconnect = new channel. Explicit cumulative
  ack windows (64 frames / 1 MiB per channel per direction); drops are
  loss (kill E2E sessions fail-closed). No `bufferedAmount` (does not
  exist on server WS). Max 64 clients / 64 channels per room.
- DO: hibernation-safe via snapshot/restore (no JWTs/challenges persist);
  alarms ONLY on deadlines (idle rooms sleep); expiry enforced per-frame
  so missed alarms never extend grants. Presence endpoint requires a
  same-room bearer grant.

## Verified (actually run, 2026-10-27)

- `tsc --noEmit` clean (TS 7.1 beta, Effect 3.22.4 aligned with Core).
- 80+ vitest tests: contracts strictness, JWT rejections, room/adversarial/
  restore/integration (FakeWS + real grants + real Noise through RoomState),
  byte-frozen fixtures (`contracts/fixtures/noise-xx.json`).
- LIVE snow interop green: JS initiator <-> real `snow` 0.10 responder,
  handshake-hash equality + both transport directions + tamper negative
  (test/noise-interop.test.ts, needs cargo + network for first build).
- Miniflare (workerd) green: real WS admission/routing, presence auth
  (401/403), cross-room 4403, expiry close, alarm-driven revocation sweep
  from stub Core endpoint, backpressure bound.
- esbuild browser-platform bundle of the E2E path built AND executed
  (handshake + transport OK). Artifact not committed.

## Assumptions for Core to confirm (do NOT code against alternatives silently)

1. Revocation endpoint URL (field names CONFIRMED camelCase per Core §4
   + src/services/grants.ts; URL derivable from iss — confirm).
2. Core-issued artifact requested: `core/fixtures/v1/core-issued.json`
   ({origin, iss, aud, grantJwt, jwks, revocations, nowSec}). On arrival:
   `node --experimental-strip-types scripts/copy-core-fixture.ts` (byte-exact, no hand edits) then
   `test/core-issued.test.ts` verifies the real bytes. The shape mirror
   (`contracts/fixtures/core-v1.json`) is NOT a stand-in.
2. `iss`, JWKS URL, `aud` (`ast-relay` default).
3. Machine record carries enrolled Ed25519 key for Editors to verify
   Forge binding signatures (existing concept, field name TBD).
4. `rev` absent from real tokens (we ignore it if present).
