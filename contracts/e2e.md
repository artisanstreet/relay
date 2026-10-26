# Inner E2E channel v1 (exact contract for JS + Rust)

Status: decided by Relay owner. JS-side verified against `noise-handshake`
wire behavior (message sizes 32/96/64, handshake-hash equality, tamper
rejection — see test/channel.test.ts). Live JS<->`snow` exchange is
PLANNED (see `interop/`); until it runs green, the `snow` side is unverified.
Route to Rust peer via root — Rust implements the same with `snow`.

Outer WSS is Cloudflare-terminated transport, NOT end-to-end. Everything
confidential travels below. Relay routes opaque bodies only.

## 1. Protocol

`Noise_XX_25519_ChaChaPoly_BLAKE2b` (Noise Protocol Framework rev 34),
keyed as follows. JS: `noise-handshake@4.2.0` (pinned; sodium backend —
`sodium-native` on Node, `sodium-javascript` WASM in browsers (esbuild
browser-platform bundle built AND executed successfully on 2026-10-26:
handshake + transport round-trip OK; bundle artifact not committed).
Rust: `snow` (same protocol name string).

- Pattern XX, empty handshake payloads. Roles: the channel OPENER is
  always Noise initiator. Relay topology: opener = client (Editor);
  Forge is responder. (Future forge-opened channels: opener initiates.)
- Prologue (both sides, must be byte-identical or the handshake fails):
  `prologue = "ast-relay-noise-v1" || 0x00 || account || 0x00 || machine
  || 0x00 || channel` (UTF-8, single 0x00 separators).
- Static keys: raw 32-byte X25519. Fingerprints distributed via the Core
  account record (proposed format §5). Recipient aborts unless the
  received static equals the expected fingerprint (constant-time compare,
  no TOFU).
- Transport: standard sequential Noise nonces per direction (no explicit
  nonces; the Relay path is one ordered WebSocket per direction and
  reconnects always start a new channel). Violations are fail-closed:
  first AEAD failure, seq gap, kind violation, or confirm failure
  destroys the session. No reorder windows (nothing to reorder).
- Nonce layout below 2^32 messages is `0x00000000 || LE64(n)` on both
  sides; rotation is enforced at 2^20 messages so the layouts never
  diverge in practice.
- One Noise transport message ≤ 65535 bytes; app plaintext per frame ≤
  60_000 bytes (chunk above).

## 2. Mutual key confirmation + identity binding (application frames)

No static-key registry exists and none is needed. Noise static keys are
fresh per channel (pure DH randomness). Peer authentication comes from
Ed25519 binding signatures over the negotiated transcript, keyed to Core
JWT identities:

Transport plaintext framing (all multi-byte integers big-endian):

```text
frame = "AR1" || 0x01 || ch_len(u8) || channel || kind(u8) || body
kind: 0x00 = confirm, 0x01 = data
```

After Split, before any data:

1. Initiator (Editor) sends confirm with
   `body = handshake_hash (64B) || jwt_len (u16be) || grant_jwt || bind_sig_init (64B)`.
   `bind_sig_init = Ed25519(cnf_sk, "ast-relay-bind-v1" || 0x01 || handshake_hash)`
   using the grant's `cnf` key.
2. Responder (Forge) checks hash equality, then verifies the grant JWT
   ITSELF (signature via Core JWKS, `iss`/`aud`, `sub` == account,
   `mid` == machine, `exp`/`nbf` current, scope includes
   `relay:connect`), extracts ONLY the verified `cnf` key, and verifies
   `bind_sig_init` with it. Then sends confirm with
   `body = handshake_hash || bind_sig_resp`, where
   `bind_sig_resp = Ed25519(enrolled_cnf_sk, "ast-relay-bind-v1" || 0x02 || handshake_hash)`.
3. Initiator checks hash equality and verifies `bind_sig_resp` with the
   Forge's enrolled Ed25519 key from the authenticated Core machine
   record. Both sides open only after sent + received confirmation.

The handshake hash already covers prologue (account/machine/channel)
and every handshake byte (both statics, both ephemerals), so signing it
binds the exact negotiated transcript; the role byte (0x01/0x02)
separates directions. `cnf` material forwarded by Relay is NEVER trusted
directly. A MITM substituting handshake keys fails the hash comparison;
a stolen JWT without the `cnf` secret cannot produce the binding
signature. Confirm frames are single-shot per direction (a second
CONFIRM destroys the session).

## 3. Data phase

Ordering and replay protection come from the sequential Noise transport
nonces (a lost, reordered, or replayed message fails AEAD and destroys the
session — fail-closed). No app-level sequence space exists by design.
- `channel` in every frame must equal the session channel.
- DATA frames before confirmation complete are rejected (fail-closed).
- `body` is application ciphertext-plaintext (the app's own E2E layer,
  e.g. Forge command protocol, lives above and is opaque here too).

## 4. Rotation (enforced, not advisory)

- `seal()` throws once `sent + received >= 2^20` or age >= 24h; the
  caller MUST open a new channel and re-handshake. `needsRotation()`
  exposes the same predicate for proactive rotation.
- No post-compromise security is claimed for a live session.
- Forward secrecy (accurate): XX mixes only ephemeral-involving DHs
  (ee, es, se; never ss). Recorded sessions stay confidential after a
  later static-key compromise IF ephemeral secrets were erased
  (`noise-handshake` wipes e/re on completion). Static-key compromise
  enables future impersonation until rotated via Core enrollment.

## 5. Core requirements (no new storage or API)

Nothing new is required from Core beyond the reconciled grant contract:

- Forge identity: the enrolled machine Ed25519 key (already matches
  grant `cnf` for Forge grants). The Editor holds it from the
  authenticated Core machine record.
- Editor identity: the ephemeral per-grant `cnf` key, delivered to the
  Forge INSIDE the encrypted confirm frame as a Core-signed JWT the
  Forge verifies itself. No per-session publishing step, no X-key
  registry.
- Grant claims used by the channel: `sub`/`mid` (context match),
  `cnf.jwk.x` (binding signature), scope including `relay:connect`,
  `exp`/`nbf` (short TTL bounds replay of captured confirms; confirms
  are single-shot and encrypted under per-session keys regardless).

## 6. Relay carriage

Handshake bytes (32/96/64B for empty payloads) and transport ciphertexts
travel as `data` frame bodies, base64url-encoded, under the Relay's own
per-direction `seq` (transport-level, independent of app `seq`). Relay
enforces its envelope rules only and cannot distinguish phases.

## 7. Cross-language fixtures

- `contracts/fixtures/noise-xx.json`: byte-frozen vectors (fixed
  statics, fixed ephemerals via the documented `noiseOpts` fixture hook,
  fixed prologue): m1/m2/m3, handshake hash, confirm frames, data frames
  both directions. Asserts exact bytes (guards the pinned lib + our
  framing against silent change).
- `interop/`: live JS↔`snow` handshake/transport exchange (same run,
  handshake-hash equality asserted). This — not static fixtures — is the
  interop proof, since Noise ephemerals are random per run.
