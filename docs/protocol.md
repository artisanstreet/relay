# Relay Tunnel Protocol v1 (decision record + wire contract)

Status: decided by Relay owner, 2026-10-26. Implements the user-approved
architecture (Relay routes opaque E2E payload; no shared DB; Core-signed
grants; Forge verifies authorization). Pending peer confirmation on the
explicit open items at the bottom — the byte layouts below are frozen
unless a peer demonstrates an interop blocker.

## 1. Decision: Noise XX via established libraries (no TLS in tunnel, no custom handshake)

Rust proposed preserving the existing HTTPS/mTLS stack by tunneling its
bytes opaquely through Relay. Assessment:

- Browser clients have no native API to run a TLS handshake inside a
  WebSocket message stream, and there is **no established, maintained,
  audited browser-side TLS 1.3 client library**. Shipping one would be
  novel crypto-adjacent engineering with no interoperability story.
- Rust-to-Rust paths already have working mTLS and keep it: direct
  Forge↔Forge routes and local Forge listeners are untouched by this
  document. Only traffic that must traverse Relay uses the protocol below.
- "TLS via WSS" is explicitly **not** claimed: the outer WSS is
  terminated by Cloudflare and is transport-only.

A first Relay-side sketch (dual-DH "HPKE-shaped" construction) was
rejected on review: it was a new custom protocol, not a vetted one, and
its forward-secrecy claim was false.

**Decision:** the Relay path uses (a) Core-issued JWT grants + Ed25519
proof-of-possession for admission, and (b) `Noise_XX_25519_ChaChaPoly_
BLAKE2b` (Noise Protocol Framework rev 34) from established
implementations — `noise-handshake@4.2.0` pinned on the JS side
(sodium backend; esbuild browser bundle built and executed OK
2026-10-26) and `snow` on the Rust side (live JS<->snow exchange
PLANNED in `interop/`, not yet run) — plus application-level binding of the JWT `cnf`
identity to the Noise session (§4, contracts/e2e.md). No handshake
cryptography is implemented in this repo.

## 2. Layers

```text
Browser/Editor/Forge-client            Relay (CF Workers + DO)              Forge daemon
─────────────────────────            ─────────────────────────            ────────────
E2E session (X25519/HKDF/ChaCha) ◄── opaque bytes only ──► E2E session
WS admission (JWT + PoP) ──────────► verify + route ────► WS admission (JWT + PoP)
outer WSS (CF-terminated, transport, NOT E2E)
```

Relay sees: JWT claims (routing/binding), channel ids, sequence numbers,
nonces, ephemeral public keys, ciphertext lengths. Relay never sees
plaintext, session keys, or identity secret keys.

## 3. Admission (Relay verifies, Forge re-verifies)

1. `GET /v1/route/{account}/{machine}` with `Upgrade: websocket`.
   No credentials in URL, headers, or logs — browsers cannot set WS
   headers, so auth happens in-band.
2. Client sends `hello {v:1, grant}` within 5 s or the socket is closed
   (4401). Grant is a Core-signed JWT (EdDSA, `kid`), `aud: ast-relay-v1`,
   TTL ≤ 300 s, single-use `jti` (replay cache), claims
   `{v, iss, aud, jti, iat, [nbf,] exp, account, machine, role, scope,
   cnf: {jwk: OKP Ed25519 pub}, rev}`. Unknown top-level claims rejected
   at v=1. `forge`-role requires `relay:route` and is bound to exactly
   `{account}/{machine}`; `relay:admin` grants cannot open tunnels.
3. Server replies `challenge {nonce(32B), timeout_ms}` (TTL 60 s,
   single-use). Client replies
   `authenticate {jti, sig}` with
   `sig = Ed25519(cnf_sk, "ast-relay-auth-v1" || nonce || jti_utf8)`.
   Failure closes the socket (4401). No possession proof ⇒ bearer theft
   would be enough; with it, a stolen JWT alone cannot connect.
4. Server replies `ready {role, account, machine, forge_online}`.
   Forge connections replace the previous holder (old socket closed
   4001 `replaced`); replacement requires a fresh grant + fresh PoP, so
   an attacker that merely observes traffic cannot desync the room.

## 4. Inner E2E channel: Noise XX + JWT-identity binding

Fresh X25519 static keys per channel (no static-key registry, no TOFU).
Opener = initiator (client/Editor); Forge = responder. No handshake
cryptography is implemented in this repo: `Noise_XX_25519_ChaChaPoly_
BLAKE2b` via `noise-handshake@4.2.0` (JS) and `snow` (Rust).

```text
prologue = "ast-relay-noise-v1" || 0x00 || account || 0x00 || machine || 0x00 || channel
XX handshake, empty payloads  ->  Split  ->
initiator confirm: handshake_hash || grant_jwt || bind_sig(0x01)  ->
responder confirm: handshake_hash || bind_sig(0x02)  ->
data frames: "AR1" || 0x01 || ch_len || channel || seq(u64) || kind || body
```

The initiator's grant JWT travels INSIDE the encrypted confirm; Forge
verifies it itself (JWKS, sub/mid/scope/expiry) and uses ONLY the
verified `cnf` key to check the initiator's binding signature over
`"ast-relay-bind-v1" || role || handshake_hash`. The responder signs
with its enrolled machine key, verified by the Editor against the
authenticated Core machine record. JWT identity, transcript, and context
are bound without trusting Relay and without new Core storage or API.
Transport uses sequential Noise nonces (ordered WS, new channel per
reconnect); every violation is fail-closed; rotation enforced at 2^20
messages / 24h. Full byte contract: contracts/e2e.md. No
post-compromise security is claimed for live sessions.

## 5. mTLS property mapping (what replaces what)

| mTLS property (direct paths) | Relay-path equivalent |
|---|---|
| Server cert (Forge identity) | Forge identity X25519/Ed25519 keys, fingerprints via account; JWT `machine` binding |
| Client cert (caller identity) | JWT `account`/`role`/`scope` + PoP proof binds bearer to holder |
| TLS session secrecy | Per-channel `session_key` via dual-DH wrap; Relay holds only ciphertext |
| Record integrity/order | XChaCha AAD (channel+seq) + Relay transport seq enforcement |
| Revocation (CRL/OCSP) | `rev` epoch + Core-signed revocation push; live conns swept ≤ 30 s |
| Cipher negotiation | None — single fixed suite (negotiation is an interop risk) |

## 6. Non-goals / explicit limits

- Relay cannot assert E2E peer identity beyond JWT claims; initial key
  binding trust comes from Core fingerprint distribution, not Relay.
- Revocation is bounded, not instant: new auth immediate, live conns
  ≤ 30 s sweep, in-flight messages already delivered are not recalled.
- No remote attestation, no per-project scopes (pairing = full Forge
  trust per settled product decision), no project replication traffic
  semantics in v1 (replication agents run above this tunnel).
- Single suite only. If primitives must change, the contract version
  (`v`, `KEM_INFO_PREFIX`, `DATA_INFO`) bumps.

## 7. Open items (need Core / Rust confirmation)

1. Core: exact `iss`, JWKS URL, JWT TTL, v1-claim strictness,
   `relay:admin` push-auth name. No new distribution needed for channels:
   Forge identity comes from the existing enrolled machine record;
   Editor identity arrives in-band as a Core-signed JWT.
2. Rust: implement `Noise_XX_25519_ChaChaPoly_BLAKE2b` with `snow`
   (same protocol string), the §4 prologue, empty handshake payloads,
   mutual confirm (`handshake_hash || [jwt_len || jwt] || bind-sig`),
   app framing, enforced rotation per contracts/e2e.md. LIVE EXCHANGE
   RUN GREEN 2026-10-27 (JS initiator <-> snow 0.10 responder in
   `interop/snow-peer`: handshake-hash equality + both transport
   directions). Confirm/app framing above Noise is Relay/Rust-shared
   application format — implement per contracts/e2e.md §2/§3.
3. Root: route this doc; peer threads unreachable from Relay thread
   (`agent_message` returned "has no agent" for both peer ids).
