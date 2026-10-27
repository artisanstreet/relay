# Relay wire contract v1 (transport envelopes)

Authoritative schemas: `src/schema.ts` (Effect Schema). This file is the
human-readable summary; on any conflict the Schema wins and this file
must be fixed. Relay validates envelopes only — `data.body` is opaque
E2E ciphertext (`contracts/e2e.md`).

## WebSocket endpoint

`GET /v1/route/{account}/{machine}` with `Upgrade: websocket`.
No credentials in URL/query/headers. First frame must be `hello`
(within 5 s), then `challenge` → `authenticate` → `ready`.

### Client → server

| type | fields | notes |
|---|---|---|
| `hello` | `{v:1, grant: jwt≤8KB}` | triggers grant verify + challenge |
| `authenticate` | `{v:1, jti, sig: b64u}` | PoP over server nonce |
| `open` | `{v:1, channel}` | client only; requires forge online |
| `data` | `{v:1, channel, seq: int≥0, body: b64u≤349525}` | contiguous seq per direction (first frame seq 0, then last+1 — gaps rejected); counts against the ack window (see below) |
| `ack` | `{v:1, channel, seq: int≥0}` | cumulative delivery ack: releases frames with seq ≤ ack in the direction toward the acker |
| `close` | `{v:1, channel, reason?≤256}` | closes channel, notifies peer |
| `pong` | `{v:1, t}` | heartbeat reply |

### Server → client

| type | fields | notes |
|---|---|---|
| `challenge` | `{v:1, nonce: b64u32B, timeout_ms}` | single-use, 60 s TTL |
| `ready` | `{v:1, role, account, machine, forge_online}` | admission complete |
| `channel-opened` | `{v:1, channel, peer}` | peer = the other side's role |
| `data` | same as client `data` | routed opaque |
| `ack` | `{v:1, channel, seq}` | forwarded recipient ack: the room sends the recipient's cumulative ack on to the original sender so ITS window slides (senders never ack acks — no loops) |
| `channel-closed` | `{v:1, channel, reason}` | peer close / forge offline / revoke |
| `presence` | `{v:1, forge_online, clients}` | broadcast on change |
| `error` | `{v:1, code, message}` | no secrets in messages |
| `ping` | `{v:1, t}` | every 20 s; reply `pong` within 60 s |

Channel id charset: `/^[A-Za-z0-9][A-Za-z0-9._~:-]{0,63}$/`.

### Close codes

| code | meaning |
|---|---|
| 1000 | normal |
| 4001 | forge connection replaced by a newer auth |
| 4002 | grant revoked |
| 4401 | unauthorized (bad grant, replay, PoP failure, timeout) |
| 4403 | forbidden (wrong room binding, bad scope) |
| 4408 | policy (malformed/invalid frame, oversize, heartbeat loss) |
| 4409 | backpressure overflow (legacy code point; current policy drops the frame with a `backpressure` error instead — see flow control) |

### Flow control: ack windows (the ONLY backpressure mechanism)

The Workers server WebSocket has no `bufferedAmount`, so Relay enforces
explicit windows: per channel per direction, at most 64 unacked frames
AND 1 MiB unacked bytes, where **bytes are base64url-encoded body
lengths** (`frame.body.length` of the received string — Rust: never the
decoded raw length; the client accounts the exact encoded length, pinned
by test/send-window.test.ts). Recipients ack every data frame
(cumulative); clients MUST implement this (the bundled helper auto-acks)
and SHOULD pace uploads with the send window below instead of blasting.
A frame arriving at a full window is DROPPED (newest) with a
`backpressure` error to the sender — this is LOSS, and any lost frame
destroys the E2E session downstream (fail-closed cipher stream); apps
re-handshake on a fresh channel, never retry ciphertext. Acks for
closed/foreign channels are ignored; acks ahead of routed data are
ignored; duplicate acks are ignored (and never re-forwarded).

### Client send window (pacing uploads larger than the window)

`RelaySocket` mirrors the room caps (`SEND_WINDOW_FRAMES/BYTES`, pinned
equal by test) and tracks unacked frames per channel:
- `sendOpaque()` is fire-and-forget: returns `"dropped-window-full"`
  instead of overflowing. A dropped return means sealed bytes that will
  NEVER deliver — the E2E session is thereby unusable; re-handshake,
  never retry the ciphertext.
- `sendAcked()` resolves on the forwarded cumulative ack; rejects on
  timeout (fails the whole channel closed — windows desynchronize, so
  fail-closed), close, channel loss, or a full bounded park queue
  (`SEND_QUEUE_MAX` = 256).
- `SecureChannel.sendApp(link, channel, plaintext)` is the correct upload
  primitive: it computes the EXACT encoded size pre-seal
  (`sealedFrameSize`, pinned exact by test) and throws
  `SendWouldBlockError` with NOTHING consumed (no Noise nonce spent)
  when the window lacks space — safe to retry after acks. Browsers use
  this (or `sendAcked`), never bare `sendOpaque` for uploads.
- Timeouts never free window credit silently: a timeout means the frame
  may sit unacked at Relay, so the channel fails closed (all outstanding
  rejected). Only a transport-level send failure (frame never left)
  frees credit.

### Bounds

- Max 64 clients and 64 channels per room (`too-many-channels` past it).
- Heartbeats: server `ping` every 20 s while members exist, client
  `pong` required within 60 s. Alarms fire ONLY when a deadline exists
  (idle rooms sleep; hibernation-safe). Grant expiry is enforced
  per-frame AND on sweeps — a missed alarm never extends a dead grant.
- Connection replacement: a fresh forge auth closes the old socket
  (4001 `replaced`); clients see `forge-offline` channel closes +
  `presence`, then re-open.
- Membership/channel/seq/ack state persists across DO eviction
  (snapshot/restore); challenged-but-unauthed sockets re-hello after a
  wake; JWTs never persist.

## HTTP endpoints (see `contracts/openapi.json`)

- `GET /v1/health` → `{ok, service, v}`.
- `GET /v1/presence/{account}/{machine}` → `{v, forge_online, clients}`.
  AUTHENTICATED: `Authorization: Bearer <grant>` for the SAME
  account+machine (any role with `relay:connect`). 401 without a valid
  grant, 403 on wrong binding. Presence is account activity data and
  never leaks across rooms.
- `POST /v1/admin/revocations*` → REMOVED (410). Core v1 has no admin
  push; revocation is short expiry + the polled Core list
  (contracts/grant.md).
