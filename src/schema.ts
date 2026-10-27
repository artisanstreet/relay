// Authoritative runtime contracts for the Relay service.
// Effect Schema is the single source of truth: every inbound WS frame,
// HTTP body, and JWT claim set is decoded here with onExcessProperty:"error"
// (strict request reads — unknown fields rejected). Outbound reads are
// forward-compatible (optional fields, defaults).

import { Schema } from "effect";

// ---------------------------------------------------------------------------
// Shared atoms
// ---------------------------------------------------------------------------

/** Protocol/contract major version. A bump is required for new fields. */
export const ProtocolV = Schema.Literal(1);

const idCharset = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const channelCharset = /^[A-Za-z0-9][A-Za-z0-9._~:-]{0,63}$/;

export const AccountId = Schema.String.pipe(Schema.pattern(idCharset));
export type AccountId = typeof AccountId.Type;
export const MachineId = Schema.String.pipe(Schema.pattern(idCharset));
export type MachineId = typeof MachineId.Type;
export const ChannelId = Schema.String.pipe(Schema.pattern(channelCharset));
export type ChannelId = typeof ChannelId.Type;
export const JwtCompact = Schema.String.pipe(
  Schema.minLength(16),
  Schema.maxLength(8192),
);
export const B64U32 = Schema.String.pipe(Schema.pattern(/^[A-Za-z0-9_-]{43}$/));
export const B64U = Schema.String.pipe(
  Schema.minLength(1),
  Schema.maxLength(349_525), // 256 KiB binary ceiling as base64url text
);

// ---------------------------------------------------------------------------
// Grant JWT claims (RelayGrant v=1). Signed by Core (EdDSA, kid in header).
// Relay enforces relay:* scopes; forge:* scopes are opaque here (Forge's job).
// ---------------------------------------------------------------------------

export const RelayScope = Schema.Union(
  Schema.Literal("relay:connect"),
  Schema.Literal("forge:execute"),
  Schema.Literal("machine:sync"),
);

export const CnfJwk = Schema.Struct({
  kty: Schema.Literal("OKP"),
  crv: Schema.Literal("Ed25519"),
  x: B64U32,
});

export const GrantClaims = Schema.Struct({
  v: ProtocolV,
  iss: Schema.NonEmptyString,
  aud: Schema.Union(Schema.String, Schema.Array(Schema.String)),
  // Reconciled with Core docs/contracts.md (root decision 2026-10-26):
  // sub = account, mid = explicit target machine on ALL relay grants
  // (Forge and Editor alike). Core binding prevents cross-account and
  // cross-machine routes; Relay enforces the binding per room.
  sub: AccountId,
  mid: MachineId,
  jti: Schema.NonEmptyString,
  iat: Schema.Int,
  nbf: Schema.Int,
  exp: Schema.Int,
  role: Schema.Union(Schema.Literal("forge"), Schema.Literal("client")),
  scope: Schema.Array(RelayScope),
  cnf: Schema.Struct({ jwk: CnfJwk }),
  // Core v1 has NO rev claim (authoritative: Core docs/contracts.md §4).
  // Accepted when present for backward compatibility, NOT enforced:
  // v1 revocation = short expiry + the /v1/grants/revocations list.
  rev: Schema.optional(Schema.Int),
});
export type GrantClaims = typeof GrantClaims.Type;

// ---------------------------------------------------------------------------
// WS frames, client -> server
// ---------------------------------------------------------------------------

export const HelloFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("hello"),
  grant: JwtCompact,
});
export type HelloFrame = typeof HelloFrame.Type;

export const AuthenticateFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("authenticate"),
  jti: Schema.NonEmptyString,
  sig: B64U,
});
export type AuthenticateFrame = typeof AuthenticateFrame.Type;

export const OpenFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("open"),
  channel: ChannelId,
});
export type OpenFrame = typeof OpenFrame.Type;

export const DataFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("data"),
  channel: ChannelId,
  seq: Schema.NonNegativeInt,
  body: B64U, // opaque E2E ciphertext; Relay never inspects
});
export type DataFrame = typeof DataFrame.Type;

export const CloseFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("close"),
  channel: ChannelId,
  reason: Schema.optional(Schema.String.pipe(Schema.maxLength(256))),
});
export type CloseFrame = typeof CloseFrame.Type;

/**
 * Cumulative delivery ack (flow control). ackSeq acknowledges all data
 * frames with seq <= ackSeq in the direction toward the acker.
 */
export const AckFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("ack"),
  channel: ChannelId,
  seq: Schema.NonNegativeInt,
});
export type AckFrame = typeof AckFrame.Type;

export const PongFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("pong"),
  t: Schema.Int,
});
export type PongFrame = typeof PongFrame.Type;

export const ClientFrame = Schema.Union(
  HelloFrame,
  AuthenticateFrame,
  OpenFrame,
  DataFrame,
  AckFrame,
  CloseFrame,
  PongFrame,
);
export type ClientFrame = typeof ClientFrame.Type;

// ---------------------------------------------------------------------------
// WS frames, server -> client
// ---------------------------------------------------------------------------

export const ChallengeFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("challenge"),
  nonce: B64U32,
  timeout_ms: Schema.Int,
});
export type ChallengeFrame = typeof ChallengeFrame.Type;

export const ReadyFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("ready"),
  role: Schema.Union(Schema.Literal("forge"), Schema.Literal("client")),
  account: AccountId,
  machine: MachineId,
  forge_online: Schema.Boolean,
});
export type ReadyFrame = typeof ReadyFrame.Type;

export const ChannelOpenedFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("channel-opened"),
  channel: ChannelId,
  peer: Schema.Union(Schema.Literal("forge"), Schema.Literal("client")),
});
export type ChannelOpenedFrame = typeof ChannelOpenedFrame.Type;

export const ChannelClosedFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("channel-closed"),
  channel: ChannelId,
  reason: Schema.String,
});
export type ChannelClosedFrame = typeof ChannelClosedFrame.Type;

export const PresenceFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("presence"),
  forge_online: Schema.Boolean,
  clients: Schema.Int,
});
export type PresenceFrame = typeof PresenceFrame.Type;

export const ErrorFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("error"),
  code: Schema.String,
  message: Schema.String,
});
export type ErrorFrame = typeof ErrorFrame.Type;

export const PingFrame = Schema.Struct({
  v: ProtocolV,
  type: Schema.Literal("ping"),
  t: Schema.Int,
});
export type PingFrame = typeof PingFrame.Type;

export const ServerFrame = Schema.Union(
  ChallengeFrame,
  ReadyFrame,
  ChannelOpenedFrame,
  DataFrame,
  AckFrame,
  ChannelClosedFrame,
  PresenceFrame,
  ErrorFrame,
  PingFrame,
);
export type ServerFrame = typeof ServerFrame.Type;

// ---------------------------------------------------------------------------
// HTTP bodies
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Strict decode helpers (requests) / tolerant encode (responses).
// ---------------------------------------------------------------------------

const strictOptions = { onExcessProperty: "error" } as const;

export function decodeClientFrame(u: unknown): ClientFrame {
  return Schema.decodeUnknownSync(ClientFrame, strictOptions)(u);
}

export function decodeGrantClaims(u: unknown): GrantClaims {
  return Schema.decodeUnknownSync(GrantClaims, strictOptions)(u);
}

/** Forward-compatible read of server frames (ignores unknown fields). */
export function readServerFrame(u: unknown): ServerFrame {
  return Schema.decodeUnknownSync(ServerFrame)(u);
}

export function encodeServerFrame(f: ServerFrame): string {
  return JSON.stringify(Schema.encodeSync(ServerFrame)(f));
}
