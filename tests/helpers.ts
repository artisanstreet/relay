// Shared test helpers: throwaway Core keys, grant minting, fake sockets.
// Nothing here is production code; the committed fixtures in
// contracts/fixtures/ are the cross-language artifacts, generated from
// fixed seeds by tests/vectors.test.ts (UPDATE_FIXTURES=1).

import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex as bytes_to_hex } from "@noble/hashes/utils.js";
import { SignJWT, importJWK } from "jose";
import { create_grant_verifier, b64u_encode } from "../src/jwt.ts";
import type { VerifyGrant } from "../src/jwt.ts";
import { RoomState } from "../src/room.ts";
import type { RoomSocket } from "../src/room.ts";

export const TEST_ISS = "https://core.test/ast";
export const TEST_AUD = "ast-relay";
export const TEST_JWKS_URL = "https://core.test/.well-known/jwks.json";
export const TEST_KID = "test-core-1";

export interface CoreKey {
  sk: Uint8Array; // 32B Ed25519 seed
  pk: Uint8Array; // 32B
  jwk_public: { kty: "OKP"; crv: "Ed25519"; x: string };
}

export function test_core_key(seed_byte = 0x42): CoreKey {
  const sk = new Uint8Array(32).fill(seed_byte);
  sk[0] = (sk[0] ?? 0) ^ 0x01;
  const pk = ed25519.getPublicKey(sk);
  return {
    sk,
    pk,
    jwk_public: { kty: "OKP", crv: "Ed25519", x: b64u_encode(pk) },
  };
}

export interface GrantOpts {
  account?: string;
  machine?: string;
  role?: "forge" | "client";
  scope?: string[];
  /** Legacy rev epoch. Core v1 omits it; mint_grant omits it unless set. */
  rev?: number;
  iat?: number;
  nbf?: number;
  exp?: number;
  extra_claims?: Record<string, unknown>;
  cnf_sk?: Uint8Array; // defaults to fresh key
  kid?: string | null;
  alg?: string;
  iss?: string;
  aud?: string;
  jti?: string;
}

export async function mint_grant(
  core: CoreKey,
  opts: GrantOpts = {},
): Promise<{ jwt: string; jti: string; cnf_sk: Uint8Array; cnf_pk: Uint8Array }> {
  const cnf_sk = opts.cnf_sk ?? ed25519.utils.randomSecretKey();
  const cnf_pk = ed25519.getPublicKey(cnf_sk);
  const iat = opts.iat ?? Math.floor(Date.now() / 1000);
  const nbf = opts.nbf ?? iat;
  const jti = opts.jti ?? `test-${bytes_to_hex(ed25519.utils.randomSecretKey()).slice(0, 16)}`;
  const core_key = await importJWK(
    {
      kty: "OKP",
      crv: "Ed25519",
      d: b64u_encode(core.sk),
      x: b64u_encode(core.pk),
    },
    "EdDSA",
  );
  const header = {
    alg: "EdDSA" as const,
    typ: "JWT" as const,
    ...(opts.kid !== null ? { kid: opts.kid ?? TEST_KID } : {}),
  };
  const jwt = await new SignJWT({
    v: 1,
    sub: opts.account ?? "acct1",
    mid: opts.machine ?? "forge1",
    role: opts.role ?? "client",
    // Core §4: full trust = all three. Tests narrow explicitly where a
    // reduced scope is the point (routing-only open rejection, etc.).
    scope: opts.scope ?? ["relay:connect", "forge:execute", "machine:sync"],
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: b64u_encode(cnf_pk) } },
    // Core v1 has no rev claim: omit unless explicitly requested.
    ...(opts.rev !== undefined ? { rev: opts.rev } : {}),
    jti,
    ...(opts.extra_claims ?? {}),
  })
    .setProtectedHeader(header)
    .setIssuer(opts.iss ?? TEST_ISS)
    .setAudience(opts.aud ?? TEST_AUD)
    .setIssuedAt(iat)
    .setNotBefore(nbf)
    .setExpirationTime(opts.exp ?? iat + 120)
    .sign(core_key);
  return { jwt, jti, cnf_sk, cnf_pk };
}

export function stub_fetch(jwks: { keys: unknown[] }) {
  return async (): Promise<Response> =>
    new Response(JSON.stringify(jwks), { status: 200, headers: { "content-type": "application/json" } });
}

export function test_verifier(core: CoreKey, max_ttl_sec = 300): VerifyGrant {
  return create_grant_verifier(
    { jwks_url: TEST_JWKS_URL, expected_iss: TEST_ISS, expected_aud: TEST_AUD, max_ttl_sec },
    stub_fetch({ keys: [{ ...core.jwk_public, kid: TEST_KID, alg: "EdDSA", use: "sig" }] }),
  );
}

// ---------------------------------------------------------------------------

export interface FakeSocket extends RoomSocket {
  sent: string[];
  closed: { code?: number; reason?: string } | null;
}

export function fake_socket(): FakeSocket {
  return {
    sent: [] as string[],
    closed: null as { code?: number; reason?: string } | null,
    send(data: string) {
      (this as FakeSocket).sent.push(data);
    },
    close(code?: number, reason?: string) {
      (this as FakeSocket).closed = { code, reason };
    },
  };
}

export function last_sent(s: FakeSocket): unknown {
  if (s.sent.length === 0) throw new Error("no frames sent");
  return JSON.parse(s.sent[s.sent.length - 1] as string);
}

/**
 * Bounded wait for a frame matching `pred` (Effect scheduling can defer
 * verifier continuations; setup must synchronize on readiness, not assume
 * microtask counts). Throws with the last frame for diagnosis on timeout.
 * Security assertions in callers are unchanged.
 */
export async function wait_for_frame<T>(
  s: FakeSocket,
  pred: (f: unknown) => f is T,
  timeout_ms = 2000,
): Promise<T> {
  const deadline = Date.now() + timeout_ms;
  for (;;) {
    for (const raw of s.sent) {
      const f: unknown = JSON.parse(raw);
      if (pred(f)) return f;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for frame; last=${s.sent[s.sent.length - 1] ?? "none"}`);
    }
    await new Promise((r) => setTimeout(r, 1));
  }
}

export function is_challenge(f: unknown): f is { type: "challenge"; nonce: string } {
  return (
    typeof f === "object" &&
    f !== null &&
    (f as { type?: unknown }).type === "challenge" &&
    typeof (f as { nonce?: unknown }).nonce === "string"
  );
}

export interface RoomHarness {
  room: RoomState;
  now_ms: { t: number };
  advance(ms: number): void;
}

/** Room with controllable clock. Default room id acct1/forge1. */
export function make_room(
  verify: VerifyGrant,
  account = "acct1",
  machine = "forge1",
  // Start 1s ahead of wall clock: grants minted after setup carry
  // second-granularity nbf == iat, which a room clock fixed just before a
  // second boundary would (correctly) reject as not-yet-valid. Production
  // uses live time and never sees this; the offset only absorbs test
  // scheduling jitter, never test assertions (all advances are relative).
  start_ms = Date.now() + 1000,
): RoomHarness {
  const now_ms = { t: start_ms };
  const room = new RoomState(account, machine, verify, () => now_ms.t);
  return { room, now_ms, advance: (ms: number) => (now_ms.t += ms) };
}

export function send(room: RoomState, conn: string, obj: unknown): Promise<void> {
  return room.on_message(conn, JSON.stringify(obj));
}
