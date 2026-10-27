// Forge-side channel EXECUTION authorizer (not a generic grant verifier).
//
// The initiator (Editor) presents its Core grant INSIDE the encrypted Noise
// confirm. The Forge verifies it ITSELF (Core JWKS) and authorizes the
// channel — which may carry execution — only when:
//   role == "client", scope ⊇ {"relay:connect", "forge:execute"},
//   sub/mid bind this channel context, TTL current.
// `forge:execute` presence is the Relay-side half of Core §4 ("Relay checks
// presence, Forge enforces execution itself"); the Forge's application
// layer enforces execution independently (Rust), never trusting this alone.

import { create_grant_verifier, has_scope } from "./jwt.ts";
import type { ChannelCtx, VerifyChannelJwt } from "./channel.ts";

export interface ChannelVerifierOptions {
  jwks_url: string;
  expected_iss: string;
  expected_aud: string;
  max_ttl_sec: number;
}

/** Build the Forge-side channel execution authorizer (and tests). */
export function make_channel_jwt_verifier(
  opts: ChannelVerifierOptions,
  fetch_impl?: (url: string, options: { headers: Headers; method: "GET"; redirect: "manual"; signal: AbortSignal }) => Promise<Response>,
): VerifyChannelJwt {
  const verify = create_grant_verifier(
    { jwks_url: opts.jwks_url, expected_iss: opts.expected_iss, expected_aud: opts.expected_aud, max_ttl_sec: opts.max_ttl_sec },
    fetch_impl,
  );
  return async (jwt: string, ctx: ChannelCtx, now_sec?: number): Promise<Uint8Array> => {
    const g = await verify(jwt, now_sec);
    if (g.claims.role !== "client") throw new Error("channel grants must have role client");
    if (g.claims.sub !== ctx.account || g.claims.mid !== ctx.machine) {
      throw new Error("grant not bound to this channel context");
    }
    if (!has_scope(g, "relay:connect")) throw new Error("grant lacks relay:connect");
    if (!has_scope(g, "forge:execute")) throw new Error("grant lacks forge:execute");
    return g.cnf_pk;
  };
}
