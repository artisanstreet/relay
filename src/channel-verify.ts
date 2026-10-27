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

import { createGrantVerifier, hasScope } from "./jwt.ts";
import type { ChannelCtx, VerifyChannelJwt } from "./channel.ts";

export interface ChannelVerifierOptions {
  jwksUrl: string;
  expectedIss: string;
  expectedAud: string;
  maxTtlSec: number;
}

/** Build the Forge-side channel execution authorizer (and tests). */
export function makeChannelJwtVerifier(
  opts: ChannelVerifierOptions,
  fetchImpl?: (url: string, options: { headers: Headers; method: "GET"; redirect: "manual"; signal: AbortSignal }) => Promise<Response>,
): VerifyChannelJwt {
  const verify = createGrantVerifier(
    { jwksUrl: opts.jwksUrl, expectedIss: opts.expectedIss, expectedAud: opts.expectedAud, maxTtlSec: opts.maxTtlSec },
    fetchImpl,
  );
  return async (jwt: string, ctx: ChannelCtx, nowSec?: number): Promise<Uint8Array> => {
    const g = await verify(jwt, nowSec);
    if (g.claims.role !== "client") throw new Error("channel grants must have role client");
    if (g.claims.sub !== ctx.account || g.claims.mid !== ctx.machine) {
      throw new Error("grant not bound to this channel context");
    }
    if (!hasScope(g, "relay:connect")) throw new Error("grant lacks relay:connect");
    if (!hasScope(g, "forge:execute")) throw new Error("grant lacks forge:execute");
    return g.cnfPk;
  };
}
