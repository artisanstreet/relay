// Responder-side verification of the in-confirm grant JWT.
//
// The Forge verifies the Editor's grant ITSELF (Core JWKS) and extracts
// ONLY the verified `cnf` key for the binding-signature check. Relay-
// forwarded keys are never accepted here. Reuses the Relay grant verifier
// (same claim rules: sub/mid binding, TTL, audience) plus the channel
// context match.

import { createGrantVerifier, hasScope } from "./jwt.ts";
import type { ChannelCtx, VerifyChannelJwt } from "./channel.ts";

export interface ChannelVerifierOptions {
  jwksUrl: string;
  expectedIss: string;
  expectedAud: string;
  maxTtlSec: number;
}

/** Build a VerifyChannelJwt for Forge daemons (and tests). */
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
    if (g.claims.sub !== ctx.account || g.claims.mid !== ctx.machine) {
      throw new Error("grant not bound to this channel context");
    }
    if (!hasScope(g, "relay:connect")) throw new Error("grant lacks relay:connect");
    return g.cnfPk;
  };
}
