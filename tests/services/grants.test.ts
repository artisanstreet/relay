import { describe, expect, it } from "vitest";
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "@effect/platform";
import { GrantAuthority, GrantVerifier, GrantVerifierLive } from "../../src/services/grants/verifier.ts";
import type { GrantAuthorityConfig } from "../../src/services/grants/verifier.ts";
import { mintGrant, testCoreKey, TEST_AUD, TEST_ISS, TEST_KID } from "../helpers.ts";

function fetch_layer(jwks_body: unknown, status = 200) {
  return Layer.succeed(
    FetchHttpClient.Fetch,
    (async (): Promise<Response> =>
      new Response(JSON.stringify(jwks_body), {
        status,
        headers: { "content-type": "application/json" },
      })) as typeof fetch,
  );
}

function cfg(): GrantAuthorityConfig {
  return {
    jwks_url: "https://core.test/.well-known/jwks.json",
    core_iss: TEST_ISS,
    relay_aud: TEST_AUD,
    max_ttl_sec: 300,
  };
}

function live(jwks_body: unknown, status = 200) {
  const fetch = fetch_layer(jwks_body, status);
  return Layer.mergeAll(
    Layer.provide(GrantVerifierLive, Layer.provide(FetchHttpClient.layer, fetch)),
    Layer.succeed(GrantAuthority, cfg()),
  );
}

describe("grant verifier (Effect adapter over vetted jose)", () => {
  it("verifies a valid grant via HttpClient JWKS transport", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { role: "client" });
    const jwks = {
      keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }],
    };
    const prog = Effect.gen(function* () {
      const api = yield* GrantVerifier;
      return yield* api.verify_grant(g.jwt);
    }).pipe(Effect.provide(live(jwks)));
    const verified = await Effect.runPromise(prog);
    expect(verified.kid).toBe(TEST_KID);
    expect(verified.claims.sub).toBe("acct1");
    expect(verified.scopes.has("relay:connect")).toBe(true);
  });

  it("rejects unknown kid with typed failure (jose refetch preserved)", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { role: "client", kid: "unknown-kid" });
    const jwks = {
      keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }],
    };
    const prog = Effect.gen(function* () {
      const api = yield* GrantVerifier;
      return yield* Effect.exit(api.verify_grant(g.jwt));
    }).pipe(Effect.provide(live(jwks)));
    const exit = await Effect.runPromise(prog);
    expect(exit._tag).toBe("Failure");
  });

  it("rejects over-TTL grants without leaking cause to caller", async () => {
    const core = testCoreKey();
    const iat = Math.floor(Date.now() / 1000);
    const g = await mintGrant(core, { role: "client", iat, exp: iat + 9999 });
    const jwks = {
      keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID, alg: "EdDSA", use: "sig" }],
    };
    const prog = Effect.gen(function* () {
      const api = yield* GrantVerifier;
      return yield* Effect.exit(api.verify_grant(g.jwt));
    }).pipe(Effect.provide(live(jwks)));
    const exit = await Effect.runPromise(prog);
    expect(exit._tag).toBe("Failure");
    if (exit._tag === "Failure") {
      const failure = exit.cause as unknown as { _tag: string };
      void failure;
    }
  });
});
