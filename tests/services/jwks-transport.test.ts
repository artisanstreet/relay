import { describe, expect, it } from "vitest";
import { Effect, Exit, Layer } from "effect";
import { FetchHttpClient } from "@effect/platform";
import { GrantAuthority, GrantVerifier, GrantVerifierLive } from "../../src/services/grants/verifier.ts";
import { mintGrant, testCoreKey, TEST_AUD, TEST_ISS, TEST_KID } from "../helpers.ts";

describe("jwks transport fidelity (SDK policy preserved)", () => {
  it("does not follow redirects and propagates a real abort signal", async () => {
    const core = testCoreKey();
    const g = await mintGrant(core, { role: "client" });
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const fetch_layer = Layer.succeed(
      FetchHttpClient.Fetch,
      (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        seen.push({ url: String(url), init: init ?? {} });
        if (String(url).endsWith("/jwks.json")) {
          return new Response(null, { status: 302, headers: { location: "https://core.test/other" } });
        }
        return new Response(
          JSON.stringify({
            keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(core.pk).toString("base64url"), kid: TEST_KID }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }) as typeof fetch,
    );
    const prog = Effect.gen(function* () {
      const api = yield* GrantVerifier;
      return yield* Effect.exit(api.verify_grant(g.jwt));
    }).pipe(
      Effect.provide(
        Layer.mergeAll(
          Layer.provide(GrantVerifierLive, Layer.provide(FetchHttpClient.layer, fetch_layer)),
          Layer.succeed(GrantAuthority, {
            jwks_url: "https://core.test/.well-known/jwks.json",
            core_iss: TEST_ISS,
            relay_aud: TEST_AUD,
            max_ttl_sec: 300,
          }),
        ),
      ),
    );
    const exit = await Effect.runPromise(prog);
    expect(Exit.isFailure(exit)).toBe(true);
    expect(seen.length).toBe(1);
    expect(seen[0]?.init.redirect).toBe("manual");
    expect(seen[0]?.init.signal).toBeInstanceOf(AbortSignal);
  });
});
