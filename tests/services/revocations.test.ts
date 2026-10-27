import { describe, expect, it } from "vitest";
import { Effect, Layer } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "@effect/platform";
import { RelayEnv } from "../../src/config/relay.ts";
import { RevocationClient, RevocationClientLive } from "../../src/services/revocations.ts";

function stub_client(body: unknown, status = 200, counter?: { calls: number }): Layer.Layer<HttpClient.HttpClient> {
  const stub = {
    execute: (_req: HttpClientRequest.HttpClientRequest) => {
      if (counter) counter.calls++;
      return Effect.succeed(
        HttpClientResponse.fromWeb(
          _req,
          new Response(typeof body === "string" ? body : JSON.stringify(body), {
            status,
            headers: { "content-type": "application/json" },
          }),
        ),
      );
    },
  } as unknown as HttpClient.HttpClient;
  return Layer.succeed(HttpClient.HttpClient, stub);
}

function cfg(url = "https://core.test/v1/grants/revocations") {
  return {
    jwks_url: "https://core.test/.well-known/jwks.json",
    core_iss: "https://core.test",
    relay_aud: "ast-relay",
    max_ttl_sec: 300,
    revocations_url: url,
    poll_ms: 60_000,
    portal_origin: null,
    raw_env: {} as never,
  };
}

function run_fetch(body: unknown, status = 200, counter?: { calls: number }) {
  const stub = stub_client(body, status, counter);
  return Effect.runPromise(
    Effect.gen(function* () {
      const api = yield* RevocationClient;
      return yield* api.fetch_revocations();
    }).pipe(
      Effect.provide(Layer.mergeAll(Layer.provide(RevocationClientLive, stub), Layer.succeed(RelayEnv, cfg()))),
      Effect.provide(stub),
    ),
  );
}

describe("revocation client (Effect HttpClient, Core-exact shape)", () => {
  it("parses Core-exact camelCase, ignores unknown fields", async () => {
    const list = await run_fetch({
      v: 1,
      revokedMachineIds: ["m1"],
      revokedKeyIds: ["k1"],
      asOf: "2026-10-27T00:00:00.000Z",
      future_unknown: true,
    });
    expect(list).toEqual({ machines: ["m1"], keys: ["k1"] });
  });

  it("fails typed on non-2xx (poll stays fail-open upstream)", async () => {
    const stub = stub_client({ error: "x" }, 500);
    const exit = await Effect.runPromise(
      Effect.exit(
        Effect.gen(function* () {
          const api = yield* RevocationClient;
          return yield* api.fetch_revocations();
        }).pipe(
          Effect.provide(Layer.mergeAll(Layer.provide(RevocationClientLive, stub), Layer.succeed(RelayEnv, cfg()))),
          Effect.provide(stub),
        ),
      ),
    );
    expect(exit._tag).toBe("Failure");
  });

  it("retries transient transport failures (bounded)", async () => {
    let attempts = 0;
    const flaky = Layer.succeed(
      HttpClient.HttpClient,
      {
        execute: (_req: HttpClientRequest.HttpClientRequest) => {
          attempts++;
          if (attempts < 3) {
            return Effect.fail({ _tag: "RequestError", reason: "Transport", request: _req } as never);
          }
          return Effect.succeed(
            HttpClientResponse.fromWeb(
              _req,
              new Response(JSON.stringify({ revokedMachineIds: [], revokedKeyIds: [] }), {
                status: 200,
                headers: { "content-type": "application/json" },
              }),
            ),
          );
        },
      } as unknown as HttpClient.HttpClient,
    );
    const list = await Effect.runPromise(
      Effect.gen(function* () {
        const api = yield* RevocationClient;
        return yield* api.fetch_revocations();
      }).pipe(
        Effect.provide(Layer.mergeAll(Layer.provide(RevocationClientLive, flaky), Layer.succeed(RelayEnv, cfg()))),
        Effect.provide(flaky),
      ),
    );
    expect(list).toEqual({ machines: [], keys: [] });
    expect(attempts).toBe(3);
  });
});
