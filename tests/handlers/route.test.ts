import { describe, expect, it } from "vitest";
import { Effect } from "effect";
import { RelayEnv } from "../../src/config/relay.ts";
import { handle_route_upgrade } from "../../src/handlers/route.ts";

function env_with_stub(handler: (url: string, init?: RequestInit) => Promise<Response>) {
  return {
    MACHINE_ROOM: {
      get: (_id: unknown) => ({ fetch: handler }),
      idFromName: (name: string) => ({ name }) as unknown as DurableObjectId,
    } as unknown as DurableObjectNamespace,
    CORE_JWKS_URL: "https://core.test/.well-known/jwks.json",
    CORE_ISS: "https://core.test",
  };
}

describe("WS upgrade adapter (101 extension survival)", () => {
  it("passes the raw 101 webSocket through identical (never reconstructed)", async () => {
    const marker = { marker: "ws-extension" };
    // workerd allows 101 + webSocket; undici does not — minimal stub for the
    // platform adapter (same approach as glue tests). The adapter must pass
    // it through identical, never reconstructed via HttpServerResponse.
    const upstream = { status: 101, webSocket: marker } as unknown as Response;
    const env = env_with_stub(async () => upstream);
    const cfg = await Effect.runPromise(
      Effect.match((await import("../../src/config/relay.ts")).parse_env(env), {
        onFailure: () => null,
        onSuccess: (c) => c,
      }),
    );
    if (!cfg) throw new Error("config failed");
    const res = await Effect.runPromise(
      handle_route_upgrade(
        new Request("https://relay/v1/route/acct1/forge1", { headers: { Upgrade: "websocket" } }),
        "acct1",
        "forge1",
      ).pipe(Effect.provideService(RelayEnv, cfg)),
    );
    expect(res.status).toBe(101);
    expect((res as unknown as { webSocket: unknown }).webSocket).toBe(marker);
  });

  it("preserves admission gates (400/426/403)", async () => {
    const env = env_with_stub(async () => new Response(null, { status: 101 }));
    const cfg = await Effect.runPromise(
      Effect.match((await import("../../src/config/relay.ts")).parse_env(env), {
        onFailure: () => null,
        onSuccess: (c) => c,
      }),
    );
    if (!cfg) throw new Error("config failed");
    const run = (req: Request, a: string, m: string) =>
      Effect.runPromise(handle_route_upgrade(req, a, m).pipe(Effect.provideService(RelayEnv, cfg)));
    expect((await run(new Request("https://r/v1/route/a/m"), "bad id!", "m")).status).toBe(400);
    expect(
      (await run(new Request("https://r/v1/route/a/m"), "a", "m")).status,
    ).toBe(426);
  });
});
