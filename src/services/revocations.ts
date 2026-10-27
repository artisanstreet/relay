import { Context, Duration, Effect, Layer, Schedule, Schema } from "effect";
import { HttpClient, HttpClientRequest } from "@effect/platform";
import { RelayEnv } from "../config/relay.ts";
import { RevocationFetchFailed } from "../errors.ts";

const RevId = Schema.String.pipe(Schema.maxLength(256));

const RevocationsResponse = Schema.Struct({
  revokedMachineIds: Schema.optional(Schema.Array(RevId)),
  revokedKeyIds: Schema.optional(Schema.Array(RevId)),
  asOf: Schema.optional(Schema.Union(Schema.String, Schema.Number)),
});

export interface RevocationList {
  readonly machines: string[];
  readonly keys: string[];
}

export function parse_revocations_response(body: unknown): RevocationList {
  const parsed = Schema.decodeUnknownSync(RevocationsResponse)(body);
  return {
    machines: [...(parsed.revokedMachineIds ?? [])],
    keys: [...(parsed.revokedKeyIds ?? [])],
  };
}

export interface RevocationClientApi {
  readonly fetch_revocations: () => Effect.Effect<RevocationList, RevocationFetchFailed, RelayEnv>;
}

export class RevocationClient extends Context.Tag("RevocationClient")<RevocationClient, RevocationClientApi>() {}

const retry_schedule = Schedule.exponential(Duration.millis(100)).pipe(
  Schedule.compose(Schedule.recurs(2)),
);

export const RevocationClientLive: Layer.Layer<RevocationClient, never, HttpClient.HttpClient> = Layer.effect(
  RevocationClient,
  Effect.gen(function* () {
    const http_client = yield* HttpClient.HttpClient;
    const fetch_revocations: RevocationClientApi["fetch_revocations"] = () =>
      Effect.gen(function* () {
        const cfg = yield* RelayEnv;
        const req = HttpClientRequest.get(cfg.revocations_url, {
          headers: { accept: "application/json" },
        });
        const res = yield* Effect.mapError(
          Effect.retry(
            Effect.provideService(
              Effect.flatMap(HttpClient.HttpClient, (c) => c.execute(req)),
              HttpClient.HttpClient,
              http_client,
            ),
            retry_schedule,
          ),
          (cause) => new RevocationFetchFailed({ reason: "revocations fetch failed", cause }),
        );
        if (res.status < 200 || res.status >= 300) {
          return yield* Effect.fail(new RevocationFetchFailed({ reason: "revocations fetch failed" }));
        }
        const body: unknown = yield* Effect.mapError(
          res.json,
          (cause) => new RevocationFetchFailed({ reason: "revocations decode failed", cause }),
        );
        try {
          return parse_revocations_response(body);
        } catch (cause) {
          return yield* Effect.fail(new RevocationFetchFailed({ reason: "revocations parse failed", cause }));
        }
      });
    return RevocationClient.of({ fetch_revocations });
  }),
);
