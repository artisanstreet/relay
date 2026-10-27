import { Effect } from "effect";
import { RelayEnv, room_id } from "../config/relay.ts";
import { wsOriginGate } from "../cors.ts";

const id_re = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;

function json_response(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * WebSocket upgrade adapter. Explicit platform code: returns the raw
 * Cloudflare 101 Response with the `webSocket` extension intact. Never
 * reconstructed via HttpServerResponse (which would drop the extension).
 * Effect covers validation + gate + forwarding; the 101 passes through.
 */
export const handle_route_upgrade = (
  req: Request,
  account: string,
  machine: string,
): Effect.Effect<Response, never, RelayEnv> =>
  Effect.gen(function* () {
    if (!id_re.test(account) || !id_re.test(machine)) {
      return json_response({ error: "bad room id" }, 400);
    }
    if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return json_response({ error: "websocket required" }, 426);
    }
    const cfg = yield* RelayEnv;
    const gate = wsOriginGate(req, cfg.portal_origin);
    if (gate) return gate;
    const stub = cfg.raw_env.MACHINE_ROOM.get(room_id(cfg.raw_env.MACHINE_ROOM, account, machine));
    return yield* Effect.matchEffect(
      Effect.tryPromise({
        try: () => stub.fetch(`https://relay/room/${account}/${machine}`, { headers: req.headers }),
        catch: () => new Error("route forward failed"),
      }),
      {
        onFailure: () => Effect.succeed(json_response({ error: "route unavailable" }, 502)),
        onSuccess: (upstream) => Effect.succeed(upstream),
      },
    );
  });
