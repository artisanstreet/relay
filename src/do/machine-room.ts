import { Effect, Layer, ManagedRuntime, Ref } from "effect";
import { FetchHttpClient } from "@effect/platform";
import { RoomState } from "../room/state.ts";
import type { RoomSocket, VerifyGrant } from "../room/state.ts";
import { RelayEnv, parse_env, type Env } from "../config/relay.ts";
import { createGrantVerifier } from "../jwt.ts";
import { RevocationClient, RevocationClientLive } from "../services/revocations.ts";
import { make_room_store } from "./room-store.ts";
import type { RoomStoreApi } from "./room-store.ts";
import { next_wake_ms, schedule_alarm } from "./alarm-scheduler.ts";
import { refresh_revocations } from "./revocation-refresh.ts";

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;

interface Attachment {
  conn: string;
}

const HttpLive = FetchHttpClient.layer;

function live_map(state: DurableObjectState): Map<string, WebSocket> {
  const live = new Map<string, WebSocket>();
  for (const ws of state.getWebSockets()) {
    const att = ws.deserializeAttachment() as Attachment | null;
    if (att) live.set(att.conn, ws);
  }
  return live;
}

function adapter_for(live: Map<string, WebSocket>, conn_id: string): RoomSocket | null {
  const ws = live.get(conn_id);
  if (!ws) return null;
  return {
    send: (data: string) => ws.send(data),
    close: (code?: number, reason?: string) => ws.close(code, reason),
  };
}

/** Best-effort socket close: a gone socket is expected, never an error. */
const close_quietly = (ws: WebSocket, code: number, reason: string): Effect.Effect<void> =>
  Effect.try({
    try: () => ws.close(code, reason),
    catch: () => undefined,
  }).pipe(Effect.ignore);

type DoRuntime = ManagedRuntime.ManagedRuntime<RevocationClient | RelayEnv, never>;

const run_background = (
  do_state: DurableObjectState,
  runtime: DoRuntime,
  effect: Effect.Effect<void, unknown, RevocationClient | RelayEnv>,
): void => {
  do_state.waitUntil(runtime.runPromise(effect));
};

const flush_shared = (store: RoomStoreApi, do_state: DurableObjectState): Effect.Effect<void> =>
  Effect.gen(function* () {
    const exit = yield* Effect.exit(store.flush());
    if (exit._tag === "Failure") {
      for (const ws of do_state.getWebSockets()) {
        yield* close_quietly(ws, 1011, "storage-unavailable");
      }
    }
  });

const schedule_shared = (
  store: RoomStoreApi,
  last_ref: Ref.Ref<number>,
  poll_ms: number,
  do_state: DurableObjectState,
): Effect.Effect<void> =>
  Effect.catchAll(
    Effect.gen(function* () {
      const room = yield* store.get_room();
      const last = yield* Ref.get(last_ref);
      yield* schedule_alarm(do_state, next_wake_ms(room, last, poll_ms));
    }),
    () => Effect.void,
  );

const refresh_shared = (
  store: RoomStoreApi,
  last_ref: Ref.Ref<number>,
): Effect.Effect<void, never, RelayEnv | RevocationClient> =>
  Effect.ignore(refresh_revocations(() => store.get_room(), last_ref, () => Date.now()));

export class MachineRoom implements DurableObject {
  private state: DurableObjectState;
  private relay_cfg: RelayEnv["Type"];
  private store: RoomStoreApi;
  private last_fetch_ref: Ref.Ref<number>;
  private runtime: DoRuntime;
  private verify_fn: VerifyGrant;

  constructor(state: DurableObjectState, env: Env) {
    const do_state = state;
    const acquired = Effect.runSync(Effect.gen(function* () {
      const cfg = yield* parse_env(env);
      const last_fetch_ref = yield* Ref.make(0);
      return { cfg, last_fetch_ref };
    }));
    this.state = do_state;
    this.relay_cfg = acquired.cfg;
    this.last_fetch_ref = acquired.last_fetch_ref;
    this.runtime = ManagedRuntime.make(
      Layer.mergeAll(
        Layer.provide(RevocationClientLive, HttpLive),
        HttpLive,
        Layer.succeed(RelayEnv, acquired.cfg),
      ),
    );
    this.verify_fn = createGrantVerifier({
      jwksUrl: acquired.cfg.jwks_url,
      expectedIss: acquired.cfg.core_iss,
      expectedAud: acquired.cfg.relay_aud,
      maxTtlSec: acquired.cfg.max_ttl_sec,
    });
    this.store = Effect.runSync(make_room_store(do_state, this.verify_fn, () => Date.now()));
  }

  async fetch(req: Request): Promise<Response> {
    const store = this.store;
    const do_state = this.state;
    const verify_fn = this.verify_fn;
    const runtime = this.runtime;
    const last_ref = this.last_fetch_ref;
    const poll_ms = this.relay_cfg.poll_ms;
    const program = Effect.gen(function* () {
      const url = new URL(req.url);
      const m = url.pathname.match(/^\/room\/([^/]+)\/([^/]+)$/);
      if (m && req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
        const [, account = "", machine = ""] = m;
        if (!ID_RE.test(account) || !ID_RE.test(machine)) {
          return new Response("bad room id", { status: 400 });
        }
        const live = live_map(do_state);
        const socket_for = (id: string) => adapter_for(live, id);
        const exit = yield* Effect.exit(store.ensure_loaded(socket_for));
        if (exit._tag === "Failure") {
          return new Response("storage unavailable", { status: 500 });
        }
        const room_check = exit.value;
        if (room_check && (room_check.account !== account || room_check.machine !== machine)) {
          return new Response("room mismatch", { status: 400 });
        }
        let room = room_check;
        if (!room) {
          const fresh = new RoomState(account, machine, verify_fn, () => Date.now());
          yield* store.set_fresh_room(fresh);
          room = fresh;
        }
        void room;
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        const conn = crypto.randomUUID();
        do_state.acceptWebSocket(server);
        server.serializeAttachment({ conn } satisfies Attachment);
        const live_after = live_map(do_state);
        const adapter = adapter_for(live_after, conn) ?? {
          send: (d: string) => (server as unknown as WebSocket).send(d),
          close: (c?: number, r?: string) => (server as unknown as WebSocket).close(c, r),
        };
        const current = yield* store.get_room();
        current?.onConnect(conn, adapter);
        run_background(do_state, runtime, flush_shared(store, do_state));
        run_background(do_state, runtime, refresh_shared(store, last_ref));
        yield* schedule_shared(store, last_ref, poll_ms, do_state);
        return new Response(null, { status: 101, webSocket: client });
      }
      if (url.pathname === "/presence") {
        const live = live_map(do_state);
        const socket_for = (id: string) => adapter_for(live, id);
        const exit = yield* Effect.exit(store.ensure_loaded(socket_for));
        if (exit._tag === "Failure") {
          return Response.json({ error: "storage unavailable" }, { status: 500 });
        }
        const room = exit.value;
        if (!room) return Response.json({ v: 1, forge_online: false, clients: 0 });
        return Response.json({ v: 1, ...room.presence() });
      }
      return new Response("not found", { status: 404 });
    });
    return this.runtime.runPromise(program);
  }

  async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer): Promise<void> {
    const store = this.store;
    const do_state = this.state;
    const runtime = this.runtime;
    const last_ref = this.last_fetch_ref;
    const poll_ms = this.relay_cfg.poll_ms;
    const program = Effect.gen(function* () {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (!att) {
        yield* close_quietly(ws, 4401, "gone");
        return;
      }
      const live = live_map(do_state);
      const existing = yield* store.get_room();
      if (!existing) {
        const exit = yield* Effect.exit(store.ensure_loaded((id) => adapter_for(live, id)));
        if (exit._tag === "Failure") {
          yield* close_quietly(ws, 1011, "storage-unavailable");
          return;
        }
        if (exit.value === null) {
          yield* close_quietly(ws, 4401, "gone");
          return;
        }
      }
      const current = yield* store.get_room();
      if (!current) {
        yield* close_quietly(ws, 4401, "gone");
        return;
      }
      if (!current.hasConn(att.conn)) {
        const adapter = adapter_for(live, att.conn) ?? {
          send: (d: string) => ws.send(d),
          close: (c?: number, r?: string) => ws.close(c, r),
        };
        current.onConnect(att.conn, adapter);
      }
      yield* Effect.ignore(Effect.promise(() => current.onMessage(att.conn, msg)));
      run_background(do_state, runtime, flush_shared(store, do_state));
      yield* schedule_shared(store, last_ref, poll_ms, do_state);
    });
    await this.runtime.runPromise(program);
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    const store = this.store;
    const do_state = this.state;
    const runtime = this.runtime;
    const last_ref = this.last_fetch_ref;
    const poll_ms = this.relay_cfg.poll_ms;
    const program = Effect.gen(function* () {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (!att) return;
      const live = live_map(do_state);
      const existing = yield* store.get_room();
      if (!existing) {
        yield* Effect.ignore(Effect.exit(store.ensure_loaded((id) => adapter_for(live, id))));
      }
      const current = yield* store.get_room();
      current?.onClose(att.conn);
      run_background(do_state, runtime, flush_shared(store, do_state));
      yield* schedule_shared(store, last_ref, poll_ms, do_state);
    });
    await this.runtime.runPromise(program);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    const store = this.store;
    const do_state = this.state;
    const runtime = this.runtime;
    const last_ref = this.last_fetch_ref;
    const poll_ms = this.relay_cfg.poll_ms;
    const program = Effect.gen(function* () {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (att) {
        const live = live_map(do_state);
        const existing = yield* store.get_room();
        if (!existing) {
          yield* Effect.ignore(Effect.exit(store.ensure_loaded((id) => adapter_for(live, id))));
        }
        const current = yield* store.get_room();
        current?.onClose(att.conn);
      }
      yield* close_quietly(ws, 1011, "error");
      run_background(do_state, runtime, flush_shared(store, do_state));
      yield* schedule_shared(store, last_ref, poll_ms, do_state);
    });
    await this.runtime.runPromise(program);
  }

  async alarm(): Promise<void> {
    const store = this.store;
    const do_state = this.state;
    const runtime = this.runtime;
    const last_ref = this.last_fetch_ref;
    const poll_ms = this.relay_cfg.poll_ms;
    const program = Effect.gen(function* () {
      const live = live_map(do_state);
      const existing = yield* store.get_room();
      if (!existing) {
        const exit = yield* Effect.exit(store.ensure_loaded((id) => adapter_for(live, id)));
        if (exit._tag === "Failure") {
          yield* Effect.ignore(
            Effect.promise(() => do_state.storage.setAlarm(Date.now() + 30_000)),
          );
          return;
        }
      }
      yield* refresh_shared(store, last_ref);
      const current = yield* store.get_room();
      current?.tick();
      run_background(do_state, runtime, flush_shared(store, do_state));
      yield* schedule_shared(store, last_ref, poll_ms, do_state);
    });
    await this.runtime.runPromise(program);
  }
}
