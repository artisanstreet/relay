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

export class MachineRoom implements DurableObject {
  private state: DurableObjectState;
  private relay_cfg: RelayEnv["Type"];
  private store: RoomStoreApi;
  private last_fetch_ref: Ref.Ref<number>;
  private runtime: ManagedRuntime.ManagedRuntime<RevocationClient | RelayEnv, never>;
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

  private flush_shared(): Effect.Effect<void> {
    const store = this.store;
    const do_state = this.state;
    return Effect.gen(function* () {
      const exit = yield* Effect.exit(store.flush());
      if (exit._tag === "Failure") {
        for (const ws of do_state.getWebSockets()) {
          try {
            ws.close(1011, "storage-unavailable");
          } catch { /* expected: socket gone, best effort */ }
        }
      }
    });
  }

  private background(effect: Effect.Effect<void>): void {
    this.state.waitUntil(this.runtime.runPromise(effect));
  }

  private schedule_shared(): Effect.Effect<void> {
    const store = this.store;
    const last_ref = this.last_fetch_ref;
    const cfg = this.relay_cfg;
    const do_state = this.state;
    return Effect.catchAll(
      Effect.gen(function* () {
        const room = yield* store.get_room();
        const last = yield* Ref.get(last_ref);
        yield* schedule_alarm(do_state, next_wake_ms(room, last, cfg.poll_ms));
      }),
      () => Effect.void,
    );
  }

  private refresh_shared(): Effect.Effect<void, never, RelayEnv | RevocationClient> {
    const store = this.store;
    const last_ref = this.last_fetch_ref;
    return Effect.ignore(refresh_revocations(() => store.get_room(), last_ref, () => Date.now()));
  }

  async fetch(req: Request): Promise<Response> {
    const store = this.store;
    const do_state = this.state;
    const verify_fn = this.verify_fn;
    const self_ref = this;
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
        do_state.waitUntil(self_ref.runtime.runPromise(self_ref.flush_shared()));
        do_state.waitUntil(self_ref.runtime.runPromise(self_ref.refresh_shared()));
        yield* self_ref.schedule_shared();
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
    const program = Effect.gen(function* () {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (!att) {
        yield* Effect.sync(() => {
          try {
            ws.close(4401, "gone");
          } catch { /* expected: socket gone, best effort */ }
        });
        return;
      }
      const live = live_map(do_state);
      const existing = yield* store.get_room();
      if (!existing) {
        const exit = yield* Effect.exit(store.ensure_loaded((id) => adapter_for(live, id)));
        if (exit._tag === "Failure") {
          yield* Effect.sync(() => {
            try {
              ws.close(1011, "storage-unavailable");
            } catch { /* expected: socket gone, best effort */ }
          });
          return;
        }
        if (exit.value === null) {
          yield* Effect.sync(() => {
            try {
              ws.close(4401, "gone");
            } catch { /* expected: socket gone, best effort */ }
          });
          return;
        }
      }
      const current = yield* store.get_room();
      if (!current) {
        yield* Effect.sync(() => {
          try {
            ws.close(4401, "gone");
          } catch { /* expected: socket gone, best effort */ }
        });
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
      do_state.waitUntil(self_ref.runtime.runPromise(self_ref.flush_shared()));
      yield* self_ref.schedule_shared();
    });
    const self_ref = this;
    await this.runtime.runPromise(program);
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    const store = this.store;
    const do_state = this.state;
    const self_ref = this;
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
      do_state.waitUntil(self_ref.runtime.runPromise(self_ref.flush_shared()));
      yield* self_ref.schedule_shared();
    });
    await this.runtime.runPromise(program);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    const store = this.store;
    const do_state = this.state;
    const self_ref = this;
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
      yield* Effect.sync(() => {
        try {
          ws.close(1011, "error");
        } catch { /* expected: socket gone, best effort */ }
      });
      do_state.waitUntil(self_ref.runtime.runPromise(self_ref.flush_shared()));
      yield* self_ref.schedule_shared();
    });
    await this.runtime.runPromise(program);
  }

  async alarm(): Promise<void> {
    const store = this.store;
    const do_state = this.state;
    const self_ref = this;
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
      yield* self_ref.refresh_shared();
      const current = yield* store.get_room();
      current?.tick();
      do_state.waitUntil(self_ref.runtime.runPromise(self_ref.flush_shared()));
      yield* self_ref.schedule_shared();
    });
    await this.runtime.runPromise(program);
  }
}
