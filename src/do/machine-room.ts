import { Effect, Layer, Ref } from "effect";
import { FetchHttpClient } from "@effect/platform";
import { RoomState } from "../room/state.ts";
import type { RoomSocket, VerifyGrant } from "../room/state.ts";
import { RelayEnv, parse_env, type Env } from "../config/relay.ts";
import { createGrantVerifier } from "../jwt.ts";
import { RevocationClientLive } from "../services/revocations.ts";
import { make_room_store } from "./room-store.ts";
import type { RoomStoreApi } from "./room-store.ts";
import { next_wake_ms, schedule_alarm } from "./alarm-scheduler.ts";
import { refresh_revocations } from "./revocation-refresh.ts";

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;

interface Attachment {
  conn: string;
}

const HttpLive = FetchHttpClient.layer;
const RevocationLive = Layer.provide(RevocationClientLive, HttpLive);

export class MachineRoom implements DurableObject {
  private state: DurableObjectState;
  private relay_cfg: RelayEnv["Type"] | null = null;
  private store: RoomStoreApi | null = null;
  private last_fetch_ref: Ref.Ref<number> | null = null;
  private verify_fn: VerifyGrant | null = null;
  private ready: Promise<void>;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.ready = this.init_instance(env);
  }

  private async init_instance(env: Env): Promise<void> {
    const cfg = await Effect.runPromise(parse_env(env));
    this.relay_cfg = cfg;
    this.verify_fn = createGrantVerifier({
      jwksUrl: cfg.jwks_url,
      expectedIss: cfg.core_iss,
      expectedAud: cfg.relay_aud,
      maxTtlSec: cfg.max_ttl_sec,
    });
    this.store = await Effect.runPromise(
      make_room_store(this.state, this.verify_fn, () => Date.now()),
    );
    this.last_fetch_ref = await Effect.runPromise(Ref.make(0));
  }

  private cfg(): RelayEnv["Type"] {
    if (!this.relay_cfg) throw new Error("relay misconfigured");
    return this.relay_cfg;
  }

  private get_store(): RoomStoreApi {
    if (!this.store) throw new Error("storage unavailable");
    return this.store;
  }

  private live_map(): Map<string, WebSocket> {
    const live = new Map<string, WebSocket>();
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (att) live.set(att.conn, ws);
    }
    return live;
  }

  private adapter_for(live: Map<string, WebSocket>, conn_id: string): RoomSocket | null {
    const ws = live.get(conn_id);
    if (!ws) return null;
    return {
      send: (data: string) => ws.send(data),
      close: (code?: number, reason?: string) => ws.close(code, reason),
    };
  }

  private run<A>(effect: Effect.Effect<A, unknown, never>): Promise<A> {
    return Effect.runPromise(effect as Effect.Effect<A, never, never>);
  }

  private flush_later(): void {
    const store = this.store;
    if (!store) return;
    this.state.waitUntil(this.run(store.flush()));
  }

  private async schedule_now(): Promise<void> {
    if (!this.store || !this.last_fetch_ref) return;
    const store = this.store;
    const last_ref = this.last_fetch_ref;
    const cfg = this.cfg();
    const do_state = this.state;
    await this.run(
      Effect.catchAll(
        Effect.gen(function* () {
          const room = yield* store.get_room();
          const last = yield* Ref.get(last_ref);
          yield* schedule_alarm(do_state, next_wake_ms(room, last, cfg.poll_ms));
        }),
        () => Effect.void,
      ),
    );
  }

  private refresh_later(): void {
    if (!this.store || !this.last_fetch_ref) return;
    const store = this.store;
    const last_ref = this.last_fetch_ref;
    const cfg = this.cfg();
    const prog = refresh_revocations(() => store.get_room(), last_ref, () => Date.now()).pipe(
      Effect.provide(Layer.mergeAll(RevocationLive, Layer.succeed(RelayEnv, cfg))),
      Effect.provide(HttpLive),
    );
    this.state.waitUntil(this.run(Effect.catchAll(prog, () => Effect.void)));
  }

  async fetch(req: Request): Promise<Response> {
    await this.ready;
    const store = this.get_store();
    const url = new URL(req.url);
    const m = url.pathname.match(/^\/room\/([^/]+)\/([^/]+)$/);
    if (m && req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      const [, account = "", machine = ""] = m;
      if (!ID_RE.test(account) || !ID_RE.test(machine)) {
        return new Response("bad room id", { status: 400 });
      }
      const live = this.live_map();
      const socket_for = (id: string) => this.adapter_for(live, id);
      const loaded = await this.run(
        Effect.match(store.ensure_loaded(socket_for), {
          onFailure: () => "storage-failed" as const,
          onSuccess: (r) => r as RoomState | null | "storage-failed",
        }),
      );
      if (loaded === "storage-failed") {
        return new Response("storage unavailable", { status: 500 });
      }
      const room_check = loaded;
      if (room_check && (room_check.account !== account || room_check.machine !== machine)) {
        return new Response("room mismatch", { status: 400 });
      }
      let room = room_check;
      if (!room) {
        if (!this.verify_fn) return new Response("storage unavailable", { status: 500 });
        const fresh = new RoomState(account, machine, this.verify_fn, () => Date.now());
        await this.run(store.set_fresh_room(fresh));
        room = fresh;
      }
      void room;
      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      const conn = crypto.randomUUID();
      this.state.acceptWebSocket(server);
      server.serializeAttachment({ conn } satisfies Attachment);
      const live_after = this.live_map();
      const adapter = this.adapter_for(live_after, conn) ?? {
        send: (d: string) => (server as unknown as WebSocket).send(d),
        close: (c?: number, r?: string) => (server as unknown as WebSocket).close(c, r),
      };
      const current = await this.run(store.get_room());
      current?.onConnect(conn, adapter);
      this.flush_later();
      this.refresh_later();
      await this.schedule_now();
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/presence") {
      const live = this.live_map();
      const socket_for = (id: string) => this.adapter_for(live, id);
      const room = await this.run(
        Effect.match(store.ensure_loaded(socket_for), {
          onFailure: () => "storage-failed" as const,
          onSuccess: (r) => r as RoomState | null | "storage-failed",
        }),
      );
      if (room === "storage-failed") {
        return Response.json({ error: "storage unavailable" }, { status: 500 });
      }
      if (!room) return Response.json({ v: 1, forge_online: false, clients: 0 });
      return Response.json({ v: 1, ...room.presence() });
    }
    return new Response("not found", { status: 404 });
  }

  async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer): Promise<void> {
    await this.ready;
    const store = this.get_store();
    const att = ws.deserializeAttachment() as Attachment | null;
    if (!att) {
      try {
        ws.close(4401, "gone");
      } catch { /* expected: socket gone, best effort */ }
      return;
    }
    const live = this.live_map();
    const existing = await this.run(store.get_room());
    if (!existing) {
      const loaded = await this.run(
        Effect.match(store.ensure_loaded((id) => this.adapter_for(live, id)), {
          onFailure: () => "storage-failed" as const,
          onSuccess: (r) => r as RoomState | null | "storage-failed",
        }),
      );
      if (loaded === "storage-failed") {
        try {
          ws.close(1011, "storage-unavailable");
        } catch { /* expected: socket gone, best effort */ }
        return;
      }
      if (loaded === null) {
        try {
          ws.close(4401, "gone");
        } catch { /* expected: socket gone, best effort */ }
        return;
      }
    }
    const current = await this.run(store.get_room());
    if (!current) {
      try {
        ws.close(4401, "gone");
      } catch { /* expected: socket gone, best effort */ }
      return;
    }
    if (!current.hasConn(att.conn)) {
      const adapter = this.adapter_for(live, att.conn) ?? {
        send: (d: string) => ws.send(d),
        close: (c?: number, r?: string) => ws.close(c, r),
      };
      current.onConnect(att.conn, adapter);
    }
    await current.onMessage(att.conn, msg);
    this.flush_later();
    await this.schedule_now();
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    await this.ready;
    const store = this.get_store();
    const att = ws.deserializeAttachment() as Attachment | null;
    if (!att) return;
    const live = this.live_map();
    const existing = await this.run(store.get_room());
    if (!existing) {
      await this.run(
        Effect.match(store.ensure_loaded((id) => this.adapter_for(live, id)), {
          onFailure: () => null,
          onSuccess: () => null,
        }),
      );
    }
    const current = await this.run(store.get_room());
    current?.onClose(att.conn);
    this.flush_later();
    await this.schedule_now();
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.ready;
    const store = this.get_store();
    const att = ws.deserializeAttachment() as Attachment | null;
    if (att) {
      const live = this.live_map();
      const existing = await this.run(store.get_room());
      if (!existing) {
        await this.run(
          Effect.match(store.ensure_loaded((id) => this.adapter_for(live, id)), {
            onFailure: () => null,
            onSuccess: () => null,
          }),
        );
      }
      const current = await this.run(store.get_room());
      current?.onClose(att.conn);
    }
    try {
      ws.close(1011, "error");
    } catch { /* expected: socket gone, best effort */ }
    this.flush_later();
    await this.schedule_now();
  }

  async alarm(): Promise<void> {
    await this.ready;
    const store = this.get_store();
    const live = this.live_map();
    const existing = await this.run(store.get_room());
    if (!existing) {
      const loaded = await this.run(
        Effect.match(store.ensure_loaded((id) => this.adapter_for(live, id)), {
          onFailure: () => "storage-failed" as const,
          onSuccess: (r) => r as RoomState | null | "storage-failed",
        }),
      );
      if (loaded === "storage-failed") {
        await this.run(
          Effect.match(
            Effect.tryPromise({
              try: () => this.state.storage.setAlarm(Date.now() + 30_000),
              catch: () => "alarm-failed" as const,
            }),
            { onFailure: () => Effect.void, onSuccess: () => Effect.void },
          ),
        );
        return;
      }
    }
    if (this.store && this.last_fetch_ref) {
      const store_ref = this.store;
      const last_ref = this.last_fetch_ref;
      const cfg = this.cfg();
      const prog = refresh_revocations(() => store_ref.get_room(), last_ref, () => Date.now()).pipe(
        Effect.provide(Layer.mergeAll(RevocationLive, Layer.succeed(RelayEnv, cfg))),
        Effect.provide(HttpLive),
      );
      await this.run(Effect.catchAll(prog, () => Effect.void));
    }
    const current = await this.run(store.get_room());
    current?.tick();
    this.flush_later();
    await this.schedule_now();
  }
}
