// Cloudflare Workers entry: routes, JWKS-backed grant verification,
// admin revocation push, authenticated presence reads. WS upgrades are
// handed to the per-{account,machine} Durable Object. No thread/application
// state here.
//
// Hibernation model (the DO may evict this instance at any time):
// - Room binding + membership + channel/seq/ack state persist in DO
//   storage (RoomSnapshot). On any wake (fetch/message/close/alarm) the
//   instance reloads and re-attaches live hibernated sockets.
// - Challenge nonces never persist (short-lived); challenged sockets
//   re-hello after a wake. JWTs never persist (bearer secrets).
// - Alarms fire ONLY when nextDeadlineMs() is non-null (no idle wakes).

import { RoomState } from "./room.ts";
import type { RoomSnapshot, RoomSocket, VerifyGrant } from "./room.ts";
import { createGrantVerifier, hasScope } from "./jwt.ts";
import { REVOCATION_POLL_MS, fetchRevocations } from "./revocations.ts";
import { corsPreflight, corsResponseHeaders, normalizePortalOrigin, wsOriginGate } from "./cors.ts";

export interface Env {
  MACHINE_ROOM: DurableObjectNamespace;
  CORE_JWKS_URL: string;
  CORE_ISS: string;
  RELAY_AUD?: string;
  GRANT_MAX_TTL_S?: string;
  /**
   * Core revocation list endpoint. Defaults to
   * `${CORE_ISS}/v1/grants/revocations` (assumption for Core to confirm).
   */
  CORE_REVOCATIONS_URL?: string;
  /** Revocation poll interval ms (default 60000, min 1000). */
  REVOCATION_POLL_MS?: string;
  /**
   * Exact account-portal origin allowed cross-origin browser access
   * (e.g. `https://core.artisanstreet.dev`), for CORS on presence/version
   * and the WebSocket-upgrade Origin check. Unset/invalid => no CORS
   * headers and no Origin gate (same-origin + native clients unaffected).
   */
  RELAY_PORTAL_ORIGIN?: string;
}

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const SNAP_KEY = "relay:room:v1";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function verifierFor(env: Env, fetchImpl?: typeof fetch): VerifyGrant {
  if (!env.CORE_JWKS_URL || !env.CORE_ISS) throw new Error("relay misconfigured");
  return createGrantVerifier({
    jwksUrl: env.CORE_JWKS_URL,
    expectedIss: env.CORE_ISS,
    expectedAud: env.RELAY_AUD ?? "ast-relay",
    maxTtlSec: Number(env.GRANT_MAX_TTL_S ?? 300),
  }, fetchImpl);
}

function roomId(ns: DurableObjectNamespace, account: string, machine: string) {
  return ns.idFromName(`${account}/${machine}`);
}

function bearer(req: Request): string | null {
  const h = req.headers.get("Authorization");
  if (!h) return null;
  const m = h.match(/^Bearer (.+)$/);
  return m?.[1] ? m[1].trim() : null;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    const portalOrigin = normalizePortalOrigin(env.RELAY_PORTAL_ORIGIN);

    // Browser preflight for the CORS-enabled routes (presence reads carry
    // `Authorization`, so cross-origin portals preflight). Nothing else
    // answers OPTIONS.
    const preflight = corsPreflight(req, /^\/(v1\/presence\/[^/]+\/[^/]+|v1\/health)$/, portalOrigin);
    if (preflight) return preflight;

    /** Attach CORS headers where they apply; Vary always (cache safety). */
    const withCors = (res: Response): Response => {
      const out = new Response(res.body, res);
      out.headers.set("Vary", "Origin");
      const h = corsResponseHeaders(req, portalOrigin);
      if (h) {
        out.headers.set("Access-Control-Allow-Origin", h.get("Access-Control-Allow-Origin") as string);
      }
      return out;
    };

    if (req.method === "GET" && path === "/v1/health") {
      return withCors(json({ ok: true, service: "artisan-relay", v: 1 }));
    }

    const route = path.match(/^\/v1\/route\/([^/]+)\/([^/]+)$/);
    if (route) {
      const [, account = "", machine = ""] = route;
      if (!ID_RE.test(account) || !ID_RE.test(machine)) {
        return json({ error: "bad room id" }, 400);
      }
      if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return json({ error: "websocket required" }, 426);
      }
      // Browser upgrades carry Origin; native clients send none. When a
      // portal origin is configured, a mismatched Origin is refused here
      // (403 JSON, pre-upgrade). Absent Origin always proceeds to
      // grant+PoP admission below.
      const gate = wsOriginGate(req, portalOrigin);
      if (gate) return gate;
      const stub = env.MACHINE_ROOM.get(roomId(env.MACHINE_ROOM, account, machine));
      return stub.fetch(`https://relay/room/${account}/${machine}`, { headers: req.headers });
    }

    // Presence is account activity data: requires a Bearer grant for the
    // SAME account+machine (any role with relay:connect). No token -> 401;
    // wrong room binding -> 403. Never leaks across accounts.
    const presence = path.match(/^\/v1\/presence\/([^/]+)\/([^/]+)$/);
    if (presence && req.method === "GET") {
      const [, account = "", machine = ""] = presence;
      if (!ID_RE.test(account) || !ID_RE.test(machine)) {
        return withCors(json({ error: "bad room id" }, 400));
      }
      const token = bearer(req);
      if (!token) return withCors(json({ error: "bearer grant required" }, 401));
      let grant;
      try {
        grant = await verifierFor(env)(token);
      } catch {
        return withCors(json({ error: "bad grant" }, 401));
      }
      if (grant.claims.sub !== account || grant.claims.mid !== machine) {
        return withCors(json({ error: "forbidden" }, 403));
      }
      if (!hasScope(grant, "relay:connect")) return withCors(json({ error: "forbidden" }, 403));
      const stub = env.MACHINE_ROOM.get(roomId(env.MACHINE_ROOM, account, machine));
      return withCors(await stub.fetch(`https://relay/presence`));
    }

    if (req.method === "POST" && path === "/v1/admin/revocations") {
      // Removed: Core v1 has no admin push (authoritative contracts.md §4).
      // Revocation is short expiry + the polled /v1/grants/revocations list.
      return json({ error: "gone: revocation is poll-based, see contracts/grant.md" }, 410);
    }

    const revRoom = path.match(/^\/v1\/admin\/revocations\/([^/]+)\/([^/]+)$/);
    if (revRoom && req.method === "POST") {
      return json({ error: "gone: revocation is poll-based, see contracts/grant.md" }, 410);
    }

    return json({ error: "not found" }, 404);
  },
} satisfies ExportedHandler<Env>;

// ---------------------------------------------------------------------------
// Durable Object: hibernatable WebSockets, one room per {account,machine}.
// ---------------------------------------------------------------------------

interface Attachment {
  conn: string;
}

export class MachineRoom implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private verify: VerifyGrant;
  private room: RoomState | null = null;
  private lastRevFetch = 0;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.verify = verifierFor(env);
  }

  /** Load persisted state (if any) and re-attach live sockets. Shared
   *  across concurrent events: the load runs once per instance; concurrent
   *  waiters share the promise (no double restore).
   *
   *  Storage FAILURE is never converted to null: null means "absent
   *  snapshot" (safe to start fresh); an error means "unknown" (must fail
   *  closed, never create a fresh room that would drop authority for live
   *  sockets or overwrite the good snapshot). The shared promise resets on
   *  failure so later events retry the load. */
  private loadPromise: Promise<RoomState | null> | null = null;

  private async ensureLoaded(): Promise<RoomState | null> {
    if (this.room) return this.room;
    if (!this.loadPromise) {
      this.loadPromise = this.doLoad().then(
        (r) => r,
        (e: unknown) => {
          this.loadPromise = null;
          throw e;
        },
      );
    }
    return this.loadPromise;
  }

  private async doLoad(): Promise<RoomState | null> {
    const snap = await this.state.storage.get<RoomSnapshot>(SNAP_KEY);
    if (!snap) return null;
    const room = new RoomState(snap.account, snap.machine, this.verify, () => Date.now());
    room.restore(snap, (connId) => this.adapterFor(connId));
    this.room = room;
    return room;
  }

  private liveSockets(): Map<string, WebSocket> {
    const live = new Map<string, WebSocket>();
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (att) live.set(att.conn, ws);
    }
    return live;
  }

  private adapterFor(connId: string): RoomSocket | null {
    const ws = this.liveSockets().get(connId);
    if (!ws) return null;
    return {
      send: (data: string) => ws.send(data),
      close: (code?: number, reason?: string) => ws.close(code, reason),
    };
  }

  private persist(): Promise<void> {
    // Chained so concurrent flushes cannot interleave a stale snapshot
    // after a fresh one (each pass re-checks dirtiness).
    const run = this.persistChain.then(() => this.persistOnce());
    this.persistChain = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  private persistChain: Promise<void> = Promise.resolve();

  private async persistOnce(): Promise<void> {
    for (let i = 0; i < 4; i++) {
      if (!this.room || !this.room.isDirty()) return;
      this.room.clearDirty();
      const snap = this.room.snapshot();
      try {
        await this.state.storage.put(SNAP_KEY, snap);
      } catch {
        // Save failed: restore dirtiness so a later flush retries.
        // The chain alone orders passes; it cannot recover a lost save.
        this.room?.markDirty();
        return;
      }
    }
  }

  private flush(): void {
    this.state.waitUntil(this.persist());
  }

  /** Refresh the Core revocation list when the poll interval elapsed. */
  private async refreshRevocations(): Promise<void> {
    const now = Date.now();
    if (now - this.lastRevFetch < this.pollMs()) return;
    this.lastRevFetch = now;
    try {
      const list = await fetchRevocations(this.env);
      this.room?.setRevocations(list.machines, list.keys);
    } catch {
      // Fetch failures fail OPEN on the poll (stale list) but grants still
      // expire on their own TTL: fail-closed overall. Next alarm retries.
    }
  }

  /** Set the next alarm exactly when needed, or delete it when idle. */
  private async schedule(): Promise<void> {
    const roomNext = this.room?.nextDeadlineMs() ?? null;
    // Bound revocation staleness: if the room has members, wake at the
    // next poll boundary even when nothing else is due.
    let next = roomNext;
    if (this.room && (this.room.presence().clients > 0 || this.room.presence().forge_online)) {
      const pollAt = this.lastRevFetch + this.pollMs();
      next = next === null ? pollAt : Math.min(next, pollAt);
    }
    try {
      if (next === null) {
        await this.state.storage.deleteAlarm();
      } else {
        await this.state.storage.setAlarm(next);
      }
    } catch { /* alarms unavailable in some dev modes */ }
  }

  private pollMs(): number {
    const v = Number(this.env.REVOCATION_POLL_MS ?? REVOCATION_POLL_MS);
    return Number.isFinite(v) && v >= 1000 ? v : REVOCATION_POLL_MS;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const m = url.pathname.match(/^\/room\/([^/]+)\/([^/]+)$/);
    if (m && req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      const [, account = "", machine = ""] = m;
      if (!ID_RE.test(account) || !ID_RE.test(machine)) {
        return new Response("bad room id", { status: 400 });
      }
      // Restore first: a new connection arriving after hibernation must NOT
      // discard surviving authenticated members/channels (previous bug:
      // forRoom() built a fresh empty room here). Mismatch (should not
      // happen: DO id space is per-room) is a 400, never a clobber.
      // Storage failure is a 500: never create a fresh room on a failed
      // read — it would drop authority for live sockets and let the next
      // persist overwrite the good snapshot with an empty room.
      let loaded: RoomState | null;
      try {
        loaded = await this.ensureLoaded();
      } catch {
        return new Response("storage unavailable", { status: 500 });
      }
      let room: RoomState | null = null;
      if (loaded && (loaded.account !== account || loaded.machine !== machine)) {
        return new Response("room mismatch", { status: 400 });
      }
      room = loaded ?? new RoomState(account, machine, this.verify, () => Date.now());
      if (!loaded) this.room = room;
      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      const conn = crypto.randomUUID();
      this.state.acceptWebSocket(server);
      server.serializeAttachment({ conn } satisfies Attachment);
      room.onConnect(conn, server as unknown as RoomSocket);
      this.flush();
      // Background revocation refresh (stale-while-revalidate): the first
      // hello checks the last-known list without blocking on a fetch.
      this.state.waitUntil(this.refreshRevocations());
      await this.schedule();
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/presence") {
      let room: RoomState | null;
      try {
        room = await this.ensureLoaded();
      } catch {
        return Response.json({ error: "storage unavailable" }, { status: 500 });
      }
      if (!room) return Response.json({ v: 1, forge_online: false, clients: 0 });
      return Response.json({ v: 1, ...room.presence() });
    }
    return new Response("not found", { status: 404 });
  }

  async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer): Promise<void> {
    const att = ws.deserializeAttachment() as Attachment | null;
    if (!att) {
      try { ws.close(4401, "gone"); } catch { /* ignore */ }
      return;
    }
    if (!this.room) {
      // Wake path: reload the snapshot and re-attach live sockets.
      // Storage failure fails CLOSED (1011): no fresh room, no message
      // processing, no authority change. The client reconnects.
      try {
        await this.ensureLoaded();
      } catch {
        try { ws.close(1011, "storage-unavailable"); } catch { /* ignore */ }
        return;
      }
    }
    if (!this.room) {
      try { ws.close(4401, "gone"); } catch { /* ignore */ }
      return;
    }
    if (!this.room.hasConn(att.conn)) {
      // Unknown socket (was pending/challenged at eviction, or arrived
      // after): require a fresh hello within the normal timeout.
      const adapter = this.adapterFor(att.conn) ?? {
        send: (d: string) => ws.send(d),
        close: (c?: number, r?: string) => ws.close(c, r),
      };
      this.room.onConnect(att.conn, adapter);
    }
    await this.room.onMessage(att.conn, msg);
    this.flush();
    await this.schedule();
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    const att = ws.deserializeAttachment() as Attachment | null;
    if (!att) return;
    if (!this.room) {
      // Wake on close: still need cleanup so channels don't go stale.
      // Best effort: a storage failure leaves the persisted record for
      // the next successful load to sweep (restore drops socketless conns).
      try {
        await this.ensureLoaded();
      } catch { /* ignore */ }
    }
    this.room?.onClose(att.conn);
    this.flush();
    await this.schedule();
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    const att = ws.deserializeAttachment() as Attachment | null;
    if (att) {
      if (!this.room) {
        try {
          await this.ensureLoaded();
        } catch { /* ignore */ }
      }
      this.room?.onClose(att.conn);
    }
    try { ws.close(1011, "error"); } catch { /* ignore */ }
    this.flush();
    await this.schedule();
  }

  async alarm(): Promise<void> {
    if (!this.room) {
      try {
        await this.ensureLoaded();
      } catch {
        // Retry later: without state there is nothing to sweep, but the
        // next alarm must still happen (no silent stall).
        try {
          await this.state.storage.setAlarm(Date.now() + 30_000);
        } catch { /* ignore */ }
        return;
      }
    }
    try {
      await this.refreshRevocations();
      this.room?.tick();
      this.flush();
      await this.schedule();
    } catch { /* ignore */ }
  }
}
