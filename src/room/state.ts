import {
  decode_client_frame,
  encode_server_frame,
} from "../schema.ts";
import type { ClientFrame } from "../schema.ts";
import { b64u_decode, b64u_encode } from "../b64u.ts";
import { Either } from "effect";
import type { VerifiedGrant } from "../services/grants/verifier.ts";
import {
  CLOSE_AUTH,
  CLOSE_FORBIDDEN,
  CLOSE_POLICY,
  CLOSE_REPLACED,
  CLOSE_REVOKED,
  HELLO_TIMEOUT_MS,
  MAX_BODY_B64,
  MAX_CHANNELS,
  MAX_CLIENTS,
  MAX_REVOKED_JTIS,
  PING_INTERVAL_MS,
  PONG_TIMEOUT_MS,
} from "./limits.ts";
import type {
  AuthedConn,
  NowMs,
  RoomCore,
  RoomEvents,
  RoomIo,
  RoomSnapshot,
} from "./types.ts";
import type { RoomSocket } from "./types.ts";
import { admit_authenticate, admit_hello } from "./admission.ts";
import {
  authed_conn,
  channel_close,
  channel_open,
  close_channel,
  handle_ack,
  route_data,
} from "./channels.ts";
import { matches_revoked_keys } from "./revocation.ts";
import { is_revoked } from "./revocation.ts";
import { restored_grant } from "./snapshot.ts";

export {
  CHALLENGE_TTL_MS,
  CLOSE_AUTH,
  CLOSE_BACKPRESSURE,
  CLOSE_FORBIDDEN,
  CLOSE_POLICY,
  CLOSE_REPLACED,
  CLOSE_REVOKED,
  HELLO_TIMEOUT_MS,
  MAX_BODY_B64,
  MAX_CHANNELS,
  MAX_CLIENTS,
  MAX_REVOKED_JTIS,
  MAX_UNACKED_BYTES,
  MAX_UNACKED_FRAMES,
  PING_INTERVAL_MS,
  PONG_TIMEOUT_MS,
} from "./limits.ts";
export type { AckWindow, NowMs, RoomEvents, RoomSnapshot, RoomSocket, SnapshotChannel, SnapshotConn } from "./types.ts";

export type VerifyGrant = (jwt: string, now_sec?: number) => Promise<VerifiedGrant>;

function err(code: string, message: string): string {
  return encode_server_frame({ v: 1, type: "error", code, message });
}

function safe_send(s: RoomSocket | undefined, data: string): boolean {
  if (!s) return false;
  return Either.try({ try: () => s.send(data), catch: () => false }).pipe(
    Either.match({ onLeft: () => false, onRight: () => true }),
  );
}

export class RoomState {
  readonly account: string;
  readonly machine: string;
  private core: RoomCore;
  private io: RoomIo;

  constructor(
    account: string,
    machine: string,
    verify: VerifyGrant,
    now: NowMs = () => Date.now(),
    events: RoomEvents = {},
  ) {
    this.account = account;
    this.machine = machine;
    const core: RoomCore = {
      account,
      machine,
      verify,
      now,
      events,
      forge: null,
      clients: new Map(),
      pending: new Map(),
      challenges: new Map(),
      channels: new Map(),
      used_jti: new Map(),
      revoked_machines: new Set(),
      revoked_keys: new Set(),
    };
    this.core = core;
    const self = this;
    this.io = {
      send_to(conn_id: string, data: string): void {
        safe_send(self.socket_of(conn_id), data);
      },
      drop(conn_id: string, code: number, reason: string): void {
        self.drop_conn(conn_id, code, reason);
      },
      remove_conn(conn_id: string): boolean {
        return self.remove_conn(conn_id);
      },
      close_channel(channel: string, gone_conn_id: string, reason: string): void {
        close_channel(self.core, self.io, channel, gone_conn_id, reason);
      },
      broadcast_presence(): void {
        self.broadcast_presence();
      },
      mark_dirty(): void {
        self.mark_dirty();
      },
    };
  }

  on_connect(conn_id: string, socket: RoomSocket): void {
    this.core.pending.set(conn_id, { socket, deadline: this.core.now() + HELLO_TIMEOUT_MS });
  }

  async on_message(conn_id: string, raw: string | ArrayBuffer): Promise<void> {
    const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
    if (text.length > MAX_BODY_B64 + 1024) {
      this.drop_conn(conn_id, CLOSE_POLICY, "frame-too-large");
      return;
    }
    // JSON.parse never yields undefined on success, so undefined here
    // unambiguously signals a parse rejection (not a wire value).
    const parsed = Either.getOrElse(
      Either.try({ try: () => JSON.parse(text) as unknown, catch: () => undefined }),
      () => undefined,
    );
    if (parsed === undefined) {
      this.io.send_to(conn_id, err("malformed", "frame is not JSON"));
      this.drop_conn(conn_id, CLOSE_POLICY, "malformed");
      return;
    }
    const frame = Either.getOrElse(
      Either.try({ try: () => decode_client_frame(parsed), catch: () => undefined }),
      () => undefined,
    );
    if (frame === undefined) {
      this.io.send_to(conn_id, err("invalid-frame", "unknown fields or bad shape"));
      this.drop_conn(conn_id, CLOSE_POLICY, "invalid-frame");
      return;
    }

    if (this.core.pending.has(conn_id) && !this.core.challenges.has(conn_id)) {
      if (frame.type !== "hello") {
        this.io.send_to(conn_id, err("auth-required", "first frame must be hello"));
        this.drop_conn(conn_id, CLOSE_AUTH, "auth-required");
        return;
      }
      await admit_hello(this.core, this.io, conn_id, frame.grant);
      return;
    }
    if (this.core.challenges.has(conn_id)) {
      if (frame.type !== "authenticate") {
        this.io.send_to(conn_id, err("auth-required", "expected authenticate"));
        this.drop_conn(conn_id, CLOSE_AUTH, "auth-required");
        return;
      }
      admit_authenticate(this.core, this.io, conn_id, frame.jti, frame.sig);
      return;
    }
    await this.handle_authed(conn_id, frame);
  }

  on_close(conn_id: string): void {
    this.remove_conn(conn_id);
  }

  has_conn(conn_id: string): boolean {
    return (
      this.core.pending.has(conn_id) ||
      this.core.challenges.has(conn_id) ||
      this.core.forge?.conn_id === conn_id ||
      this.core.clients.has(conn_id)
    );
  }

  private remove_conn(conn_id: string): boolean {
    const core = this.core;
    core.pending.delete(conn_id);
    core.challenges.delete(conn_id);
    let changed = false;
    if (core.forge?.conn_id === conn_id) {
      core.forge = null;
      changed = true;
      core.events.on_forge_presence?.(false);
      for (const ch of [...core.channels.keys()]) close_channel(core, this.io, ch, conn_id, "forge-offline");
    }
    if (core.clients.has(conn_id)) {
      core.clients.delete(conn_id);
      changed = true;
      for (const [ch, st] of [...core.channels]) {
        if (st.owner === conn_id) close_channel(core, this.io, ch, conn_id, "client-gone");
      }
    }
    if (changed) this.broadcast_presence();
    return changed;
  }

  private socket_of(conn_id: string): RoomSocket | undefined {
    if (this.core.forge?.conn_id === conn_id) return this.core.forge.socket;
    return this.core.clients.get(conn_id)?.socket ?? this.core.pending.get(conn_id)?.socket;
  }

  private drop_conn(conn_id: string, code: number, reason: string): void {
    const s = this.socket_of(conn_id);
    this.remove_conn(conn_id);
    if (s) void Either.try({ try: () => s.close(code, reason), catch: () => undefined });
  }

  private send_to_forge(data: string): void {
    if (this.core.forge) safe_send(this.core.forge.socket, data);
  }

  private broadcast_presence(): void {
    const msg = encode_server_frame({
      v: 1,
      type: "presence",
      forge_online: this.core.forge !== null,
      clients: this.core.clients.size,
    });
    if (this.core.forge) safe_send(this.core.forge.socket, msg);
    for (const c of this.core.clients.values()) safe_send(c.socket, msg);
  }

  private async handle_authed(conn_id: string, frame: ClientFrame): Promise<void> {
    const found = authed_conn(this.core, conn_id);
    if (!found) {
      this.io.send_to(conn_id, err("auth-required", "unknown connection"));
      this.drop_conn(conn_id, CLOSE_AUTH, "auth-required");
      return;
    }
    if (Math.floor(this.core.now() / 1000) >= found.conn.exp_sec) {
      this.io.send_to(conn_id, err("grant-expired", "grant expired"));
      this.drop_conn(conn_id, CLOSE_AUTH, "grant-expired");
      return;
    }
    if (frame.type === "hello" || frame.type === "authenticate") {
      this.io.send_to(conn_id, err("invalid", "already authenticated"));
      return;
    }
    switch (frame.type) {
      case "open": {
        channel_open(this.core, this.io, conn_id, found, frame.channel);
        return;
      }
      case "data": {
        route_data(this.core, this.io, conn_id, found.is_forge, frame);
        return;
      }
      case "ack": {
        handle_ack(this.core, this.io, conn_id, found.is_forge, frame.channel, frame.seq);
        return;
      }
      case "close": {
        channel_close(this.core, this.io, conn_id, found.is_forge, frame.channel, frame.reason);
        return;
      }
      case "pong": {
        found.conn.last_pong = this.core.now();
        return;
      }
    }
  }

  private is_revoked(grant: VerifiedGrant): boolean {
    return is_revoked(grant, this.core.revoked_machines, this.core.revoked_keys);
  }

  set_revocations(machines: string[], keys: string[]): boolean {
    const cap = (arr: string[]) => arr.slice(0, MAX_REVOKED_JTIS);
    const nm = new Set(cap(machines));
    const nk = new Set(cap(keys));
    const changed = nm.size !== this.core.revoked_machines.size || nk.size !== this.core.revoked_keys.size ||
      [...nm].some((x) => !this.core.revoked_machines.has(x)) || [...nk].some((x) => !this.core.revoked_keys.has(x));
    this.core.revoked_machines = nm;
    this.core.revoked_keys = nk;
    this.mark_dirty();
    this.sweep_revocations();
    return changed;
  }

  private sweep_revocations(): void {
    if (this.core.forge && this.is_revoked(this.core.forge.grant)) {
      const id = this.core.forge.conn_id;
      this.io.send_to(id, err("revoked", "grant revoked"));
      this.drop_conn(id, CLOSE_REVOKED, "revoked");
    }
    for (const [id, c] of [...this.core.clients]) {
      if (this.is_revoked(c.grant)) {
        this.io.send_to(id, err("revoked", "grant revoked"));
        this.drop_conn(id, CLOSE_REVOKED, "revoked");
      }
    }
  }

  tick(): void {
    const core = this.core;
    const now = core.now();
    const now_sec = Math.floor(now / 1000);
    for (const [id, p] of [...core.pending]) {
      if (!core.challenges.has(id) && now > p.deadline) {
        this.io.send_to(id, err("timeout", "hello not received in time"));
        this.drop_conn(id, CLOSE_AUTH, "hello-timeout");
      }
    }
    for (const [id, ch] of [...core.challenges]) {
      if (now > ch.expires_at) {
        core.challenges.delete(id);
        this.io.send_to(id, err("timeout", "authenticate not received in time"));
        this.drop_conn(id, CLOSE_AUTH, "challenge-timeout");
      }
    }
    if (core.forge && now_sec >= core.forge.exp_sec) {
      const id = core.forge.conn_id;
      this.io.send_to(id, err("grant-expired", "grant expired"));
      this.drop_conn(id, CLOSE_AUTH, "grant-expired");
    }
    for (const [id, c] of [...core.clients]) {
      if (now_sec >= c.exp_sec) {
        this.io.send_to(id, err("grant-expired", "grant expired"));
        this.drop_conn(id, CLOSE_AUTH, "grant-expired");
      }
    }
    this.sweep_revocations();
    const ping = encode_server_frame({ v: 1, type: "ping", t: now });
    const check = (id: string, c: AuthedConn) => {
      if (now - c.last_pong > PONG_TIMEOUT_MS) {
        this.io.send_to(id, err("timeout", "heartbeat lost"));
        this.drop_conn(id, CLOSE_POLICY, "heartbeat-timeout");
        return;
      }
      if (now - c.last_ping_sent >= PING_INTERVAL_MS) {
        c.last_ping_sent = now;
        safe_send(c.socket, ping);
      }
    };
    if (core.forge) check(core.forge.conn_id, core.forge);
    for (const [id, c] of [...core.clients]) check(id, c);
  }

  next_deadline_ms(): number | null {
    let next: number | null = null;
    const consider = (t: number) => {
      if (next === null || t < next) next = t;
    };
    const now = this.core.now();
    for (const p of this.core.pending.values()) consider(p.deadline);
    for (const ch of this.core.challenges.values()) consider(ch.expires_at);
    const conns: AuthedConn[] = [
      ...(this.core.forge ? [this.core.forge] : []),
      ...this.core.clients.values(),
    ];
    for (const c of conns) {
      consider(c.exp_sec * 1000);
      consider(c.last_pong + PONG_TIMEOUT_MS);
      consider(c.last_ping_sent + PING_INTERVAL_MS);
    }
    if (next !== null && next < now) return now;
    return next;
  }

  presence(): { forge_online: boolean; clients: number } {
    return { forge_online: this.core.forge !== null, clients: this.core.clients.size };
  }

  private dirty = false;

  is_dirty(): boolean {
    return this.dirty;
  }

  mark_dirty(): void {
    this.dirty = true;
  }

  clear_dirty(): void {
    this.dirty = false;
  }

  snapshot(): RoomSnapshot {
    const core = this.core;
    return {
      v: 1,
      account: this.account,
      machine: this.machine,
      revokedMachines: [...core.revoked_machines],
      revokedKeys: [...core.revoked_keys],
      usedJti: [...core.used_jti],
      conns: [
        ...(core.forge
          ? [{
              conn: core.forge.conn_id,
              role: "forge" as const,
              jti: core.forge.grant.claims.jti,
              exp: core.forge.exp_sec,
              kid: core.forge.grant.kid,
              cnfX: b64u_encode(core.forge.grant.cnf_pk),
              scope: [...core.forge.grant.claims.scope],
            }]
          : []),
        ...[...core.clients].map(([conn, c]) => ({
          conn,
          role: "client" as const,
          jti: c.grant.claims.jti,
          exp: c.exp_sec,
          kid: c.grant.kid,
          cnfX: b64u_encode(c.grant.cnf_pk),
          scope: [...c.grant.claims.scope],
        })),
      ],
      channels: [...core.channels].map(([name, st]) => ({
        name,
        owner: st.owner,
        lastClientSeq: st.last_client_seq,
        lastForgeSeq: st.last_forge_seq,
        toForge: {
          sentHigh: st.to_forge.sent_high,
          ackedHigh: st.to_forge.acked_high,
          sizes: [...st.to_forge.sizes],
          unackedBytes: st.to_forge.unacked_bytes,
        },
        toClient: {
          sentHigh: st.to_client.sent_high,
          ackedHigh: st.to_client.acked_high,
          sizes: [...st.to_client.sizes],
          unackedBytes: st.to_client.unacked_bytes,
        },
      })),
    };
  }

  restore(snap: RoomSnapshot, socket_for: (conn_id: string) => RoomSocket | null): { restored: number; dropped: number } {
    if (snap.v !== 1 || snap.account !== this.account || snap.machine !== this.machine) {
      throw new Error("snapshot mismatch");
    }
    const core = this.core;
    const now_sec = Math.floor(core.now() / 1000);
    core.revoked_machines = new Set(snap.revokedMachines.slice(0, MAX_REVOKED_JTIS));
    core.revoked_keys = new Set(snap.revokedKeys.slice(0, MAX_REVOKED_JTIS));
    core.used_jti = new Map(snap.usedJti.filter(([, e]) => e >= now_sec));
    const machine_revoked = core.revoked_machines.has(this.machine);
    let restored = 0;
    let dropped = 0;
    const live = new Set<string>();
    for (const c of snap.conns) {
      const sock = socket_for(c.conn);
      if (!sock) {
        dropped++;
        continue;
      }
      type Freshness = { readonly tag: "fresh" } | { readonly tag: "stale"; readonly code: number };
      const freshness: Freshness = c.exp <= now_sec
        ? { tag: "stale", code: CLOSE_AUTH }
        : machine_revoked
          ? { tag: "stale", code: CLOSE_REVOKED }
          : Either.match(Either.try({ try: () => b64u_decode(c.cnfX), catch: () => undefined }), {
              onLeft: (): Freshness => ({ tag: "stale", code: CLOSE_AUTH }),
              onRight: (cnf_pk): Freshness =>
                cnf_pk.length !== 32
                  ? { tag: "stale", code: CLOSE_AUTH }
                  : matches_revoked_keys(c.kid, cnf_pk, core.revoked_keys)
                    ? { tag: "stale", code: CLOSE_REVOKED }
                    : { tag: "fresh" },
            });
      if (freshness.tag === "stale") {
        void Either.try({ try: () => sock.close(freshness.code, "stale"), catch: () => undefined });
        dropped++;
        continue;
      }
      const reattached = restored_grant(this.account, this.machine, c);
      if (!reattached) {
        void Either.try({ try: () => sock.close(CLOSE_AUTH, "stale"), catch: () => undefined });
        dropped++;
        continue;
      }
      const conn: AuthedConn = {
        socket: sock,
        grant: reattached,
        exp_sec: c.exp,
        last_pong: core.now(),
        last_ping_sent: 0,
      };
      if (c.role === "forge") {
        if (core.forge) {
          void Either.try({ try: () => sock.close(CLOSE_REPLACED, "duplicate"), catch: () => undefined });
          dropped++;
          continue;
        }
        core.forge = { ...conn, conn_id: c.conn };
      } else {
        if (core.clients.size >= MAX_CLIENTS) {
          void Either.try({ try: () => sock.close(CLOSE_POLICY, "room-full"), catch: () => undefined });
          dropped++;
          continue;
        }
        core.clients.set(c.conn, conn);
      }
      live.add(c.conn);
      restored++;
    }
    for (const ch of snap.channels) {
      if (core.channels.size >= MAX_CHANNELS) break;
      const owner_live = live.has(ch.owner);
      const forge_live = core.forge !== null;
      if (!owner_live || !forge_live) continue;
      core.channels.set(ch.name, {
        owner: ch.owner,
        last_client_seq: ch.lastClientSeq,
        last_forge_seq: ch.lastForgeSeq,
        to_forge: {
          sent_high: ch.toForge.sentHigh,
          acked_high: ch.toForge.ackedHigh,
          sizes: [...ch.toForge.sizes],
          unacked_bytes: ch.toForge.unackedBytes,
        },
        to_client: {
          sent_high: ch.toClient.sentHigh,
          acked_high: ch.toClient.ackedHigh,
          sizes: [...ch.toClient.sizes],
          unacked_bytes: ch.toClient.unackedBytes,
        },
      });
    }
    this.clear_dirty();
    this.broadcast_presence();
    return { restored, dropped };
  }
}
