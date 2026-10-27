import {
  decodeClientFrame,
  encodeServerFrame,
} from "../schema.ts";
import type { ClientFrame } from "../schema.ts";
import { b64uDecode, b64uEncode } from "../b64u.ts";
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

export type VerifyGrant = (jwt: string, nowSec?: number) => Promise<VerifiedGrant>;

function err(code: string, message: string): string {
  return encodeServerFrame({ v: 1, type: "error", code, message });
}

function safe_send(s: RoomSocket | undefined, data: string): boolean {
  if (!s) return false;
  try {
    s.send(data);
    return true;
  } catch {
    return false;
  }
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
        self.markDirty();
      },
    };
  }

  onConnect(connId: string, socket: RoomSocket): void {
    this.core.pending.set(connId, { socket, deadline: this.core.now() + HELLO_TIMEOUT_MS });
  }

  async onMessage(connId: string, raw: string | ArrayBuffer): Promise<void> {
    const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
    if (text.length > MAX_BODY_B64 + 1024) {
      this.drop_conn(connId, CLOSE_POLICY, "frame-too-large");
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      this.io.send_to(connId, err("malformed", "frame is not JSON"));
      this.drop_conn(connId, CLOSE_POLICY, "malformed");
      return;
    }
    let frame: ClientFrame;
    try {
      frame = decodeClientFrame(parsed);
    } catch {
      this.io.send_to(connId, err("invalid-frame", "unknown fields or bad shape"));
      this.drop_conn(connId, CLOSE_POLICY, "invalid-frame");
      return;
    }

    if (this.core.pending.has(connId) && !this.core.challenges.has(connId)) {
      if (frame.type !== "hello") {
        this.io.send_to(connId, err("auth-required", "first frame must be hello"));
        this.drop_conn(connId, CLOSE_AUTH, "auth-required");
        return;
      }
      await admit_hello(this.core, this.io, connId, frame.grant);
      return;
    }
    if (this.core.challenges.has(connId)) {
      if (frame.type !== "authenticate") {
        this.io.send_to(connId, err("auth-required", "expected authenticate"));
        this.drop_conn(connId, CLOSE_AUTH, "auth-required");
        return;
      }
      admit_authenticate(this.core, this.io, connId, frame.jti, frame.sig);
      return;
    }
    await this.handle_authed(connId, frame);
  }

  onClose(connId: string): void {
    this.remove_conn(connId);
  }

  hasConn(connId: string): boolean {
    return (
      this.core.pending.has(connId) ||
      this.core.challenges.has(connId) ||
      this.core.forge?.connId === connId ||
      this.core.clients.has(connId)
    );
  }

  private remove_conn(connId: string): boolean {
    const core = this.core;
    core.pending.delete(connId);
    core.challenges.delete(connId);
    let changed = false;
    if (core.forge?.connId === connId) {
      core.forge = null;
      changed = true;
      core.events.onForgePresence?.(false);
      for (const ch of [...core.channels.keys()]) close_channel(core, this.io, ch, connId, "forge-offline");
    }
    if (core.clients.has(connId)) {
      core.clients.delete(connId);
      changed = true;
      for (const [ch, st] of [...core.channels]) {
        if (st.owner === connId) close_channel(core, this.io, ch, connId, "client-gone");
      }
    }
    if (changed) this.broadcast_presence();
    return changed;
  }

  private socket_of(connId: string): RoomSocket | undefined {
    if (this.core.forge?.connId === connId) return this.core.forge.socket;
    return this.core.clients.get(connId)?.socket ?? this.core.pending.get(connId)?.socket;
  }

  private drop_conn(connId: string, code: number, reason: string): void {
    const s = this.socket_of(connId);
    this.remove_conn(connId);
    try {
      s?.close(code, reason);
    } catch { /* expected: socket gone, best effort */ }
  }

  private send_to_forge(data: string): void {
    if (this.core.forge) safe_send(this.core.forge.socket, data);
  }

  private broadcast_presence(): void {
    const msg = encodeServerFrame({
      v: 1,
      type: "presence",
      forge_online: this.core.forge !== null,
      clients: this.core.clients.size,
    });
    if (this.core.forge) safe_send(this.core.forge.socket, msg);
    for (const c of this.core.clients.values()) safe_send(c.socket, msg);
  }

  private async handle_authed(connId: string, frame: ClientFrame): Promise<void> {
    const found = authed_conn(this.core, connId);
    if (!found) {
      this.io.send_to(connId, err("auth-required", "unknown connection"));
      this.drop_conn(connId, CLOSE_AUTH, "auth-required");
      return;
    }
    if (Math.floor(this.core.now() / 1000) >= found.conn.expSec) {
      this.io.send_to(connId, err("grant-expired", "grant expired"));
      this.drop_conn(connId, CLOSE_AUTH, "grant-expired");
      return;
    }
    if (frame.type === "hello" || frame.type === "authenticate") {
      this.io.send_to(connId, err("invalid", "already authenticated"));
      return;
    }
    switch (frame.type) {
      case "open": {
        channel_open(this.core, this.io, connId, found, frame.channel);
        return;
      }
      case "data": {
        route_data(this.core, this.io, connId, found.is_forge, frame);
        return;
      }
      case "ack": {
        handle_ack(this.core, this.io, connId, found.is_forge, frame.channel, frame.seq);
        return;
      }
      case "close": {
        channel_close(this.core, this.io, connId, found.is_forge, frame.channel, frame.reason);
        return;
      }
      case "pong": {
        found.conn.lastPong = this.core.now();
        return;
      }
    }
  }

  private is_revoked(grant: VerifiedGrant): boolean {
    return is_revoked(grant, this.core.revoked_machines, this.core.revoked_keys);
  }

  setRevocations(machines: string[], keys: string[]): boolean {
    const cap = (arr: string[]) => arr.slice(0, MAX_REVOKED_JTIS);
    const nm = new Set(cap(machines));
    const nk = new Set(cap(keys));
    const changed = nm.size !== this.core.revoked_machines.size || nk.size !== this.core.revoked_keys.size ||
      [...nm].some((x) => !this.core.revoked_machines.has(x)) || [...nk].some((x) => !this.core.revoked_keys.has(x));
    this.core.revoked_machines = nm;
    this.core.revoked_keys = nk;
    this.markDirty();
    this.sweep_revocations();
    return changed;
  }

  private sweep_revocations(): void {
    if (this.core.forge && this.is_revoked(this.core.forge.grant)) {
      const id = this.core.forge.connId;
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
    const nowSec = Math.floor(now / 1000);
    for (const [id, p] of [...core.pending]) {
      if (!core.challenges.has(id) && now > p.deadline) {
        this.io.send_to(id, err("timeout", "hello not received in time"));
        this.drop_conn(id, CLOSE_AUTH, "hello-timeout");
      }
    }
    for (const [id, ch] of [...core.challenges]) {
      if (now > ch.expiresAt) {
        core.challenges.delete(id);
        this.io.send_to(id, err("timeout", "authenticate not received in time"));
        this.drop_conn(id, CLOSE_AUTH, "challenge-timeout");
      }
    }
    if (core.forge && nowSec >= core.forge.expSec) {
      const id = core.forge.connId;
      this.io.send_to(id, err("grant-expired", "grant expired"));
      this.drop_conn(id, CLOSE_AUTH, "grant-expired");
    }
    for (const [id, c] of [...core.clients]) {
      if (nowSec >= c.expSec) {
        this.io.send_to(id, err("grant-expired", "grant expired"));
        this.drop_conn(id, CLOSE_AUTH, "grant-expired");
      }
    }
    this.sweep_revocations();
    const ping = encodeServerFrame({ v: 1, type: "ping", t: now });
    const check = (id: string, c: AuthedConn) => {
      if (now - c.lastPong > PONG_TIMEOUT_MS) {
        this.io.send_to(id, err("timeout", "heartbeat lost"));
        this.drop_conn(id, CLOSE_POLICY, "heartbeat-timeout");
        return;
      }
      if (now - c.lastPingSent >= PING_INTERVAL_MS) {
        c.lastPingSent = now;
        safe_send(c.socket, ping);
      }
    };
    if (core.forge) check(core.forge.connId, core.forge);
    for (const [id, c] of [...core.clients]) check(id, c);
  }

  nextDeadlineMs(): number | null {
    let next: number | null = null;
    const consider = (t: number) => {
      if (next === null || t < next) next = t;
    };
    const now = this.core.now();
    for (const p of this.core.pending.values()) consider(p.deadline);
    for (const ch of this.core.challenges.values()) consider(ch.expiresAt);
    const conns: AuthedConn[] = [
      ...(this.core.forge ? [this.core.forge] : []),
      ...this.core.clients.values(),
    ];
    for (const c of conns) {
      consider(c.expSec * 1000);
      consider(c.lastPong + PONG_TIMEOUT_MS);
      consider(c.lastPingSent + PING_INTERVAL_MS);
    }
    if (next !== null && next < now) return now;
    return next;
  }

  presence(): { forge_online: boolean; clients: number } {
    return { forge_online: this.core.forge !== null, clients: this.core.clients.size };
  }

  private dirty = false;

  isDirty(): boolean {
    return this.dirty;
  }

  markDirty(): void {
    this.dirty = true;
  }

  clearDirty(): void {
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
              conn: core.forge.connId,
              role: "forge" as const,
              jti: core.forge.grant.claims.jti,
              exp: core.forge.expSec,
              kid: core.forge.grant.kid,
              cnfX: b64uEncode(core.forge.grant.cnfPk),
              scope: [...core.forge.grant.claims.scope],
            }]
          : []),
        ...[...core.clients].map(([conn, c]) => ({
          conn,
          role: "client" as const,
          jti: c.grant.claims.jti,
          exp: c.expSec,
          kid: c.grant.kid,
          cnfX: b64uEncode(c.grant.cnfPk),
          scope: [...c.grant.claims.scope],
        })),
      ],
      channels: [...core.channels].map(([name, st]) => ({
        name,
        owner: st.owner,
        lastClientSeq: st.lastClientSeq,
        lastForgeSeq: st.lastForgeSeq,
        toForge: { ...st.toForge, sizes: [...st.toForge.sizes] },
        toClient: { ...st.toClient, sizes: [...st.toClient.sizes] },
      })),
    };
  }

  restore(snap: RoomSnapshot, socketFor: (connId: string) => RoomSocket | null): { restored: number; dropped: number } {
    if (snap.v !== 1 || snap.account !== this.account || snap.machine !== this.machine) {
      throw new Error("snapshot mismatch");
    }
    const core = this.core;
    const nowSec = Math.floor(core.now() / 1000);
    core.revoked_machines = new Set(snap.revokedMachines.slice(0, MAX_REVOKED_JTIS));
    core.revoked_keys = new Set(snap.revokedKeys.slice(0, MAX_REVOKED_JTIS));
    core.used_jti = new Map(snap.usedJti.filter(([, e]) => e >= nowSec));
    const machineRevoked = core.revoked_machines.has(this.machine);
    let restored = 0;
    let dropped = 0;
    const live = new Set<string>();
    for (const c of snap.conns) {
      const sock = socketFor(c.conn);
      if (!sock) {
        dropped++;
        continue;
      }
      let stale: number | null = null;
      if (c.exp <= nowSec) stale = CLOSE_AUTH;
      else if (machineRevoked) stale = CLOSE_REVOKED;
      else {
        try {
          const cnfPk = b64uDecode(c.cnfX);
          if (cnfPk.length !== 32 || matches_revoked_keys(c.kid, cnfPk, core.revoked_keys)) {
            stale = cnfPk.length !== 32 ? CLOSE_AUTH : CLOSE_REVOKED;
          }
        } catch {
          stale = CLOSE_AUTH;
        }
      }
      if (stale !== null) {
        try {
          sock.close(stale, "stale");
        } catch { /* expected: socket gone, best effort */ }
        dropped++;
        continue;
      }
      const reattached = restored_grant(this.account, this.machine, c);
      if (!reattached) {
        try {
          sock.close(CLOSE_AUTH, "stale");
        } catch { /* expected: socket gone, best effort */ }
        dropped++;
        continue;
      }
      const conn: AuthedConn = {
        socket: sock,
        grant: reattached,
        expSec: c.exp,
        lastPong: core.now(),
        lastPingSent: 0,
      };
      if (c.role === "forge") {
        if (core.forge) {
          try {
            sock.close(CLOSE_REPLACED, "duplicate");
          } catch { /* expected: socket gone, best effort */ }
          dropped++;
          continue;
        }
        core.forge = { ...conn, connId: c.conn };
      } else {
        if (core.clients.size >= MAX_CLIENTS) {
          try {
            sock.close(CLOSE_POLICY, "room-full");
          } catch { /* expected: socket gone, best effort */ }
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
      const ownerLive = live.has(ch.owner);
      const forgeLive = core.forge !== null;
      if (!ownerLive || !forgeLive) continue;
      core.channels.set(ch.name, {
        owner: ch.owner,
        lastClientSeq: ch.lastClientSeq,
        lastForgeSeq: ch.lastForgeSeq,
        toForge: { ...ch.toForge, sizes: [...ch.toForge.sizes] },
        toClient: { ...ch.toClient, sizes: [...ch.toClient.sizes] },
      });
    }
    this.clearDirty();
    this.broadcast_presence();
    return { restored, dropped };
  }
}
