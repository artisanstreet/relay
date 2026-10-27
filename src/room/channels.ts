import { encodeServerFrame } from "../schema.ts";
import type { ChannelId, DataFrame } from "../schema.ts";
import { has_scope } from "../services/grants/verifier.ts";
import { CLOSE_FORBIDDEN, CLOSE_POLICY, MAX_BODY_B64, MAX_CHANNELS } from "./limits.ts";
import { new_window, window_has_space, window_push, window_release } from "./ack-window.ts";
import type { AuthedConn, RoomCore, RoomIo } from "./types.ts";

function err(code: string, message: string): string {
  return encodeServerFrame({ v: 1, type: "error", code, message });
}

function safe_send(
  socket: { send(data: string): void } | undefined,
  data: string,
): boolean {
  if (!socket) return false;
  try {
    socket.send(data);
    return true;
  } catch {
    return false;
  }
}

export function close_channel(core: RoomCore, io: RoomIo, channel: string, gone_conn_id: string, reason: string): void {
  const st = core.channels.get(channel);
  if (!st) return;
  core.channels.delete(channel);
  io.mark_dirty();
  const note = encodeServerFrame({ v: 1, type: "channel-closed", channel: channel as ChannelId, reason });
  if (core.forge && core.forge.connId !== gone_conn_id) safe_send(core.forge.socket, note);
  if (st.owner !== gone_conn_id) {
    const owner = core.clients.get(st.owner)?.socket;
    if (owner) safe_send(owner, note);
  }
}

export function authed_conn(core: RoomCore, conn_id: string): { conn: AuthedConn; is_forge: boolean } | null {
  if (core.forge?.connId === conn_id) return { conn: core.forge, is_forge: true };
  const c = core.clients.get(conn_id);
  return c ? { conn: c, is_forge: false } : null;
}

export function channel_open(core: RoomCore, io: RoomIo, conn_id: string, found: { conn: AuthedConn; is_forge: boolean }, channel: string): void {
  const { is_forge } = found;
  if (is_forge) {
    io.send_to(conn_id, err("invalid", "forge cannot open channels"));
    return;
  }
  if (!has_scope(found.conn.grant, "forge:execute")) {
    io.send_to(conn_id, err("bad-scope", "opening channels needs forge:execute"));
    io.drop(conn_id, CLOSE_FORBIDDEN, "bad-scope");
    return;
  }
  if (!core.forge) {
    io.send_to(conn_id, err("forge-offline", "no forge connected"));
    return;
  }
  const existing = core.channels.get(channel);
  if (existing) {
    if (existing.owner !== conn_id) {
      io.send_to(conn_id, err("channel-in-use", "channel owned by another client"));
      return;
    }
  } else {
    if (core.channels.size >= MAX_CHANNELS) {
      io.send_to(conn_id, err("too-many-channels", "room channel cap reached"));
      return;
    }
    core.channels.set(channel, {
      owner: conn_id,
      lastClientSeq: -1,
      lastForgeSeq: -1,
      toForge: new_window(),
      toClient: new_window(),
    });
    io.mark_dirty();
  }
  io.send_to(
    conn_id,
    encodeServerFrame({ v: 1, type: "channel-opened", channel: channel as ChannelId, peer: "forge" }),
  );
  if (core.forge) safe_send(core.forge.socket, encodeServerFrame({ v: 1, type: "channel-opened", channel: channel as ChannelId, peer: "client" }));
}

export function channel_close(core: RoomCore, io: RoomIo, conn_id: string, is_forge: boolean, channel: string, reason?: string): void {
  const st = core.channels.get(channel);
  if (st && (is_forge || st.owner === conn_id)) {
    core.channels.delete(channel);
    io.mark_dirty();
    const note = encodeServerFrame({
      v: 1,
      type: "channel-closed",
      channel: channel as ChannelId,
      reason: reason ?? "closed",
    });
    if (is_forge) io.send_to(st.owner, note);
    else if (core.forge) safe_send(core.forge.socket, note);
  }
}

export function route_data(core: RoomCore, io: RoomIo, conn_id: string, is_forge: boolean, frame: DataFrame): void {
  const st = core.channels.get(frame.channel);
  if (!st) {
    io.send_to(conn_id, err("no-channel", "channel is not open"));
    return;
  }
  if (!is_forge && st.owner !== conn_id) {
    io.send_to(conn_id, err("forbidden", "not your channel"));
    io.drop(conn_id, CLOSE_FORBIDDEN, "forbidden");
    return;
  }
  if (frame.body.length > MAX_BODY_B64) {
    io.send_to(conn_id, err("too-large", "body exceeds 256 KiB"));
    io.drop(conn_id, CLOSE_POLICY, "too-large");
    return;
  }
  const last = is_forge ? st.lastForgeSeq : st.lastClientSeq;
  if (!Number.isSafeInteger(frame.seq) || frame.seq !== last + 1) {
    io.send_to(conn_id, err("bad-seq", "seq must be exactly last+1 (first frame 0)"));
    return;
  }
  if (is_forge) st.lastForgeSeq = frame.seq;
  else st.lastClientSeq = frame.seq;

  const win = is_forge ? st.toClient : st.toForge;
  if (!window_has_space(win, frame.body.length)) {
    io.send_to(conn_id, err("backpressure", "recipient window full; frame dropped"));
    io.mark_dirty();
    return;
  }
  window_push(win, frame.seq, frame.body.length);
  io.mark_dirty();

  const out = encodeServerFrame({ v: 1, type: "data", channel: frame.channel, seq: frame.seq, body: frame.body });
  if (is_forge) {
    const target = core.clients.get(st.owner)?.socket;
    if (!target || !safe_send(target, out)) {
      if (core.forge) safe_send(core.forge.socket, err("route-failed", "client gone; frame dropped"));
    }
  } else {
    if (core.forge && !safe_send(core.forge.socket, out)) {
      io.send_to(conn_id, err("route-failed", "forge gone; frame dropped"));
    }
  }
}

export function handle_ack(core: RoomCore, io: RoomIo, conn_id: string, is_forge: boolean, channel: string, ack_seq: number): void {
  const st = core.channels.get(channel);
  if (!st) return;
  if (!is_forge && st.owner !== conn_id) return;
  const win = is_forge ? st.toForge : st.toClient;
  if (!window_release(win, ack_seq)) return;
  io.mark_dirty();
  const fwd = encodeServerFrame({ v: 1, type: "ack", channel: channel as ChannelId, seq: ack_seq });
  if (is_forge) io.send_to(st.owner, fwd);
  else if (core.forge) safe_send(core.forge.socket, fwd);
}
