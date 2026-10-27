import type { VerifiedGrant } from "../services/grants/verifier.ts";

export interface RoomSocket {
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export type VerifyGrant = (jwt: string, now_sec?: number) => Promise<VerifiedGrant>;
export type NowMs = () => number;

export interface RoomEvents {
  on_forge_presence?: (online: boolean) => void;
}

export interface AckWindow {
  sent_high: number;
  acked_high: number;
  sizes: number[];
  unacked_bytes: number;
}

export interface SnapshotConn {
  conn: string;
  role: "forge" | "client";
  jti: string;
  exp: number;
  kid: string;
  cnfX: string;
  scope: string[];
}

export interface SnapshotChannel {
  name: string;
  owner: string;
  lastClientSeq: number;
  lastForgeSeq: number;
  toForge: { sentHigh: number; ackedHigh: number; sizes: number[]; unackedBytes: number };
  toClient: { sentHigh: number; ackedHigh: number; sizes: number[]; unackedBytes: number };
}

export interface RoomSnapshot {
  v: 1;
  account: string;
  machine: string;
  revokedMachines: string[];
  revokedKeys: string[];
  usedJti: [string, number][];
  conns: SnapshotConn[];
  channels: SnapshotChannel[];
}

export interface PendingConn {
  socket: RoomSocket;
  deadline: number;
}

export interface Challenge {
  nonce: Uint8Array;
  jti: string;
  cnf_pk: Uint8Array;
  grant: VerifiedGrant;
  expires_at: number;
}

export interface AuthedConn {
  socket: RoomSocket;
  grant: VerifiedGrant;
  exp_sec: number;
  last_pong: number;
  last_ping_sent: number;
}

export interface ChannelState {
  owner: string;
  last_client_seq: number;
  last_forge_seq: number;
  to_forge: AckWindow;
  to_client: AckWindow;
}

export interface RoomCore {
  account: string;
  machine: string;
  verify: VerifyGrant;
  now: NowMs;
  events: RoomEvents;
  forge: (AuthedConn & { conn_id: string }) | null;
  clients: Map<string, AuthedConn>;
  pending: Map<string, PendingConn>;
  challenges: Map<string, Challenge>;
  channels: Map<string, ChannelState>;
  used_jti: Map<string, number>;
  revoked_machines: Set<string>;
  revoked_keys: Set<string>;
}

export interface RoomIo {
  send_to(conn_id: string, data: string): void;
  drop(conn_id: string, code: number, reason: string): void;
  remove_conn(conn_id: string): boolean;
  close_channel(channel: string, gone_conn_id: string, reason: string): void;
  broadcast_presence(): void;
  mark_dirty(): void;
}
