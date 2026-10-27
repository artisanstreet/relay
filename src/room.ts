// MachineRoom: per-{account,machine} routing, presence, and lifecycle.
//
// Pure, runtime-agnostic RoomState (fully unit-testable with fake sockets)
// plus persistence DTOs for Durable Object hibernation wake-up.
// The room routes OPAQUE bytes only: it validates envelopes, never payloads.
//
// Flow control honesty note: the Workers server-side WebSocket has NO
// bufferedAmount property (it does not exist in @cloudflare/workers-types),
// so send-buffer heuristics cannot work in production. Instead the room
// enforces explicit per-channel ack windows: recipients ack every data
// frame (cumulative acks); senders stall at a bounded unacked cap.
// Memory is bounded by construction and proven by tests with fake sockets
// (no production-only property involved).

import {
  decodeClientFrame,
  encodeServerFrame,
} from "./schema.ts";
import type { AccountId, ChannelId, ClientFrame, DataFrame, MachineId } from "./schema.ts";
import { b64uDecode, b64uEncode, hasScope } from "./jwt.ts";
import type { VerifiedGrant } from "./jwt.ts";
import { popVerify } from "./e2e.ts";
import { randomBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";

// ---------------------------------------------------------------------------
// Limits (frozen v1, see contracts/wire.md)
// ---------------------------------------------------------------------------

export const MAX_BODY_B64 = 349_525; // ~256 KiB ciphertext per data frame
export const MAX_CLIENTS = 64;
export const MAX_CHANNELS = 64;
export const MAX_REVOKED_JTIS = 10_000;
export const HELLO_TIMEOUT_MS = 5_000;
export const CHALLENGE_TTL_MS = 60_000;
export const PING_INTERVAL_MS = 20_000;
export const PONG_TIMEOUT_MS = 60_000;
// Ack-window flow control: bounded unacked frames AND bytes per channel
// per direction. Senders stall (drop-newest + error) instead of growing
// memory without bound.
export const MAX_UNACKED_FRAMES = 64;
export const MAX_UNACKED_BYTES = 1_048_576; // 1 MiB

export const CLOSE_AUTH = 4401;
export const CLOSE_FORBIDDEN = 4403;
export const CLOSE_POLICY = 4408;
export const CLOSE_BACKPRESSURE = 4409;
export const CLOSE_REPLACED = 4001;
export const CLOSE_REVOKED = 4002;

export interface RoomSocket {
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export type VerifyGrant = (jwt: string, nowSec?: number) => Promise<VerifiedGrant>;
export type NowMs = () => number;

interface PendingConn {
  socket: RoomSocket;
  deadline: number;
}

interface Challenge {
  nonce: Uint8Array;
  jti: string;
  cnfPk: Uint8Array;
  grant: VerifiedGrant;
  expiresAt: number;
}

interface AuthedConn {
  socket: RoomSocket;
  grant: VerifiedGrant;
  /** Grant expiry, seconds. Enforced per-frame AND on every sweep. */
  expSec: number;
  lastPong: number;
  lastPingSent: number;
}

/** Ack window for one direction of one channel. Bounded by construction. */
export interface AckWindow {
  /** Highest relay-seq routed toward the recipient. */
  sentHigh: number;
  /** Highest cumulatively acked seq. */
  ackedHigh: number;
  /** Sizes of unacked frames (index 0 == ackedHigh+1). Length <= 64. */
  sizes: number[];
  unackedBytes: number;
}

interface ChannelState {
  owner: string; // client connId
  lastClientSeq: number;
  lastForgeSeq: number;
  /** client -> forge direction window. */
  toForge: AckWindow;
  /** forge -> client direction window. */
  toClient: AckWindow;
}

export interface RoomEvents {
  onForgePresence?: (online: boolean) => void;
}

function newWindow(): AckWindow {
  return { sentHigh: -1, ackedHigh: -1, sizes: [], unackedBytes: 0 };
}

function err(code: string, message: string) {
  return encodeServerFrame({ v: 1, type: "error", code, message });
}

function safeSend(s: RoomSocket | undefined, data: string): boolean {
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
  private forge: (AuthedConn & { connId: string }) | null = null;
  private clients = new Map<string, AuthedConn>();
  private pending = new Map<string, PendingConn>();
  private challenges = new Map<string, Challenge>();
  private channels = new Map<string, ChannelState>();
  private usedJti = new Map<string, number>(); // jti -> expSec
  // Core v1 revocation model (authoritative: Core docs/contracts.md §4):
  // short grant expiry + the /v1/grants/revocations list. NO epochs.
  private revokedMachines = new Set<string>();
  private revokedKeys = new Set<string>();

  constructor(
    account: string,
    machine: string,
    private verify: VerifyGrant,
    private now: NowMs = () => Date.now(),
    private events: RoomEvents = {},
  ) {
    this.account = account;
    this.machine = machine;
  }

  // -- connection lifecycle -------------------------------------------------

  onConnect(connId: string, socket: RoomSocket): void {
    this.pending.set(connId, { socket, deadline: this.now() + HELLO_TIMEOUT_MS });
  }

  async onMessage(connId: string, raw: string | ArrayBuffer): Promise<void> {
    const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
    if (text.length > MAX_BODY_B64 + 1024) {
      this.drop(connId, CLOSE_POLICY, "frame-too-large");
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      this.sendTo(connId, err("malformed", "frame is not JSON"));
      this.drop(connId, CLOSE_POLICY, "malformed");
      return;
    }
    let frame: ClientFrame;
    try {
      frame = decodeClientFrame(parsed);
    } catch {
      this.sendTo(connId, err("invalid-frame", "unknown fields or bad shape"));
      this.drop(connId, CLOSE_POLICY, "invalid-frame");
      return;
    }

    if (this.pending.has(connId) && !this.challenges.has(connId)) {
      if (frame.type !== "hello") {
        this.sendTo(connId, err("auth-required", "first frame must be hello"));
        this.drop(connId, CLOSE_AUTH, "auth-required");
        return;
      }
      await this.handleHello(connId, frame.grant);
      return;
    }
    if (this.challenges.has(connId)) {
      if (frame.type !== "authenticate") {
        this.sendTo(connId, err("auth-required", "expected authenticate"));
        this.drop(connId, CLOSE_AUTH, "auth-required");
        return;
      }
      this.handleAuthenticate(connId, frame.jti, frame.sig);
      return;
    }
    await this.handleAuthed(connId, frame);
  }

  /** Remote close or error: centralized cleanup (idempotent). */
  onClose(connId: string): void {
    this.removeConn(connId);
  }

  /** True when this conn has any record (pending/challenged/authed). */
  hasConn(connId: string): boolean {
    return (
      this.pending.has(connId) ||
      this.challenges.has(connId) ||
      this.forge?.connId === connId ||
      this.clients.has(connId)
    );
  }

  // -- centralized membership -------------------------------------------------
  //
  // removeConn() is the ONLY place membership changes. drop() adds the
  // socket close; onClose() (remote hangup) calls removeConn() directly.
  // Previously drop() deleted members without channel/presence cleanup,
  // leaving stale channel ownership behind — fixed by centralizing here.

  /** Remove a connection and clean up its channels + presence. Returns true if membership changed. */
  private removeConn(connId: string): boolean {
    this.pending.delete(connId);
    this.challenges.delete(connId);
    let changed = false;
    if (this.forge?.connId === connId) {
      this.forge = null;
      changed = true;
      this.events.onForgePresence?.(false);
      for (const ch of [...this.channels.keys()]) this.closeChannel(ch, connId, "forge-offline");
    }
    if (this.clients.has(connId)) {
      this.clients.delete(connId);
      changed = true;
      for (const [ch, st] of [...this.channels]) {
        if (st.owner === connId) this.closeChannel(ch, connId, "client-gone");
      }
    }
    if (changed) this.broadcastPresence();
    return changed;
  }

  private socketOf(connId: string): RoomSocket | undefined {
    if (this.forge?.connId === connId) return this.forge.socket;
    return this.clients.get(connId)?.socket ?? this.pending.get(connId)?.socket;
  }

  private drop(connId: string, code: number, reason: string): void {
    const s = this.socketOf(connId);
    this.removeConn(connId);
    try {
      s?.close(code, reason);
    } catch { /* ignore */ }
  }

  /** Close one channel and notify the surviving peer(s). */
  private closeChannel(channel: string, goneConnId: string, reason: string): void {
    const st = this.channels.get(channel);
    if (!st) return;
    this.channels.delete(channel);
    this.markDirty();
    const note = encodeServerFrame({ v: 1, type: "channel-closed", channel: channel as ChannelId, reason });
    if (this.forge && this.forge.connId !== goneConnId) safeSend(this.forge.socket, note);
    if (st.owner !== goneConnId) {
      const owner = this.clients.get(st.owner)?.socket;
      if (owner) safeSend(owner, note);
    }
  }

  // -- auth -----------------------------------------------------------------

  private async handleHello(connId: string, jwt: string): Promise<void> {
    const pend = this.pending.get(connId);
    if (!pend) return;
    let grant: VerifiedGrant;
    try {
      grant = await this.verify(jwt, Math.floor(this.now() / 1000));
    } catch {
      // Never log the token. Only the failure class.
      this.sendTo(connId, err("bad-grant", "grant verification failed"));
      this.drop(connId, CLOSE_AUTH, "bad-grant");
      return;
    }
    const cl = grant.claims;
    // Core binding: sub (account) + mid (target machine) must equal this
    // room. Prevents cross-account and cross-machine routes.
    if (cl.sub !== this.account || cl.mid !== this.machine) {
      this.sendTo(connId, err("bad-binding", "grant is for another machine"));
      this.drop(connId, CLOSE_FORBIDDEN, "bad-binding");
      return;
    }
    // Tunnels require relay:connect. forge:execute / machine:sync are
    // opaque to Relay (enforced by Forge on the application surface).
    if (!hasScope(grant, "relay:connect")) {
      this.sendTo(connId, err("bad-scope", "tunnel needs relay:connect"));
      this.drop(connId, CLOSE_FORBIDDEN, "bad-scope");
      return;
    }
    if (this.isRevoked(grant)) {
      this.sendTo(connId, err("revoked", "grant revoked"));
      this.drop(connId, CLOSE_REVOKED, "revoked");
      return;
    }
    this.pruneJti();
    if (this.usedJti.has(cl.jti)) {
      this.sendTo(connId, err("replay", "grant already used"));
      this.drop(connId, CLOSE_AUTH, "replay");
      return;
    }
    this.usedJti.set(cl.jti, cl.exp);
    this.markDirty();
    const nonce = randomBytes(32);
    this.challenges.set(connId, {
      nonce,
      jti: cl.jti,
      cnfPk: grant.cnfPk,
      grant,
      expiresAt: this.now() + CHALLENGE_TTL_MS,
    });
    this.sendTo(
      connId,
      encodeServerFrame({ v: 1, type: "challenge", nonce: b64uEncode(nonce), timeout_ms: CHALLENGE_TTL_MS }),
    );
  }

  private handleAuthenticate(connId: string, jti: string, sigB64: string): void {
    const ch = this.challenges.get(connId);
    if (!ch) return;
    this.challenges.delete(connId);
    if (this.now() > ch.expiresAt || jti !== ch.jti) {
      this.sendTo(connId, err("auth-failed", "challenge expired or mismatched"));
      this.drop(connId, CLOSE_AUTH, "auth-failed");
      return;
    }
    let sig: Uint8Array;
    try {
      sig = b64uDecode(sigB64);
    } catch {
      this.sendTo(connId, err("auth-failed", "bad signature encoding"));
      this.drop(connId, CLOSE_AUTH, "auth-failed");
      return;
    }
    if (!popVerify(ch.cnfPk, ch.nonce, ch.jti, sig)) {
      this.sendTo(connId, err("auth-failed", "proof of possession failed"));
      this.drop(connId, CLOSE_AUTH, "auth-failed");
      return;
    }
    const pend = this.pending.get(connId);
    if (!pend) return;
    this.pending.delete(connId);
    const role = ch.grant.claims.role;
    const conn: AuthedConn = {
      socket: pend.socket,
      grant: ch.grant,
      expSec: ch.grant.claims.exp,
      lastPong: this.now(),
      lastPingSent: 0,
    };
    if (role === "forge") {
      const prev = this.forge;
      if (prev) {
        this.removeConn(prev.connId);
        try {
          prev.socket.close(CLOSE_REPLACED, "replaced");
        } catch { /* ignore */ }
      }
      this.forge = { ...conn, connId };
      this.events.onForgePresence?.(true);
    } else {
      if (this.clients.size >= MAX_CLIENTS) {
        this.sendTo(connId, err("room-full", "too many clients"));
        this.drop(connId, CLOSE_POLICY, "room-full");
        return;
      }
      this.clients.set(connId, conn);
    }
    this.markDirty();
    this.sendTo(
      connId,
      encodeServerFrame({
        v: 1,
        type: "ready",
        role,
        account: this.account as AccountId,
        machine: this.machine as MachineId,
        forge_online: this.forge !== null,
      }),
    );
    this.broadcastPresence();
  }

  // -- authed frames ----------------------------------------------------------

  private authedConn(connId: string): { conn: AuthedConn; isForge: boolean } | null {
    if (this.forge?.connId === connId) return { conn: this.forge, isForge: true };
    const c = this.clients.get(connId);
    return c ? { conn: c, isForge: false } : null;
  }

  private async handleAuthed(connId: string, frame: ClientFrame): Promise<void> {
    const found = this.authedConn(connId);
    if (!found) {
      this.sendTo(connId, err("auth-required", "unknown connection"));
      this.drop(connId, CLOSE_AUTH, "auth-required");
      return;
    }
    // Per-frame grant expiry: expired grants cannot act, even between sweeps
    // (covers long sleeps where no alarm fired).
    if (Math.floor(this.now() / 1000) >= found.conn.expSec) {
      this.sendTo(connId, err("grant-expired", "grant expired"));
      this.drop(connId, CLOSE_AUTH, "grant-expired");
      return;
    }
    if (frame.type === "hello" || frame.type === "authenticate") {
      this.sendTo(connId, err("invalid", "already authenticated"));
      return;
    }
    const { isForge } = found;
    switch (frame.type) {
      case "open": {
        if (isForge) {
          this.sendTo(connId, err("invalid", "forge cannot open channels"));
          return;
        }
        // Core §4: tunneled execution requires forge:execute, and Relay
        // checks presence. Channels are opaque (any may carry execution),
        // so opening requires it; routing-only bearers can connect but
        // cannot open. (Whether machine:sync-only openers should pass is
        // an open question for Core — flagged, currently rejected.)
        if (!hasScope(found.conn.grant, "forge:execute")) {
          this.sendTo(connId, err("bad-scope", "opening channels needs forge:execute"));
          this.drop(connId, CLOSE_FORBIDDEN, "bad-scope");
          return;
        }
        if (!this.forge) {
          this.sendTo(connId, err("forge-offline", "no forge connected"));
          return;
        }
        const existing = this.channels.get(frame.channel);
        if (existing) {
          if (existing.owner !== connId) {
            this.sendTo(connId, err("channel-in-use", "channel owned by another client"));
            return;
          }
        } else {
          if (this.channels.size >= MAX_CHANNELS) {
            this.sendTo(connId, err("too-many-channels", "room channel cap reached"));
            return;
          }
          this.channels.set(frame.channel, {
            owner: connId,
            lastClientSeq: -1,
            lastForgeSeq: -1,
            toForge: newWindow(),
            toClient: newWindow(),
          });
          this.markDirty();
        }
        this.sendTo(
          connId,
          encodeServerFrame({ v: 1, type: "channel-opened", channel: frame.channel, peer: "forge" }),
        );
        this.sendToForge(
          encodeServerFrame({ v: 1, type: "channel-opened", channel: frame.channel, peer: "client" }),
        );
        return;
      }
      case "data": {
        this.routeData(connId, isForge, frame);
        return;
      }
      case "ack": {
        this.handleAck(connId, isForge, frame.channel, frame.seq);
        return;
      }
      case "close": {
        const st = this.channels.get(frame.channel);
        if (st && (isForge || st.owner === connId)) {
          this.channels.delete(frame.channel);
          this.markDirty();
          const note = encodeServerFrame({
            v: 1,
            type: "channel-closed",
            channel: frame.channel,
            reason: frame.reason ?? "closed",
          });
          if (isForge) this.sendTo(st.owner, note);
          else this.sendToForge(note);
        }
        return;
      }
      case "pong": {
        found.conn.lastPong = this.now();
        return;
      }
    }
  }

  private routeData(connId: string, isForge: boolean, frame: DataFrame): void {
    const st = this.channels.get(frame.channel);
    if (!st) {
      this.sendTo(connId, err("no-channel", "channel is not open"));
      return;
    }
    if (!isForge && st.owner !== connId) {
      this.sendTo(connId, err("forbidden", "not your channel"));
      this.drop(connId, CLOSE_FORBIDDEN, "forbidden");
      return;
    }
    if (frame.body.length > MAX_BODY_B64) {
      this.sendTo(connId, err("too-large", "body exceeds 256 KiB"));
      this.drop(connId, CLOSE_POLICY, "too-large");
      return;
    }
    const last = isForge ? st.lastForgeSeq : st.lastClientSeq;
    // Contiguous sequence numbers only (first frame is seq 0): the transport
    // is a single ordered WebSocket per direction, so gaps are never
    // legitimate. This also bounds all seq arithmetic: with contiguous seq
    // from 0, sentHigh-ackedHigh always equals the tracked entry count and
    // no crafted giant seq can force an unbounded ack loop or a
    // permanently-full window. Non-safe-integers are rejected outright
    // (JSON precision loss must never enter sequence state).
    if (!Number.isSafeInteger(frame.seq) || frame.seq !== last + 1) {
      this.sendTo(connId, err("bad-seq", "seq must be exactly last+1 (first frame 0)"));
      return;
    }
    if (isForge) st.lastForgeSeq = frame.seq;
    else st.lastClientSeq = frame.seq;

    // Ack-window flow control (the ONLY backpressure mechanism: no
    // production-invisible socket buffer properties are consulted).
    // Window bytes are BASE64-ENCODED body lengths — the exact same basis
    // senders must account (see contracts/wire.md; Rust: frame.body.length
    // of the received base64url string, never decoded raw length).
    const win = isForge ? st.toClient : st.toForge;
    if (win.sizes.length >= MAX_UNACKED_FRAMES || win.unackedBytes + frame.body.length > MAX_UNACKED_BYTES) {
      this.sendTo(connId, err("backpressure", "recipient window full; frame dropped"));
      // Dropped AFTER the seq advance: the sender's stream now has a hole
      // by design. Loss destroys the E2E session downstream (fail-closed
      // cipher stream); the app must re-handshake on a fresh channel, never
      // retry the ciphertext. Replays of the dropped seq still fail.
      this.markDirty();
      return;
    }
    win.sentHigh = frame.seq;
    win.sizes.push(frame.body.length);
    win.unackedBytes += frame.body.length;
    this.markDirty();

    const out = encodeServerFrame({ v: 1, type: "data", channel: frame.channel, seq: frame.seq, body: frame.body });
    if (isForge) {
      const target = this.clients.get(st.owner)?.socket;
      if (!target || !safeSend(target, out)) {
        this.sendToForge(err("route-failed", "client gone; frame dropped"));
      }
    } else {
      if (this.forge && !safeSend(this.forge.socket, out)) {
        this.sendTo(connId, err("route-failed", "forge gone; frame dropped"));
      }
    }
  }

  /** Cumulative ack: frames with seq <= ackSeq in the direction toward the acker are released. */
  private handleAck(connId: string, isForge: boolean, channel: string, ackSeq: number): void {
    const st = this.channels.get(channel);
    if (!st) return; // stale ack for a closed channel: ignore
    if (!isForge && st.owner !== connId) return; // not your channel: ignore
    // The ack releases the window of frames addressed TO the acker:
    // forge acks release toForge (client->forge frames it received);
    // owner-client acks release toClient (forge->client frames it received).
    const win = isForge ? st.toForge : st.toClient;
    if (ackSeq <= win.ackedHigh) return; // duplicate: ignore
    if (ackSeq > win.sentHigh) return; // ahead of anything routed: ignore
    // Bounded by construction: contiguous seq means
    // release == routed-but-unacked == sizes.length at most (≤64).
    const release = Math.min(ackSeq - win.ackedHigh, win.sizes.length);
    for (let i = 0; i < release; i++) {
      const size = win.sizes.shift() ?? 0;
      win.unackedBytes = Math.max(0, win.unackedBytes - size);
    }
    win.ackedHigh = ackSeq;
    this.markDirty();
    // Forward the ack to the original sender so ITS window slides too.
    // (Acks flow recipient -> room -> sender; senders never ack acks, so
    // this cannot loop.) Only slid windows are forwarded.
    const fwd = encodeServerFrame({ v: 1, type: "ack", channel: channel as ChannelId, seq: ackSeq });
    if (isForge) this.sendTo(st.owner, fwd);
    else this.sendToForge(fwd);
  }

  // -- helpers ----------------------------------------------------------------

  private sendTo(connId: string, data: string): void {
    safeSend(this.socketOf(connId), data);
  }

  private sendToForge(data: string): void {
    if (this.forge) safeSend(this.forge.socket, data);
  }

  private broadcastPresence(): void {
    const msg = encodeServerFrame({
      v: 1,
      type: "presence",
      forge_online: this.forge !== null,
      clients: this.clients.size,
    });
    if (this.forge) safeSend(this.forge.socket, msg);
    for (const c of this.clients.values()) safeSend(c.socket, msg);
  }

  private pruneJti(): void {
    const nowSec = Math.floor(this.now() / 1000);
    // Entries live at most one grant TTL past expiry; size is bounded by
    // hello-rate x TTL. Expired entries are always collectable.
    for (const [j, e] of this.usedJti) {
      if (e < nowSec) this.usedJti.delete(j);
    }
  }

  // -- revocation (Core v1 list model) -------------------------------------------

  /**
   * Fingerprint forms accepted for key entries: the raw `cnf.jwk.x`
   * base64url, the hex SHA-256 of the raw key, the base64url-no-pad
   * SHA-256 (Core §2 display/pinning convention), or a Core signing `kid`.
   * Generous matching is deliberate: the exact key-id vocabulary lives
   * with Core (docs/contracts.md §4); all forms are cheap to check.
   */
  private keyForms(kid: string, cnfPk: Uint8Array): string[] {
    const digest = sha256(cnfPk);
    const hexFpr = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
    let s = "";
    for (let i = 0; i < digest.length; i += 8192) {
      s += String.fromCharCode(...digest.subarray(i, i + 8192));
    }
    const b64Fpr = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return [kid, b64uEncode(cnfPk), hexFpr, b64Fpr];
  }

  private matchesRevokedKeys(kid: string, cnfPk: Uint8Array): boolean {
    return this.keyForms(kid, cnfPk).some((f) => this.revokedKeys.has(f));
  }

  private isRevoked(grant: VerifiedGrant): boolean {
    if (this.revokedMachines.has(grant.claims.mid)) return true;
    return this.matchesRevokedKeys(grant.kid, grant.cnfPk);
  }

  /**
   * Replace the revocation list (source: Core /v1/grants/revocations,
   * fetched by the DO on a bounded poll). Sweeps live connections.
   * Caps bound memory; excess entries are dropped oldest-first-ish
   * (insertion order) — documented, fail-open on the tail only.
   */
  setRevocations(machines: string[], keys: string[]): boolean {
    const cap = (arr: string[]) => arr.slice(0, MAX_REVOKED_JTIS);
    const nm = new Set(cap(machines));
    const nk = new Set(cap(keys));
    const changed = nm.size !== this.revokedMachines.size || nk.size !== this.revokedKeys.size ||
      [...nm].some((x) => !this.revokedMachines.has(x)) || [...nk].some((x) => !this.revokedKeys.has(x));
    this.revokedMachines = nm;
    this.revokedKeys = nk;
    this.markDirty();
    this.sweepRevocations();
    return changed;
  }

  private sweepRevocations(): void {
    if (this.forge && this.isRevoked(this.forge.grant)) {
      const id = this.forge.connId;
      this.sendTo(id, err("revoked", "grant revoked"));
      this.drop(id, CLOSE_REVOKED, "revoked");
    }
    for (const [id, c] of [...this.clients]) {
      if (this.isRevoked(c.grant)) {
        this.sendTo(id, err("revoked", "grant revoked"));
        this.drop(id, CLOSE_REVOKED, "revoked");
      }
    }
  }

  /**
   * Periodic duties: timeouts, heartbeats, grant-expiry + revocation sweep.
   * Call when the DO alarm fires (scheduled via nextDeadlineMs).
   */
  tick(): void {
    const now = this.now();
    const nowSec = Math.floor(now / 1000);
    for (const [id, p] of [...this.pending]) {
      if (!this.challenges.has(id) && now > p.deadline) {
        this.sendTo(id, err("timeout", "hello not received in time"));
        this.drop(id, CLOSE_AUTH, "hello-timeout");
      }
    }
    for (const [id, ch] of [...this.challenges]) {
      if (now > ch.expiresAt) {
        this.challenges.delete(id);
        this.sendTo(id, err("timeout", "authenticate not received in time"));
        this.drop(id, CLOSE_AUTH, "challenge-timeout");
      }
    }
    // Grant expiry sweep (also enforced per-frame in handleAuthed, so long
    // sleeps without an alarm cannot extend a dead grant's usefulness: the
    // next frame after expiry is rejected even if no sweep ran).
    if (this.forge && nowSec >= this.forge.expSec) {
      const id = this.forge.connId;
      this.sendTo(id, err("grant-expired", "grant expired"));
      this.drop(id, CLOSE_AUTH, "grant-expired");
    }
    for (const [id, c] of [...this.clients]) {
      if (nowSec >= c.expSec) {
        this.sendTo(id, err("grant-expired", "grant expired"));
        this.drop(id, CLOSE_AUTH, "grant-expired");
      }
    }
    this.sweepRevocations();
    const ping = encodeServerFrame({ v: 1, type: "ping", t: now });
    const check = (id: string, c: AuthedConn) => {
      if (now - c.lastPong > PONG_TIMEOUT_MS) {
        this.sendTo(id, err("timeout", "heartbeat lost"));
        this.drop(id, CLOSE_POLICY, "heartbeat-timeout");
        return;
      }
      if (now - c.lastPingSent >= PING_INTERVAL_MS) {
        c.lastPingSent = now;
        safeSend(c.socket, ping);
      }
    };
    if (this.forge) check(this.forge.connId, this.forge);
    for (const [id, c] of [...this.clients]) check(id, c);
  }

  /**
   * Next millisecond timestamp needing a wake-up, or null when idle.
   * The DO sets its alarm to this (or deletes it). Idle rooms cost nothing.
   */
  nextDeadlineMs(): number | null {
    let next: number | null = null;
    const consider = (t: number) => {
      if (next === null || t < next) next = t;
    };
    const now = this.now();
    for (const p of this.pending.values()) consider(p.deadline);
    for (const ch of this.challenges.values()) consider(ch.expiresAt);
    const conns: AuthedConn[] = [
      ...(this.forge ? [this.forge] : []),
      ...this.clients.values(),
    ];
    for (const c of conns) {
      consider(c.expSec * 1000); // grant expiry sweep
      consider(c.lastPong + PONG_TIMEOUT_MS);
      consider(c.lastPingSent + PING_INTERVAL_MS);
    }
    if (next !== null && next < now) return now;
    return next;
  }

  presence(): { forge_online: boolean; clients: number } {
    return { forge_online: this.forge !== null, clients: this.clients.size };
  }

  // -- persistence (DO hibernation) ----------------------------------------------
  //
  // The DO keeps `this.room` in memory but MUST survive eviction: on wake,
  // it reloads via snapshot()/restore(). Only small, non-secret records are
  // persisted (roles, jtis, exps, channel ownership, seq high-waters, ack
  // windows, revocation state). Challenge nonces and cnf keys never persist:
  // challenged-but-unauthed sockets re-hello after a wake (documented).
  // Seq high-waters persist on channel open/close/auth plus a debounced
  // flush during traffic (markDirty); worst-case rollback after an unclean
  // eviction is bounded, and the E2E Noise layer rejects replays
  // independently of Relay seq counters.

  private dirty = false;

  /** True when state changed since the last snapshot (DO flushes via waitUntil). */
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
    return {
      v: 1,
      account: this.account,
      machine: this.machine,
      revokedMachines: [...this.revokedMachines],
      revokedKeys: [...this.revokedKeys],
      usedJti: [...this.usedJti],
      conns: [
        ...(this.forge
          ? [{
              conn: this.forge.connId,
              role: "forge" as const,
              jti: this.forge.grant.claims.jti,
              exp: this.forge.expSec,
              kid: this.forge.grant.kid,
              cnfX: b64uEncode(this.forge.grant.cnfPk),
            }]
          : []),
        ...[...this.clients].map(([conn, c]) => ({
          conn,
          role: "client" as const,
          jti: c.grant.claims.jti,
          exp: c.expSec,
          kid: c.grant.kid,
          cnfX: b64uEncode(c.grant.cnfPk),
        })),
      ],
      channels: [...this.channels].map(([name, st]) => ({
        name,
        owner: st.owner,
        lastClientSeq: st.lastClientSeq,
        lastForgeSeq: st.lastForgeSeq,
        toForge: { ...st.toForge, sizes: [...st.toForge.sizes] },
        toClient: { ...st.toClient, sizes: [...st.toClient.sizes] },
      })),
    };
  }

  /**
   * Restore persisted state onto live sockets after a DO wake.
   * socketFor(connId) returns the live hibernated socket or null (gone).
   * Returns counts for observability. Expired/revoked/socketless conns are
   * dropped; their channels go with them via centralized cleanup.
   */
  restore(snap: RoomSnapshot, socketFor: (connId: string) => RoomSocket | null): { restored: number; dropped: number } {
    if (snap.v !== 1 || snap.account !== this.account || snap.machine !== this.machine) {
      throw new Error("snapshot mismatch");
    }
    const nowSec = Math.floor(this.now() / 1000);
    this.revokedMachines = new Set(snap.revokedMachines.slice(0, MAX_REVOKED_JTIS));
    this.revokedKeys = new Set(snap.revokedKeys.slice(0, MAX_REVOKED_JTIS));
    this.usedJti = new Map(snap.usedJti.filter(([, e]) => e >= nowSec));
    const machineRevoked = this.revokedMachines.has(this.machine);
    let restored = 0;
    let dropped = 0;
    const live = new Set<string>();
    for (const c of snap.conns) {
      const Sock = socketFor(c.conn);
      if (!Sock) {
        dropped++;
        continue;
      }
      let stale: number | null = null;
      if (c.exp <= nowSec) stale = CLOSE_AUTH;
      else if (machineRevoked) stale = CLOSE_REVOKED;
      else {
        try {
          const cnfPk = b64uDecode(c.cnfX);
          if (cnfPk.length !== 32 || this.matchesRevokedKeys(c.kid, cnfPk)) {
            stale = cnfPk.length !== 32 ? CLOSE_AUTH : CLOSE_REVOKED;
          }
        } catch {
          stale = CLOSE_AUTH;
        }
      }
      if (stale !== null) {
        try {
          Sock.close(stale, "stale");
        } catch { /* ignore */ }
        dropped++;
        continue;
      }
      // Re-attach WITHOUT re-verifying the JWT signature: claims were
      // verified at admission; storage integrity is the DO's own. Expiry
      // and revocation are re-checked here and on every sweep/frame.
      // Full grant re-verification would need the JWT (not persisted —
      // it is a bearer secret and stays out of storage).
      const conn: AuthedConn = {
        socket: Sock,
        grant: restoredGrant(this.account, this.machine, c),
        expSec: c.exp,
        lastPong: this.now(),
        lastPingSent: 0,
      };
      if (c.role === "forge") {
        if (this.forge) {
          try {
            Sock.close(CLOSE_REPLACED, "duplicate");
          } catch { /* ignore */ }
          dropped++;
          continue;
        }
        this.forge = { ...conn, connId: c.conn };
      } else {
        if (this.clients.size >= MAX_CLIENTS) {
          try {
            Sock.close(CLOSE_POLICY, "room-full");
          } catch { /* ignore */ }
          dropped++;
          continue;
        }
        this.clients.set(c.conn, conn);
      }
      live.add(c.conn);
      restored++;
    }
    for (const ch of snap.channels) {
      if (this.channels.size >= MAX_CHANNELS) break;
      const ownerLive = live.has(ch.owner);
      const forgeLive = this.forge !== null;
      if (!ownerLive || !forgeLive) continue;
      this.channels.set(ch.name, {
        owner: ch.owner,
        lastClientSeq: ch.lastClientSeq,
        lastForgeSeq: ch.lastForgeSeq,
        toForge: { ...ch.toForge, sizes: [...ch.toForge.sizes] },
        toClient: { ...ch.toClient, sizes: [...ch.toClient.sizes] },
      });
    }
    this.clearDirty();
    this.broadcastPresence();
    return { restored, dropped };
  }
}

// -- snapshot types ---------------------------------------------------------------

export interface SnapshotConn {
  conn: string;
  role: "forge" | "client";
  jti: string;
  exp: number;
  /** Core signing key id (for key-revocation matching). */
  kid: string;
  /** cnf Ed25519 public key, base64url (for key-revocation matching). */
  cnfX: string;
}

export interface SnapshotChannel {
  name: string;
  owner: string;
  lastClientSeq: number;
  lastForgeSeq: number;
  toForge: AckWindow;
  toClient: AckWindow;
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

/**
 * Minimal re-attached grant record for restored connections. Carries the
 * identifiers the room enforces post-admission (jti for replay cache
 * continuity is NOT restored as usable — usedJti covers it; kid/cnf for
 * revocation sweeps; sub/mid for binding). The JWT itself is never
 * persisted (bearer secret).
 */
function restoredGrant(account: string, machine: string, c: SnapshotConn): VerifiedGrant {
  let cnfPk: Uint8Array;
  try {
    cnfPk = b64uDecode(c.cnfX);
    if (cnfPk.length !== 32) cnfPk = new Uint8Array(32);
  } catch {
    cnfPk = new Uint8Array(32);
  }
  return {
    claims: {
      v: 1,
      iss: "",
      aud: "",
      sub: account,
      mid: machine,
      jti: c.jti,
      iat: 0,
      nbf: 0,
      exp: c.exp,
      role: c.role,
      scope: [],
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: c.cnfX } },
    },
    kid: c.kid,
    cnfPk,
    scopes: new Set<string>(),
  };
}

