import { encodeServerFrame } from "../schema.ts";
import type { AccountId, MachineId } from "../schema.ts";
import { b64uDecode, b64uEncode } from "../b64u.ts";
import { has_scope } from "../services/grants/verifier.ts";
import { popVerify } from "../e2e.ts";
import { randomBytes } from "@noble/hashes/utils.js";
import { Either } from "effect";
import { CHALLENGE_TTL_MS, CLOSE_AUTH, CLOSE_FORBIDDEN, CLOSE_POLICY, CLOSE_REPLACED, CLOSE_REVOKED, MAX_CLIENTS } from "./limits.ts";
import { is_revoked } from "./revocation.ts";
import type { AuthedConn, RoomCore, RoomIo } from "./types.ts";

function err(code: string, message: string): string {
  return encodeServerFrame({ v: 1, type: "error", code, message });
}

function prune_jti(core: RoomCore): void {
  const now_sec = Math.floor(core.now() / 1000);
  for (const [j, e] of core.used_jti) {
    if (e < now_sec) core.used_jti.delete(j);
  }
}

export async function admit_hello(core: RoomCore, io: RoomIo, conn_id: string, jwt: string): Promise<void> {
  const pend = core.pending.get(conn_id);
  if (!pend) return;
  const grant = await core.verify(jwt, Math.floor(core.now() / 1000)).then(
    (verified) => verified,
    (): null => {
      io.send_to(conn_id, err("bad-grant", "grant verification failed"));
      io.drop(conn_id, CLOSE_AUTH, "bad-grant");
      return null;
    },
  );
  if (!grant) return;
  const cl = grant.claims;
  if (cl.sub !== core.account || cl.mid !== core.machine) {
    io.send_to(conn_id, err("bad-binding", "grant is for another machine"));
    io.drop(conn_id, CLOSE_FORBIDDEN, "bad-binding");
    return;
  }
  if (!has_scope(grant, "relay:connect")) {
    io.send_to(conn_id, err("bad-scope", "tunnel needs relay:connect"));
    io.drop(conn_id, CLOSE_FORBIDDEN, "bad-scope");
    return;
  }
  if (is_revoked(grant, core.revoked_machines, core.revoked_keys)) {
    io.send_to(conn_id, err("revoked", "grant revoked"));
    io.drop(conn_id, CLOSE_REVOKED, "revoked");
    return;
  }
  prune_jti(core);
  if (core.used_jti.has(cl.jti)) {
    io.send_to(conn_id, err("replay", "grant already used"));
    io.drop(conn_id, CLOSE_AUTH, "replay");
    return;
  }
  core.used_jti.set(cl.jti, cl.exp);
  io.mark_dirty();
  const nonce = randomBytes(32);
  core.challenges.set(conn_id, {
    nonce,
    jti: cl.jti,
    cnfPk: grant.cnfPk,
    grant,
    expiresAt: core.now() + CHALLENGE_TTL_MS,
  });
  io.send_to(
    conn_id,
    encodeServerFrame({ v: 1, type: "challenge", nonce: b64uEncode(nonce), timeout_ms: CHALLENGE_TTL_MS }),
  );
}

export function admit_authenticate(core: RoomCore, io: RoomIo, conn_id: string, jti: string, sig_b64: string): void {
  const ch = core.challenges.get(conn_id);
  if (!ch) return;
  core.challenges.delete(conn_id);
  if (core.now() > ch.expiresAt || jti !== ch.jti) {
    io.send_to(conn_id, err("auth-failed", "challenge expired or mismatched"));
    io.drop(conn_id, CLOSE_AUTH, "auth-failed");
    return;
  }
  const sig = Either.match(Either.try({ try: () => b64uDecode(sig_b64), catch: () => undefined }), {
    onLeft: () => {
      io.send_to(conn_id, err("auth-failed", "bad signature encoding"));
      io.drop(conn_id, CLOSE_AUTH, "auth-failed");
      return undefined;
    },
    onRight: (right) => right as Uint8Array | undefined,
  });
  if (!sig) return;
  if (!popVerify(ch.cnfPk, ch.nonce, ch.jti, sig)) {
    io.send_to(conn_id, err("auth-failed", "proof of possession failed"));
    io.drop(conn_id, CLOSE_AUTH, "auth-failed");
    return;
  }
  const pend = core.pending.get(conn_id);
  if (!pend) return;
  core.pending.delete(conn_id);
  const role = ch.grant.claims.role;
  const conn: AuthedConn = {
    socket: pend.socket,
    grant: ch.grant,
    expSec: ch.grant.claims.exp,
    lastPong: core.now(),
    lastPingSent: 0,
  };
  if (role === "forge") {
    const prev = core.forge;
    if (prev) {
      io.remove_conn(prev.connId);
      void Either.try({ try: () => prev.socket.close(CLOSE_REPLACED, "replaced"), catch: () => undefined });
    }
    core.forge = { ...conn, connId: conn_id };
    core.events.onForgePresence?.(true);
  } else {
    if (core.clients.size >= MAX_CLIENTS) {
      io.send_to(conn_id, err("room-full", "too many clients"));
      io.drop(conn_id, CLOSE_POLICY, "room-full");
      return;
    }
    core.clients.set(conn_id, conn);
  }
  io.mark_dirty();
  io.send_to(
    conn_id,
    encodeServerFrame({
      v: 1,
      type: "ready",
      role,
      account: core.account as AccountId,
      machine: core.machine as MachineId,
      forge_online: core.forge !== null,
    }),
  );
  io.broadcast_presence();
}
