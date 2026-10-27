// LIVE cross-language interop: our Noise_XX initiator (noise-handshake)
// against a REAL snow 0.10 responder (interop/snow-peer), same run.
// This is the interop proof: handshake-hash equality means byte-identical
// protocol execution (suite, HKDF, nonces, prologue). Skipped when cargo
// or the snow crate is unavailable; the skip is reported, not hidden.

import { describe, expect, it } from "vitest";
import { execFileSync, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Noise from "noise-handshake";
import Cipher from "noise-handshake/cipher";
import dh from "noise-handshake/dh";
import { prologueBytes } from "../src/channel.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PEER_DIR = join(root, "interop", "snow-peer");
const BIN = join(PEER_DIR, "target", "debug", "snow-peer");

function cargoAvailable(): boolean {
  try {
    execFileSync("cargo", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const CTX = { account: "interop-acct", machine: "interop-forge", channel: "interop-ch" };

interface Peer {
  send(obj: unknown): Promise<Record<string, string>>;
  close(): void;
}

function startPeer(staticPrivHex: string, prologueHex: string): Peer {
  const child = spawn(BIN, [staticPrivHex, prologueHex], { stdio: ["pipe", "pipe", "inherit"] });
  const rl = createInterface({ input: child.stdout });
  const pending: ((v: Record<string, string>) => void)[] = [];
  rl.on("line", (line) => {
    const resolve = pending.shift();
    if (resolve) resolve(JSON.parse(line) as Record<string, string>);
  });
  return {
    send(obj: unknown): Promise<Record<string, string>> {
      return new Promise((resolve) => {
        pending.push(resolve);
        child.stdin.write(`${JSON.stringify(obj)}\n`);
      });
    },
    close() {
      child.stdin.end();
    },
  };
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "hex"));

describe.runIf(cargoAvailable())("live snow interop", () => {
  it("handshake + transport interoperate byte-exactly", async () => {
    execFileSync("cargo", ["build", "--offline"], { cwd: PEER_DIR, stdio: "ignore" });
    // Fixed static keys (both sides load the same raw keys).
    const initKp = dh.generateKeyPair();
    const respKp = dh.generateKeyPair();
    const prologue = prologueBytes(CTX);
    const peer = startPeer(hex(respKp.secretKey), hex(prologue));
    try {
      const init = new Noise("XX", true, { publicKey: initKp.publicKey, secretKey: initKp.secretKey });
      init.initialise(prologue);
      const m1 = init.send();
      const r2 = await peer.send({ m1: hex(m1) });
      expect(r2["error"]).toBeUndefined();
      init.recv(unhex(r2["m2"] as string));
      const m3 = init.send();
      const r3 = await peer.send({ m3: hex(m3) });
      expect(r3["error"]).toBeUndefined();
      // Killer assertion: identical handshake hash across implementations.
      expect(hex(init.hash as Uint8Array)).toBe(r3["hash"]);
      expect(init.complete).toBe(true);

      // Transport initiator -> snow responder.
      const send = new Cipher(init.tx);
      const pt = new TextEncoder().encode("hello snow");
      const ct = send.encrypt(pt);
      const rpt = await peer.send({ ct: hex(ct) });
      expect(rpt["error"]).toBeUndefined();
      expect(Buffer.from(rpt["pt"] as string, "hex").toString()).toBe("hello snow");

      // Transport snow responder -> initiator.
      const rct = await peer.send({ send: Buffer.from("hello node").toString("hex") });
      expect(rct["error"]).toBeUndefined();
      const recv = new Cipher(init.rx);
      expect(Buffer.from(recv.decrypt(unhex(rct["ct"] as string))).toString()).toBe("hello node");
    } finally {
      peer.close();
    }
  }, 120_000);

  it("snow rejects tampered handshake bytes", async () => {
    execFileSync("cargo", ["build", "--offline"], { cwd: PEER_DIR, stdio: "ignore" });
    const initKp = dh.generateKeyPair();
    const respKp = dh.generateKeyPair();
    const prologue = prologueBytes(CTX);
    const peer = startPeer(hex(respKp.secretKey), hex(prologue));
    try {
      const init = new Noise("XX", true, { publicKey: initKp.publicKey, secretKey: initKp.secretKey });
      init.initialise(prologue);
      const m1 = init.send();
      const r2 = await peer.send({ m1: hex(m1) });
      expect(r2["error"]).toBeUndefined();
      init.recv(unhex(r2["m2"] as string));
      const m3 = init.send();
      // m3 = encrypted static (48B) + encrypted payload (16B): flip inside
      // the ciphertext so snow's AEAD must fail. (Flipping m1's cleartext
      // ephemeral cannot fail — nothing is encrypted yet; the failure then
      // surfaces at m2 processing, covered in channel.test.ts.)
      const tampered = Uint8Array.from(m3);
      tampered[40] = ((tampered[40] ?? 0) ^ 0xff);
      const r = await peer.send({ m3: hex(tampered) });
      expect(r["error"]).toBeDefined();
    } finally {
      peer.close();
    }
  }, 120_000);
});
