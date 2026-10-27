import { describe, expect, it } from "vitest";
import { RelaySocket, SendClosedError } from "../../src/client/relay-socket.ts";
import type { GrantMaterial } from "../../src/client/relay-socket.ts";

class FakeWs {
  private listeners = new Map<string, Set<(ev: unknown) => void>>();
  sent: string[] = [];
  close_calls: Array<{ code?: number; reason?: string }> = [];
  constructor(_url: string) {}
  addEventListener(type: string, fn: (ev: unknown) => void): void {
    let set = this.listeners.get(type);
    if (!set) this.listeners.set(type, (set = new Set()));
    set.add(fn);
  }
  removeEventListener(type: string, fn: (ev: unknown) => void): void {
    this.listeners.get(type)?.delete(fn);
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(code?: number, reason?: string): void {
    this.close_calls.push({ code, reason });
  }
  dispatch(type: string, ev: unknown): void {
    for (const fn of [...(this.listeners.get(type) ?? [])]) fn(ev);
  }
  listener_count(type: string): number {
    return this.listeners.get(type)?.size ?? 0;
  }
}

const grant: GrantMaterial = { jwt: "stub", jti: "stub-jti", cnfSk: new Uint8Array(32) };

function with_timeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`${label}: timed out (would hang forever pre-fix)`)), ms)),
  ]);
}

describe("connect admission lifecycle", () => {
  it("close before ready rejects promptly instead of hanging", async () => {
    let ws: FakeWs | null = null;
    class Impl {
      constructor(_url: string) {
        ws = new FakeWs(_url);
        return ws;
      }
    }
    const link = new RelaySocket("wss://relay/v1/route/a/m", grant, {}, Impl as unknown as typeof WebSocket);
    const pending = link.connect();
    if (!ws) throw new Error("no socket created");
    const sock = ws as unknown as FakeWs;
    sock.dispatch("open", {});
    sock.dispatch("close", { code: 4401, reason: "bad-grant" });
    await expect(with_timeout(pending, 2000, "close-before-ready")).rejects.toBeInstanceOf(SendClosedError);
  });

  it("failed admission rejects and closes the socket (no open leak)", async () => {
    let ws: FakeWs | null = null;
    class Impl {
      constructor(_url: string) {
        ws = new FakeWs(_url);
        return ws;
      }
    }
    const link = new RelaySocket("wss://relay/v1/route/a/m", grant, {}, Impl as unknown as typeof WebSocket);
    const pending = link.connect();
    if (!ws) throw new Error("no socket created");
    const sock = ws as unknown as FakeWs;
    sock.dispatch("open", {});
    sock.dispatch("message", {
      data: JSON.stringify({ v: 1, type: "error", code: "bad-grant", message: "grant verification failed" }),
    });
    await expect(with_timeout(pending, 2000, "failed-admission")).rejects.toThrow(/bad-grant/);
    expect(sock.close_calls.length).toBeGreaterThan(0);
    expect(sock.listener_count("message")).toBe(0);
  });
});
