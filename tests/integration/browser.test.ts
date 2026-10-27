// Real-Chromium cross-origin proof against the full local stack
// (harness.ts): the built portal SPA served by the REAL Core app with its
// REAL shell CSP, talking to the REAL workerd Relay and the PRODUCTION
// Rust Forge binary. No mocks, no sibling source imports — only the UI
// bundle under test and the published Relay client contract.
//
// Covers: mailed-link sign-in across tabs (real confirm 302), machine
// discovery, cross-origin presence WITH CORS preflight (the actual
// browser enforcement), WS Origin gating (allowed in, evil refused),
// Noise E2E connect + /state read, and a Node-driven SUBSCRIBE/$stream
// start + UNSUBSCRIBE on the same run. Live $event delivery stays covered
// by forge.test.ts (production seam, no UI affordance needed).
//
// Requires a Chromium binary: CHROMIUM_PATH, or the shared
// ~/.cache/ms-playwright cache. Skips cleanly without one (like the
// cargo-less skips elsewhere in this repo).

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { accessSync, constants } from "node:fs";
import { chromium, type Browser, type BrowserContext } from "playwright-core";
import { setupBrowserHarness, type BrowserHarness } from "./harness.ts";
import { EditorLink, SecureChannel } from "../../src/client.ts";
import type { GrantMaterial } from "../../src/client.ts";
import { staticKeypairFromSecret } from "../../src/channel.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { api } from "../../../core/tests/helpers/http.ts";

function findChromium(): string | null {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH;
  const home = process.env.HOME ?? "";
  const cands = [
    `${home}/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome`,
    `${home}/.cache/ms-playwright/chromium-1243/chrome-linux/chrome`,
    "/root/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome",
    `${home}/Library/Caches/ms-playwright/chromium-1243/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`,
    `${home}/Library/Caches/ms-playwright/chromium-1243/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`,
  ];
  for (const c of cands) {
    try {
      accessSync(c, constants.X_OK);
      return c;
    } catch { /* next */ }
  }
  return null;
}

const CHROME = findChromium();
const describeBrowser = CHROME ? describe : describe.skip;

let h: BrowserHarness;
let browser: Browser | null = null;

beforeAll(async () => {
  h = await setupBrowserHarness("browser-interop@example.invalid");
  if (CHROME) {
    browser = await chromium.launch({ executablePath: CHROME, args: ["--no-sandbox"] });
  } else {
    console.log("browser interop: no Chromium found (set CHROMIUM_PATH); browser tests skip");
  }
}, 300_000);

afterAll(async () => {
  await browser?.close().catch(() => undefined);
  await h?.close().catch(() => undefined);
}, 120_000);

async function portalContext(): Promise<BrowserContext> {
  const ctx = await browser!.newContext();
  await ctx.addInitScript((base: string) => {
    localStorage.setItem("ast-core:relay-ws", base.replace(/^http/, "ws"));
    localStorage.setItem("ast-core:relay-http", base);
  }, h.relayBase);
  return ctx;
}

describeBrowser("portal in real Chromium (cross-origin Relay)", () => {
  it("serves the shell with the cross-origin CSP", async () => {
    // "/" (app entry) and unknown app paths both serve index.html through
    // Core's real shell branch; hashed assets keep upstream headers.
    // The relay origin is local http (Miniflare) in this harness, so the
    // CSP must carry the actual configured scheme pair (http+ws here,
    // https+wss in production) — never hardcoded.
    // script-src carries 'wasm-unsafe-eval' (sodium-javascript compiles
    // Wasm at startup) and never bare 'unsafe-eval'.
    const relayUrl = new URL(h.relayBase);
    const httpScheme = relayUrl.protocol === "https:" ? "https" : "http";
    const wsScheme = relayUrl.protocol === "https:" ? "wss" : "ws";
    for (const path of ["/", "/portal-deep-link"]) {
      const res = await fetch(`${h.portalBase}${path}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type") ?? "").toContain("text/html");
      const csp = res.headers.get("content-security-policy") ?? "";
      expect(csp).toContain("connect-src 'self'");
      expect(csp).toContain(`${httpScheme}://${relayUrl.host}`);
      expect(csp).toContain(`${wsScheme}://${relayUrl.host}`);
      expect(csp).toContain("img-src 'self' data: blob:");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).toContain("'wasm-unsafe-eval'");
      expect(csp).not.toMatch(/'unsafe-eval'(?!.*wasm)/);
      expect(csp).not.toContain("*");
    }
    const js = await fetch(`${h.portalBase}/index.html`);
    expect(js.headers.get("content-type")).toContain("text/html");
  });

  it("signs in via the real mailed link, lists the enrolled machine", async () => {
    // Positive discovery MUST use the enrolled harness email: the machine
    // belongs to that account and accounts stay isolated.
    const email = h.harnessEmail;
    const ctx = await portalContext();
    const tab1 = await ctx.newPage();
    tab1.on("console", (m) => console.log(`[browser console] ${m.type()}: ${m.text().slice(0, 300)}`));
    tab1.on("pageerror", (e) => console.log(`[browser pageerror] ${String(e).slice(0, 300)}`));
    await tab1.goto(`${h.portalBase}/#/signin`);
    // The shell div is empty (zero-size, "hidden") until JS renders; wait
    // for the real sign-in field, not the shell container.
    await tab1.waitForSelector("#signin-email", { timeout: 30_000 });
    await tab1.fill("#signin-email", email);
    await tab1.click("form button[type=submit]");
    await tab1.waitForSelector("#signin-progress:not([hidden])", { timeout: 30_000 });
    const token = h.rig.tokenForEmail(email);
    const tab2 = await ctx.newPage();
    await tab2.goto(`${h.portalBase}/v1/auth/magic/confirm?token=${token}`);
    await tab2.waitForURL(/#\/approve\?token=/, { timeout: 30_000 });
    await tab2.getByRole("button", { name: "Approve this request" }).click();
    await tab2.waitForSelector("text=finish in the tab that requested the link", { timeout: 30_000 });
    await tab1.getByRole("button", { name: "Finish sign-in" }).click();
    await tab1.waitForURL(/#\/account/, { timeout: 30_000 });
    await tab1.waitForSelector(`text=${email}`, { timeout: 30_000 });

    await tab1.goto(`${h.portalBase}/#/machines`);
    await tab1.waitForSelector("text=interop-forge", { timeout: 30_000 });
    // Cross-origin presence fetch WITH Authorization: the browser sends a
    // CORS preflight; the Relay answers with the exact portal origin.
    await tab1.waitForSelector("text=/online|offline/", { timeout: 30_000 });
    const presence = await tab1.locator(".card").nth(1).textContent();
    expect(presence).toMatch(/online/);
    await ctx.close();
  }, 180_000);

  it("connects Noise E2E to the production Forge and reads /state", async () => {
    // Same harness account: the Forge machine is enrolled to it.
    const email = h.harnessEmail;
    const ctx = await portalContext();
    const tab1 = await ctx.newPage();
    tab1.on("console", (m) => console.log(`[browser console] ${m.type()}: ${m.text().slice(0, 300)}`));
    tab1.on("pageerror", (e) => console.log(`[browser pageerror] ${String(e).slice(0, 300)}`));
    await tab1.goto(`${h.portalBase}/#/signin`);
    await tab1.waitForSelector("#signin-email", { timeout: 30_000 });
    await tab1.fill("#signin-email", email);
    await tab1.click("form button[type=submit]");
    await tab1.waitForSelector("#signin-progress:not([hidden])", { timeout: 30_000 });
    const token = h.rig.tokenForEmail(email);
    const tab2 = await ctx.newPage();
    await tab2.goto(`${h.portalBase}/v1/auth/magic/confirm?token=${token}`);
    await tab2.waitForURL(/#\/approve\?token=/, { timeout: 30_000 });
    await tab2.getByRole("button", { name: "Approve this request" }).click();
    await tab1.getByRole("button", { name: "Finish sign-in" }).click();
    await tab1.waitForURL(/#\/account/, { timeout: 30_000 });

    await tab1.goto(`${h.portalBase}/#/forge`);
    await tab1.getByRole("button", { name: "Connect encrypted channel" }).click();
    await tab1.waitForSelector("text=Encrypted channel open", { timeout: 60_000 });
    // Real Rust Hub snapshot over a real Noise channel (fresh Hub: the
    // empty thread list is itself the 200-shaped proof).
    await tab1.waitForSelector("text=This Forge reports no threads.", { timeout: 30_000 });
    await ctx.close();
  }, 180_000);

  it("evil origin is blocked: fetch and WebSocket", async () => {
    // A valid grant for the HARNESS account/machine (the machine owner):
    // proves the block is CORS, not auth. Accounts stay isolated so the
    // grant must belong to the owning account.
    const { ed25519: ed2 } = await import("@noble/curves/ed25519.js");
    const cnfSk = ed2.utils.randomSecretKey();
    const cnfX = Buffer.from(ed2.getPublicKey(cnfSk)).toString("base64url");
    const eg = await api(h.rig.app, "POST", "/v1/grants/issue", {
      headers: { cookie: h.sessionCookie, origin: "http://localhost" },
      rawBody: JSON.stringify({
        audience: "ast-relay",
        scope: ["relay:connect"],
        ttlSeconds: 300,
        targetMachineId: h.machineId,
        cnf: { kty: "OKP", crv: "Ed25519", x: cnfX },
      }),
    });
    expect(eg.status).toBe(200);
    const evilJwt = (eg.json as { token: string }).token;

    const evil = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<!doctype html><html><body>evil</body></html>");
    });
    await new Promise<void>((r) => evil.listen(0, "127.0.0.1", () => r()));
    const evilBase = `http://127.0.0.1:${(evil.address() as AddressInfo).port}`;
    const ctx = await browser!.newContext();
    try {
      const page = await ctx.newPage();
      await page.goto(`${evilBase}/`);
      // Control: the endpoint itself is fine (server-side 200).
      const direct = await fetch(`${h.relayBase}/v1/health`);
      expect(direct.status).toBe(200);
      // Same request from a disallowed origin: the browser must block the
      // read (no ACAO), even though the server answers 200.
      const blocked = await page.evaluate(async (url: string) => {
        try {
          const r = await fetch(url);
          return `readable (BAD): ${r.status}`;
        } catch (e) {
          return `blocked: ${(e as Error).name}`;
        }
      }, `${h.relayBase}/v1/health`);
      expect(blocked).toMatch(/^blocked: /);
      // Authenticated cross-origin read: also blocked (proves the block is
      // CORS, evaluated before any grant logic matters to the page).
      const blockedAuth = await page.evaluate(async ([url, jwt]: [string, string]) => {
        try {
          const r = await fetch(url, { headers: { Authorization: `Bearer ${jwt}` } });
          return `readable (BAD): ${r.status}`;
        } catch (e) {
          return `blocked: ${(e as Error).name}`;
        }
      }, [`${h.relayBase}/v1/presence/${h.accountId}/${h.machineId}`, evilJwt] as [string, string]);
      expect(blockedAuth).toMatch(/^blocked: /);
      // WebSocket upgrade from a disallowed origin is refused pre-upgrade.
      const wsResult = await page.evaluate(async (url: string) => {
        return new Promise<string>((resolve) => {
          const ws = new WebSocket(url);
          const done = (s: string) => {
            try {
              ws.close();
            } catch { /* ignore */ }
            resolve(s);
          };
          const t = setTimeout(() => done("no-event"), 5000);
          ws.addEventListener("open", () => {
            clearTimeout(t);
            done("opened (BAD)");
          });
          ws.addEventListener("error", () => {
            clearTimeout(t);
            done("errored");
          });
          ws.addEventListener("close", () => {
            clearTimeout(t);
            done("closed");
          });
        });
      }, `${h.relayWsBase}/v1/route/${h.accountId}/${h.machineId}`);
      expect(["errored", "closed"]).toContain(wsResult);
    } finally {
      await ctx.close();
      await new Promise<void>((r) => evil.close(() => r()));
    }
  }, 120_000);
});

describe("tunnel stream on the same run (Node driver, real Relay + Forge)", () => {
  it("SUBSCRIBEs, receives Hello $event, and UNSUBSCRIBEs", async () => {
    // A Node-side session on this harness owned by the SAME harness
    // account (owns h.machineId): accounts stay isolated.
    const cookie = h.sessionCookie;

    const editorSk = ed25519.utils.randomSecretKey();
    const editorX = Buffer.from(ed25519.getPublicKey(editorSk)).toString("base64url");
    const eb = JSON.stringify({
      audience: "ast-relay",
      scope: ["relay:connect", "forge:execute", "machine:sync"],
      ttlSeconds: 300,
      targetMachineId: h.machineId,
      cnf: { kty: "OKP", crv: "Ed25519", x: editorX },
    });
    const eg = await api(h.rig.app, "POST", "/v1/grants/issue", {
      headers: { cookie, origin: "http://localhost" },
      rawBody: eb,
    });
    expect(eg.status).toBe(200);
    const editorJwt = (eg.json as { token: string }).token;
    const editorJti = JSON.parse(Buffer.from(editorJwt.split(".")[1] as string, "base64url").toString()).jti as string;

    const me = await api(h.rig.app, "GET", "/v1/machines", {
      headers: { cookie, origin: "http://localhost" },
    });
    expect(me.status).toBe(200);
    const machines = (me.json as { machines?: { id: string; publicKey: { x: string } }[] }).machines ?? [];
    const forgeCnf = Buffer.from((machines.find((m) => m.id === h.machineId)?.publicKey.x ?? "") as string, "base64url");
    expect(forgeCnf.length).toBe(32);

    const { EditorLink, SecureChannel } = await import("../../src/client.ts");
    const { staticKeypairFromSecret } = await import("../../src/channel.ts");
    const { randomBytes } = await import("@noble/hashes/utils.js");
    const inbox: Uint8Array[] = [];
    const link = new EditorLink(
      `${h.relayWsBase}/v1/route/${h.accountId}/${h.machineId}`,
      { jwt: editorJwt, jti: editorJti, cnfSk: editorSk },
      { onData: (_c, _s, body) => inbox.push(body) },
      WebSocket as unknown as typeof globalThis.WebSocket,
    );
    try {
      await link.connect();
      const ctx = { account: h.accountId, machine: h.machineId, channel: "interop-stream" };
      const ch = SecureChannel.initiate(staticKeypairFromSecret(randomBytes(32)), {
        cnfSignKey: editorSk,
        expectedForgeCnf: new Uint8Array(forgeCnf),
        ownGrantJwt: editorJwt,
        ctx,
      });
      const pump = (): void => {
        for (const b of ch.pumpOutbound()) link.sendOpaque(ctx.channel, b);
      };
      const takeApp = (): Uint8Array[] => {
        const out: Uint8Array[] = [];
        for (const raw of inbox.splice(0, inbox.length)) {
          const app = ch.handleIncoming(raw);
          if (app) out.push(app);
        }
        return out;
      };
      link.open(ctx.channel);
      pump();
      const deadline = Date.now() + 60_000;
      while (!ch.isOpen() && Date.now() < deadline) {
        pump();
        takeApp();
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(ch.isOpen(), "Noise channel open").toBe(true);

      const pendingEvents: unknown[] = [];
      const callById = async (obj: { id: string } & Record<string, unknown>, label: string): Promise<unknown> => {
        ch.queueApp(JSON.stringify(obj));
        pump();
        const dl = Date.now() + 60_000;
        const backlog: unknown[] = [];
        for (;;) {
          pump();
          for (const b of takeApp()) backlog.push(JSON.parse(new TextDecoder().decode(b)) as unknown);
          const hit = backlog.findIndex(
            (o) => typeof o === "object" && o !== null && (o as Record<string, unknown>)["id"] === obj.id,
          );
          if (hit >= 0) {
            const [found] = backlog.splice(hit, 1);
            // Keep any interleaved $events for the caller to drain.
            for (const rest of backlog.splice(0, backlog.length)) pendingEvents.push(rest);
            return found;
          }
          if (Date.now() > dl) throw new Error(`stall waiting for ${label}`);
          await new Promise((r) => setTimeout(r, 25));
        }
      };

      const subAck = (await callById(
        { id: "bsub1", method: "SUBSCRIBE", path: "/events?since=0" },
        "SUBSCRIBE ack",
      )) as Record<string, unknown>;
      const ackBody = (subAck["body"] as Record<string, unknown>) ?? {};
      const streamId = ((ackBody["$stream"] ?? {}) as Record<string, unknown>)["stream"];
      expect(typeof streamId).toBe("string");

      // $event frames stream onward; the Hello envelope arrives first —
      // usually alongside the ack, otherwise within seconds. Drain anything
      // already collected before waiting on the wire.
      const pending = await (async () => {
        const dl = Date.now() + 30_000;
        for (;;) {
          const queued = pendingEvents.splice(0, pendingEvents.length);
          const ev = queued
            .map((b) => b as Record<string, unknown>)
            .find((o) => typeof o === "object" && o !== null && "$event" in o);
          if (ev) return ev;
          pump();
          const apps = takeApp();
          const live = apps
            .map((b) => JSON.parse(new TextDecoder().decode(b)) as Record<string, unknown>)
            .find((o) => typeof o === "object" && o !== null && "$event" in o);
          if (live) return live;
          if (Date.now() > dl) throw new Error("no $event arrived on the stream");
          await new Promise((r) => setTimeout(r, 25));
        }
      })();
      expect(((pending as Record<string, unknown>)["$event"] as Record<string, unknown>)["stream"]).toBe(streamId);

      const unsub = (await callById(
        { id: "bsub3", method: "UNSUBSCRIBE", path: `/events/${streamId as string}` },
        "UNSUBSCRIBE ack",
      )) as Record<string, unknown>;
      expect(unsub["status"]).toBe(200);
    } finally {
      link.close();
    }
  }, 180_000);
});
