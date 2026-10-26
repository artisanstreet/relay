// Wire-contract strictness: Effect Schema is authoritative; unknown fields
// rejected on requests, server frames read forward-compatibly.

import { describe, expect, it } from "vitest";
import {
  decodeClientFrame,
  decodeGrantClaims,
  encodeServerFrame,
  readServerFrame,
} from "../src/schema.ts";
import { MAX_BODY_B64 } from "../src/room.ts";

describe("wire contracts", () => {
  const fakeJwt = `${"a".repeat(20)}.${"b".repeat(20)}.${"c".repeat(20)}`;

  it("accepts each client frame shape", () => {
    expect(decodeClientFrame({ v: 1, type: "hello", grant: fakeJwt }).type).toBe("hello");
    expect(decodeClientFrame({ v: 1, type: "authenticate", jti: "j", sig: "c2ln" }).type).toBe("authenticate");
    expect(decodeClientFrame({ v: 1, type: "open", channel: "ch1" }).type).toBe("open");
    expect(decodeClientFrame({ v: 1, type: "data", channel: "ch1", seq: 0, body: "eA" }).type).toBe("data");
    expect(decodeClientFrame({ v: 1, type: "close", channel: "ch1" }).type).toBe("close");
    expect(decodeClientFrame({ v: 1, type: "pong", t: 1 }).type).toBe("pong");
  });

  it("rejects unknown fields on every client frame", () => {
    const frames = [
      { v: 1, type: "hello", grant: fakeJwt, extra: 1 },
      { v: 1, type: "authenticate", jti: "j", sig: "c2ln", extra: 1 },
      { v: 1, type: "open", channel: "ch1", extra: 1 },
      { v: 1, type: "data", channel: "ch1", seq: 0, body: "eA", extra: 1 },
      { v: 1, type: "close", channel: "ch1", extra: 1 },
      { v: 1, type: "pong", t: 1, extra: 1 },
    ];
    for (const f of frames) expect(() => decodeClientFrame(f), JSON.stringify(f)).toThrow();
  });

  it("rejects bad versions, channels, and ids", () => {
    expect(() => decodeClientFrame({ v: 2, type: "pong", t: 1 })).toThrow();
    expect(() => decodeClientFrame({ v: 1, type: "open", channel: "../x" })).toThrow();
    expect(() => decodeClientFrame({ v: 1, type: "open", channel: "" })).toThrow();
    expect(() => decodeClientFrame({ v: 1, type: "data", channel: "c", seq: -1, body: "eA" })).toThrow();
    expect(() => decodeClientFrame({ v: 1, type: "data", channel: "c", seq: 1.5, body: "eA" })).toThrow();
    expect(() => decodeClientFrame({ v: 1, type: "data", channel: "c", seq: 0, body: "x".repeat(MAX_BODY_B64 + 1) })).toThrow();
  });

  it("accepts ack frames and rejects unknown fields on them", () => {
    expect(decodeClientFrame({ v: 1, type: "ack", channel: "ch1", seq: 7 }).type).toBe("ack");
    expect(() => decodeClientFrame({ v: 1, type: "ack", channel: "ch1", seq: 7, extra: 1 })).toThrow();
    expect(() => decodeClientFrame({ v: 1, type: "ack", channel: "ch1", seq: -1 })).toThrow();
  });

  it("rejects unknown frame types and garbage", () => {
    expect(() => decodeClientFrame({ v: 1, type: "teleport" })).toThrow();
    expect(() => decodeClientFrame(null)).toThrow();
    expect(() => decodeClientFrame("hello")).toThrow();
    expect(() => decodeClientFrame([])).toThrow();
  });

  it("rejects unknown grant claims", () => {
    const base = {
      v: 1, iss: "x", aud: "ast-relay", sub: "a", mid: "m", jti: "j",
      iat: 1, nbf: 1, exp: 2, role: "client", scope: ["relay:connect"],
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: "x".repeat(43) } }, rev: 0,
    };
    expect(decodeGrantClaims(base).sub).toBe("a");
    expect(() => decodeGrantClaims({ ...base, bogus: true })).toThrow();
    expect(() => decodeGrantClaims({ ...base, scope: [] })).not.toThrow(); // shape ok; verifier rejects empty
    expect(() => decodeGrantClaims({ ...base, nbf: undefined })).toThrow(); // nbf required
  });

  it("reads server frames forward-compatibly (unknown fields ignored)", () => {
    const f = readServerFrame({ v: 1, type: "ping", t: 5, future: "ignored" });
    expect(f.type).toBe("ping");
    const rt = encodeServerFrame({ v: 1, type: "error", code: "c", message: "m" });
    expect(JSON.parse(rt).type).toBe("error");
  });
});
