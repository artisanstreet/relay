// Base64url helpers (dependency-free so browser bundles stay lean).

const b64uRe = /^[A-Za-z0-9_-]+$/;

export function b64uDecode(s: string): Uint8Array {
  if (!b64uRe.test(s) || s.length === 0 || s.length % 4 === 1) {
    throw new Error("invalid base64url");
  }
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64uEncode(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 8192) {
    s += String.fromCharCode(...b.subarray(i, i + 8192));
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
