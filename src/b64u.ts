import { Either } from "effect";
import { base64urlnopad as base64url_nopad } from "@scure/base";

export const b64u_encode = base64url_nopad.encode;

export function b64u_decode(s: string): Uint8Array {
  if (s.length === 0) throw new Error("invalid base64url");
  if (s.length % 4 === 1) throw new Error("invalid base64url");
  return Either.getOrThrowWith(
    Either.try({
      try: () => base64url_nopad.decode(s),
      catch: () => new Error("invalid base64url"),
    }),
    (e) => e as Error,
  );
}
