export { parse_revocations_response as parseRevocationsResponse } from "./services/revocations.ts";
export type { RevocationList } from "./services/revocations.ts";

export const REVOCATION_POLL_MS = 60_000;
