export { parse_revocations_response as parse_revocations_response } from "./services/revocations.ts";
export type { RevocationList } from "./services/revocations.ts";

export const REVOCATION_POLL_MS = 60_000;
