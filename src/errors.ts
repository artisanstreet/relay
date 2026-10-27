import { Data } from "effect";

export class RelayMisconfigured extends Data.TaggedError("RelayMisconfigured")<{
  readonly reason: string;
}> {}

export class GrantVerificationFailed extends Data.TaggedError("GrantVerificationFailed")<{
  readonly reason: string;
  readonly cause?: unknown;
}> {}

export class JwksFetchFailed extends Data.TaggedError("JwksFetchFailed")<{
  readonly reason: string;
  readonly cause?: unknown;
}> {}

export class RevocationFetchFailed extends Data.TaggedError("RevocationFetchFailed")<{
  readonly reason: string;
  readonly cause?: unknown;
}> {}

export class StorageUnavailable extends Data.TaggedError("StorageUnavailable")<{
  readonly reason: string;
  readonly cause?: unknown;
}> {}

export class RoomMismatch extends Data.TaggedError("RoomMismatch")<{
  readonly reason: string;
}> {}

export class BadRoomId extends Data.TaggedError("BadRoomId")<{
  readonly reason: string;
}> {}

export class RouteForwardFailed extends Data.TaggedError("RouteForwardFailed")<{
  readonly reason: string;
  readonly cause?: unknown;
}> {}
