import type { AckWindow } from "./types.ts";
import { MAX_UNACKED_BYTES, MAX_UNACKED_FRAMES } from "./limits.ts";

export function new_window(): AckWindow {
  return { sentHigh: -1, ackedHigh: -1, sizes: [], unackedBytes: 0 };
}

export function window_has_space(win: AckWindow, body_len: number): boolean {
  return win.sizes.length < MAX_UNACKED_FRAMES && win.unackedBytes + body_len <= MAX_UNACKED_BYTES;
}

export function window_push(win: AckWindow, seq: number, body_len: number): void {
  win.sentHigh = seq;
  win.sizes.push(body_len);
  win.unackedBytes += body_len;
}

export function window_release(win: AckWindow, ack_seq: number): boolean {
  if (ack_seq <= win.ackedHigh) return false;
  if (ack_seq > win.sentHigh) return false;
  const release = Math.min(ack_seq - win.ackedHigh, win.sizes.length);
  for (let i = 0; i < release; i++) {
    const size = win.sizes.shift() ?? 0;
    win.unackedBytes = Math.max(0, win.unackedBytes - size);
  }
  win.ackedHigh = ack_seq;
  return true;
}
