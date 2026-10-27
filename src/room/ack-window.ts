import type { AckWindow } from "./types.ts";
import { MAX_UNACKED_BYTES, MAX_UNACKED_FRAMES } from "./limits.ts";

export function new_window(): AckWindow {
  return { sent_high: -1, acked_high: -1, sizes: [], unacked_bytes: 0 };
}

export function window_has_space(win: AckWindow, body_len: number): boolean {
  return win.sizes.length < MAX_UNACKED_FRAMES && win.unacked_bytes + body_len <= MAX_UNACKED_BYTES;
}

export function window_push(win: AckWindow, seq: number, body_len: number): void {
  win.sent_high = seq;
  win.sizes.push(body_len);
  win.unacked_bytes += body_len;
}

export function window_release(win: AckWindow, ack_seq: number): boolean {
  if (ack_seq <= win.acked_high) return false;
  if (ack_seq > win.sent_high) return false;
  const release = Math.min(ack_seq - win.acked_high, win.sizes.length);
  for (let i = 0; i < release; i++) {
    const size = win.sizes.shift() ?? 0;
    win.unacked_bytes = Math.max(0, win.unacked_bytes - size);
  }
  win.acked_high = ack_seq;
  return true;
}
