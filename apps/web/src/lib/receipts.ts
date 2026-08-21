/**
 * Delivery and read receipts.
 *
 * # Cumulative, never per-message
 *
 * A receipt says "up to this number", not "this message". Opening a conversation two hundred
 * messages behind therefore costs one envelope and not two hundred — in a table that is never
 * purged, the difference is not an optimisation, it is viability.
 *
 * # The loop that has to be cut
 *
 * A receipt is itself an envelope. Without a guard, each side acknowledges the other's
 * acknowledgement and the conversation never stops. The cut is in `content.isControl()`, in one
 * place, applied on send as on receive.
 *
 * # Two devices, one account
 *
 * Every device on an account receives every message and would like to acknowledge it. Since all
 * members also receive all the receipts, an account's own state is known locally: it is enough to
 * emit only when going beyond what the account has already acknowledged. Deduplication needs no
 * coordination.
 *
 * # Reciprocity
 *
 * Turning off your read receipts also turns off their display. Without that symmetry, you could
 * see without being seen, which is precisely what the setting claims to prevent. `delivered` is
 * not affected: it attests that a device collected its mail, not that a person read.
 */

/** What an account has acknowledged, in one conversation. */
export interface AccountReceipts {
  delivered: number;
  read: number;
}

export type ReceiptBook = Map<string, AccountReceipts>;

/**
 * Records a received receipt. A cursor never moves backwards.
 *
 * The server orders envelopes but does not guarantee the order in which a client processes them
 * after a reconnection. Taking the maximum rather than the last value keeps an old receipt,
 * replayed or re-read, from making the display regress.
 */
export function record(
  book: ReceiptBook,
  handle: string,
  state: "delivered" | "read",
  seq: number,
): void {
  const current = book.get(handle) ?? { delivered: 0, read: 0 };

  if (state === "read") {
    // Reading implies having received. Without this line, a client that only emits `read`
    // (delivery receipts arriving out of order) would show "read" without ever showing
    // "delivered".
    current.read = Math.max(current.read, seq);
    current.delivered = Math.max(current.delivered, seq);
  } else {
    current.delivered = Math.max(current.delivered, seq);
  }

  book.set(handle, current);
}

/**
 * Should a receipt be emitted, and for which number?
 *
 * Returns `undefined` when there is nothing to announce — the common case, and what keeps every
 * poll round from producing an envelope.
 */
export function pending(
  book: ReceiptBook,
  handle: string,
  state: "delivered" | "read",
  cursor: number,
): number | undefined {
  const known = book.get(handle) ?? { delivered: 0, read: 0 };
  const reached = state === "read" ? known.read : known.delivered;
  return cursor > reached ? cursor : undefined;
}

/**
 * State to display on a message you sent yourself.
 *
 * `readReceipts` is the local setting: when it is off, we neither emit nor display. The parameter
 * is passed in rather than read from a settings module so that the reciprocity is visible in the
 * signature — a coupling failure would make the asymmetry possible.
 */
export function statusOf(
  book: ReceiptBook,
  peers: string[],
  seq: number,
  readReceipts: boolean,
): "sent" | "delivered" | "read" {
  if (peers.length === 0) return "sent";

  const states = peers.map((handle) => book.get(handle) ?? { delivered: 0, read: 0 });

  if (readReceipts && states.every((state) => state.read >= seq)) return "read";
  if (states.every((state) => state.delivered >= seq)) return "delivered";
  return "sent";
}
