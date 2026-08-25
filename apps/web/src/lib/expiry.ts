/**
 * When a message stops existing, and why that is computed once rather than read from a clock.
 *
 * # The lie the sender can tell
 *
 * `sentAt` travels inside the MLS message and its own documentation states the important half:
 * declared, not proven. A member can put a future timestamp in their own message and buy it a
 * longer life. So the deadline is `min(sentAt, first seen here) + lifetime`: shortening one's own
 * message stays possible, which was never forbidden, and extending it does not.
 *
 * # Why the deadline is stamped and stored
 *
 * A message keeps the deadline it was given when it arrived, even if the conversation's lifetime
 * changes afterwards. That is what "turning it on is not retroactive" means in code, and it also
 * means a device that was offline during a change does not recompute a different answer from the
 * same history.
 */
import type { Message } from "./session-types.ts";

/** The deadline for a message, or `undefined` when nothing expires it. */
export function expiryOf(
  sentAt: number | undefined,
  seenAt: number,
  lifetimeSeconds: number,
): number | undefined {
  if (lifetimeSeconds <= 0) return undefined;
  // Control traffic is not history: a membership notice that expired would leave a thread
  // describing a room nobody ever joined.
  if (sentAt === undefined) return undefined;

  return Math.min(sentAt, seenAt) + lifetimeSeconds * 1000;
}

export function isExpired(message: Message, now: number): boolean {
  return message.expiresAt !== undefined && message.expiresAt <= now;
}

/** The messages that are still alive, in the order they were given. */
export function prune(messages: Message[], now: number): Message[] {
  return messages.filter((message) => !isExpired(message, now));
}
