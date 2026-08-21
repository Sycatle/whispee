/**
 * Dates as a thread shows them.
 *
 * # Why this is its own module
 *
 * The rules are small but they are decisions, and decisions belong somewhere testable. Whether
 * two messages sit under the same date heading, and whether the second one repeats its author's
 * name, is the difference between a thread that reads as a conversation and one that reads as a
 * log — and both rules are quietly wrong at a day boundary if nobody checks.
 *
 * # Why hand-formatted rather than `Intl`
 *
 * For the time, to stay consistent with `presence.ts`, which already writes `HH:MM` by hand a few
 * lines away — two clocks in two formats on the same screen is worse than either format. The date
 * heading does go through `toLocaleDateString`, because a bare day number means nothing and
 * `presence.ts` made the same call for the same reason.
 *
 * # What none of this fixes
 *
 * The stamp is declared by the sender (see `Message.sentAt`): a member can date their message to
 * next year. These functions render what they are given. Ordering is `seq`, decided elsewhere,
 * and deliberately not touched here.
 */

/** `HH:MM`, in the reader's local time. */
export function timeOf(sentAt: number): string {
  const date = new Date(sentAt);
  return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
}

/**
 * The heading above the first message of a day: `Today`, `Yesterday`, or the date.
 *
 * Relative to a `now` passed in rather than read here, so the boundary can be tested and so a
 * thread rendered either side of midnight does not depend on when the module happened to run.
 */
export function dayLabel(sentAt: number, now: number): string {
  const day = new Date(sentAt);
  const today = new Date(now);

  if (day.toDateString() === today.toDateString()) return "Today";

  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (day.toDateString() === yesterday.toDateString()) return "Yesterday";

  return day.toLocaleDateString();
}

/**
 * Does this message open a new day?
 *
 * `true` for the first message of a thread, so it always gets a heading. A message with no stamp
 * never opens one: it has no day to name, and inventing one from its neighbour would put a date
 * on the screen that nothing in the message supports.
 */
export function opensDay(sentAt: number | undefined, previous: number | undefined): boolean {
  if (sentAt === undefined) return false;
  if (previous === undefined) return true;
  return new Date(sentAt).toDateString() !== new Date(previous).toDateString();
}

/**
 * How long two messages from the same author can be apart and still read as one turn.
 *
 * Five minutes is the interval past which a reply stops feeling like a continuation. Below it,
 * repeating the author's name on every line turns a burst of three sentences into three
 * announcements.
 */
export const GROUPING_WINDOW_MS = 5 * 60 * 1000;

/**
 * Does this message continue the previous one — same author, close enough in time, same day?
 *
 * Authors are compared by the value the caller considers identity; `null` never continues
 * anything, because two messages whose sender is unknown are not known to share one.
 */
export function continues(
  author: string | null,
  sentAt: number | undefined,
  previousAuthor: string | null,
  previousSentAt: number | undefined,
): boolean {
  if (author === null || previousAuthor === null || author !== previousAuthor) return false;
  if (opensDay(sentAt, previousSentAt)) return false;

  // Without both stamps there is no interval to measure. Grouping anyway would collapse an
  // unstamped backlog into one block; refusing to is the quieter mistake.
  if (sentAt === undefined || previousSentAt === undefined) return false;

  return sentAt - previousSentAt < GROUPING_WINDOW_MS;
}
