/**
 * The order the conversation list is read in.
 *
 * # Why this is a module and not four lines in the component
 *
 * Because it holds a rule that is easy to state, easy to get subtly wrong, and impossible to
 * check by looking at a screen with three conversations on it. A comparator written inline in a
 * render has no test, and the failure it produces — a pinned conversation that is *usually* first
 * — looks like correct behaviour every time somebody happens to have written in it recently.
 */

/** What the ordering needs to know about a conversation, and nothing more. */
export interface Ordered {
  /** Kept at the top whatever was said last. */
  pinned: boolean;
  /** When something last happened here, for the rest. */
  activity: number;
}

/**
 * Pinned first, then most recent.
 *
 * # Why two stacked orderings rather than one score
 *
 * They answer different questions. Pinning is a standing decision about a conversation; activity
 * is what happened to it. The tempting version adds a large constant to a pinned conversation's
 * activity and sorts once — and that version is wrong in a way nobody notices for weeks: the
 * constant is a bet on how far apart two timestamps can be, and a pinned thread quiet for longer
 * than the bet drops back among the rest. A pinned conversation that has been silent for a month
 * stays where its owner put it. That is the whole of what pinning means.
 *
 * # Stability
 *
 * Ties fall through to `activity`, and equal activity leaves the order the caller had — `sort` is
 * stable in every engine this runs on. Two conversations with the same timestamp are two
 * conversations nobody can tell apart, so shuffling them between renders would be motion with no
 * information in it.
 */
export function byPinnedThenRecent(a: Ordered, b: Ordered): number {
  return Number(b.pinned) - Number(a.pinned) || b.activity - a.activity;
}
