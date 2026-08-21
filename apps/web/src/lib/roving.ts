/**
 * Where a roving tabindex goes next.
 *
 * # Why a module and not a handler
 *
 * A list with a roving tabindex is one tab stop instead of N: exactly one item is reachable with
 * Tab, and the arrow keys move which one that is. The interface needs this in three places —
 * the conversation rail, the message thread, the skin-tone row in the emoji picker — and the
 * part that is easy to get wrong is the same in all three and is not the DOM part. It is the
 * arithmetic at the edges: what happens at the last item, what happens when nothing is focused
 * yet, what happens when the list shrank between two keystrokes because a filter is being typed.
 *
 * Those are the cases nobody exercises by hand, because reaching them means holding a key down
 * at the bottom of a list. Here they are an array in, an identifier out, and `node --test` can
 * ask them anything — the same trade `lib/thread.ts` made, and for the same reason.
 *
 * The components keep the three gestures that genuinely need a DOM: read the items, call this,
 * focus what comes back.
 *
 * # Identifiers, never indices
 *
 * `current` is an item's identity, not its position. Every list this serves is rewritten under
 * the user: the rail filters as they type, the thread grows as messages arrive. An index survives
 * neither, and an index that silently means a different row is worse than no memory at all.
 *
 * # What it does not do
 *
 * It does not decide whether an item exists — a caller reading the DOM already knows. It does not
 * focus anything, and it does not touch `preventDefault`: returning `null` for "no move" is what
 * lets the caller leave the event alone, so that ArrowDown at the bottom of a list still scrolls
 * the page rather than being swallowed by a list that had nowhere to go.
 *
 * It says nothing about moving *into* something — the thread's Right arrow, which steps from a
 * message into its row of actions. That is a change of level rather than a step along a ring, and
 * the component owns it.
 */

/** How a ring is laid out, and whether its ends meet. */
export interface Ring {
  /**
   * Which pair of arrows moves along it.
   *
   * The other pair returns `null`, which is what lets a horizontal ring sit inside a vertical
   * one: the tone row inside the emoji grid answers Left and Right and leaves Up and Down to
   * whatever contains it.
   */
  orientation?: "vertical" | "horizontal";

  /**
   * Whether the last item leads back to the first.
   *
   * Off by default, and that default is the interesting one. A rail whose bottom wraps to its top
   * takes the user somewhere they did not ask to go and gives no signal that it happened —
   * holding Down to reach the end of a list would loop forever. Wrapping belongs to a small ring
   * whose ends are both on screen, which in practice means a radio group: ARIA specifies that one
   * as circular, and six skin tones are all visible at once.
   */
  wrap?: boolean;
}

const FIRST = ["Home"];
const LAST = ["End"];
const FORWARD = { vertical: "ArrowDown", horizontal: "ArrowRight" };
const BACKWARD = { vertical: "ArrowUp", horizontal: "ArrowLeft" };

/**
 * The item to focus after `key` was pressed, or `null` if nothing should move.
 *
 * `null` covers four different situations on purpose, because the caller does the same thing in
 * all four — nothing, and leaves the event to the browser: the key means nothing here, the list
 * is empty, the ring has no wrap and this is its end, or the ring is one item long and every move
 * arrives back where it started.
 *
 * A `current` that is not in `items` is treated as no position at all rather than as an error.
 * That is the shrinking-list case: the anchor was on a conversation the filter has just excluded,
 * and the useful answer to Down is the first row of what is left, not silence.
 */
export function move(
  items: readonly string[],
  current: string | null,
  key: string,
  ring: Ring = {},
): string | null {
  if (items.length === 0) return null;

  const orientation = ring.orientation ?? "vertical";
  const first = items[0];
  const last = items[items.length - 1];

  if (FIRST.includes(key)) return current === first ? null : first;
  if (LAST.includes(key)) return current === last ? null : last;

  const forward = key === FORWARD[orientation];
  const backward = key === BACKWARD[orientation];
  if (!forward && !backward) return null;

  const at = current === null ? -1 : items.indexOf(current);

  // No position yet — the first press enters the ring from the end it came from, so Down lands on
  // the first item and Up on the last. This is also the shrinking-list answer described above.
  if (at === -1) return forward ? first : last;

  const next = at + (forward ? 1 : -1);
  if (next >= 0 && next < items.length) return items[next];
  if (!ring.wrap) return null;

  const wrapped = forward ? first : last;

  // A ring of one: wrapping is arithmetically fine and visibly nothing. Reporting a move that
  // changes no focus would have the caller call `preventDefault` for a keystroke that did not do
  // anything.
  return wrapped === current ? null : wrapped;
}
