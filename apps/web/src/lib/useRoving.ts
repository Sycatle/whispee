import { type FocusEvent, type KeyboardEvent, useRef, useState } from "react";

import { type Ring, move } from "./roving.ts";

/**
 * One list, one tab stop.
 *
 * A list of interactive rows is, by default, as many tab stops as it has rows: reaching the
 * composer from the conversation rail meant crossing every conversation on the way, and the
 * message thread was worse at roughly eight stops a message. A roving tabindex makes the whole
 * list one stop and hands the arrows the job of moving within it.
 *
 * The ring is given as identifiers the caller already holds, rather than read back out of the
 * DOM. Both callers have their arrays in React — `listed`, `contacts`, the thread's rows — so the
 * identifiers are right on the first paint, before any element exists to query. The DOM is
 * touched for the one thing it is actually needed for, which is moving the focus.
 *
 * `preferred` is where Tab lands before the user has arrowed anywhere: the open conversation in
 * the rail, the newest message in the thread. `anchor` takes over once they have, and is dropped
 * the moment the list stops holding it — which is what makes typing in the rail's filter and
 * pressing Down land on the first of whatever is left.
 *
 * Rows are addressed through a `data-row` attribute. What this does not solve: nothing checks
 * that the caller put one on every row, so a row missing it is simply unreachable by arrow, and
 * silently. The compiler cannot see an attribute, and the alternative — a ref per row — costs
 * more bookkeeping in every caller than it saves here.
 */
export function useRoving<E extends HTMLElement>(
  ids: readonly string[],
  preferred: string | null,
  ring?: Ring,
) {
  const list = useRef<E>(null);
  const [anchor, setAnchor] = useState<string | null>(null);

  const held = (id: string | null) => (id !== null && ids.includes(id) ? id : null);
  const at = held(anchor) ?? held(preferred) ?? ids[0] ?? null;

  const focus = (id: string) => {
    setAnchor(id);
    // `CSS.escape`: a conversation key is hex and a handle is not, and a selector built from
    // somebody else's handle is a selector built from input we did not choose.
    const el = list.current?.querySelector<HTMLElement>(`[data-row="${CSS.escape(id)}"]`);
    if (el === null || el === undefined) return;

    // `preventScroll` and then an explicit `nearest`, rather than letting `focus()` do it: the
    // browser's own scrolling centres the element, which in a thread means Up from the last
    // message jumps the list half a screen. `nearest` moves it as little as it can, which is
    // nothing at all when the row is already visible.
    el.focus({ preventScroll: true });
    el.scrollIntoView({ block: "nearest" });
  };

  const onKeyDown = (event: KeyboardEvent) => {
    const next = move(ids, at, event.key, ring);
    if (next === null) return;

    // Only once a move actually happened: at the bottom of the list ArrowDown has to stay with
    // the browser, or the list becomes a place the page can no longer be scrolled from.
    event.preventDefault();
    focus(next);
  };

  /**
   * The anchor follows the focus, wherever the focus came from.
   *
   * Tracking it only in `onKeyDown` would mean a row reached with the mouse leaves the tab stop
   * somewhere else, so the next Tab into the rail lands on a row nobody has touched. Focus is the
   * one event every route into a row shares — click, arrow, and `focus()` from the filter alike —
   * so reading the identifier off it covers all three with one listener.
   */
  const onFocus = (event: FocusEvent) => {
    const row = (event.target as HTMLElement).closest<HTMLElement>("[data-row]")?.dataset.row;
    if (row !== undefined) setAnchor(row);
  };

  return { list, at, onKeyDown, onFocus, focus, first: ids[0] ?? null };
}

