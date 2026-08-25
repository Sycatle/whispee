/**
 * How many panes fit at once?
 *
 * # Why the question comes up in JavaScript too
 *
 * CSS can hide a pane; it cannot decide **which of the two** to mount, nor offer a back button,
 * nor turn the system back button into "close the conversation". At one pane, navigation changes
 * nature: it is no longer a layout, it is state.
 *
 * # The breakpoints are written twice, deliberately
 *
 * `index.css` carries them too, in the `duo:` and `trio:` variants. Nothing lets Tailwind read a
 * TypeScript constant, and the reverse — deriving the JavaScript from the CSS — would mean
 * parsing a compiled stylesheet at startup. Two declarations whose disagreement is immediately
 * visible on screen beat an indirection that would hide the link.
 *
 * # What this module does not decide
 *
 * Whether a pane is *open*. The detail column is state — see `state/detail.tsx`, which also
 * records what moving it out of the route cost. This module only answers whether there is room to
 * show it beside the conversation or whether it has to cover it.
 */
import { useEffect, useState } from "react";

/** Must stay identical to the `duo:` variant in `index.css`. */
export const DUO_BREAKPOINT = "(min-width: 48rem)";

/**
 * Must stay identical to the `trio:` variant in `index.css`.
 *
 * 288 (rail) + 384 (the narrowest a thread can be and still read as a thread) + 320 (detail).
 */
export const TRIO_BREAKPOINT = "(min-width: 64rem)";

/**
 * Tracks one media query.
 *
 * Defaults to `true` before the first measurement, which matters on the server-less first paint
 * and in test environments without `matchMedia`: assuming the roomier layout means a narrow
 * window corrects itself on the first effect, whereas assuming the narrow one would make every
 * desktop load flash through a mobile layout.
 */
function useQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => globalThis.matchMedia?.(query).matches ?? true);

  useEffect(() => {
    const media = globalThis.matchMedia?.(query);
    if (!media) return;

    const react = () => setMatches(media.matches);
    media.addEventListener("change", react);
    // Re-read on subscribe: the window may have changed between the first render and this effect.
    react();
    return () => media.removeEventListener("change", react);
  }, [query]);

  return matches;
}

/**
 * True when the rail and the conversation fit side by side.
 *
 * Re-evaluated on resize, which covers rotating a tablet as much as shrinking a window — the
 * same event, and no reason to treat either as a special case.
 */
export function useDuo(): boolean {
  return useQuery(DUO_BREAKPOINT);
}

/**
 * True when the detail column fits **beside** the conversation rather than over it.
 *
 * Below this, the detail column is still reachable but it covers the centre. Above it, it takes
 * its own third of the shell and the conversation shrinks to make room.
 */
export function useTrio(): boolean {
  return useQuery(TRIO_BREAKPOINT);
}
