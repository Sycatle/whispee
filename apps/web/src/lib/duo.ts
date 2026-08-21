/**
 * Is there room to show two panes at once?
 *
 * # Why the question comes up in JavaScript too
 *
 * CSS can hide a pane; it cannot decide **which of the two** to mount, nor offer a back button,
 * nor turn the system back button into "close the conversation". At one pane, navigation changes
 * nature: it is no longer a layout, it is state.
 *
 * # The breakpoint is written twice, deliberately
 *
 * `index.css` carries it too, in the `duo:` variant. Nothing lets Tailwind read a TypeScript
 * constant, and the reverse — deriving the JavaScript from the CSS — would mean parsing a
 * compiled stylesheet at startup. Two declarations whose disagreement is immediately visible on
 * screen beat an indirection that would hide the link.
 */
import { useEffect, useState } from "react";

/** Must stay identical to the `duo:` variant in `index.css`. */
export const DUO_BREAKPOINT = "(min-width: 48rem)";

/**
 * True when both panes fit side by side.
 *
 * Re-evaluated on resize, which covers rotating a tablet as much as shrinking a window — the
 * same event, and no reason to treat either as a special case.
 */
export function useDuo(): boolean {
  const [duo, setDuo] = useState(() => globalThis.matchMedia?.(DUO_BREAKPOINT).matches ?? true);

  useEffect(() => {
    const query = globalThis.matchMedia?.(DUO_BREAKPOINT);
    if (!query) return;

    const react = () => setDuo(query.matches);
    query.addEventListener("change", react);
    // Re-read on subscribe: the window may have changed between the first render and this effect.
    react();
    return () => query.removeEventListener("change", react);
  }, []);

  return duo;
}
