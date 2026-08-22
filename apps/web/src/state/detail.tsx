import { type ReactNode, createContext, useCallback, useContext, useMemo, useState } from "react";

/**
 * Whether the detail column is open, and on whom.
 *
 * # Why this is state and no longer a route
 *
 * It used to be `#/c/<key>/info`, and the argument for that was real: a route makes the panel
 * survive a reload, gives it a back-button gesture for free, and lets a card about one member be
 * linked to. `routes/route.ts` still explains the two-level shape it needed for exactly that.
 *
 * What it also did was write to the address bar on a gesture nobody thinks of as navigation.
 * Opening a side panel is not going somewhere; it is looking at the same conversation with more
 * of it visible. The URL changing under a disclosure is a small thing that reads as a mistake,
 * and the history entry it leaves behind is one the reader did not ask for.
 *
 * # What this costs, and it is not nothing
 *
 * Three things, all of which the route was buying:
 *
 *   - **It does not survive a reload.** The panel opens on `trio` by default and closes on the
 *     smaller layouts, so a refresh returns to that default rather than to what was chosen. The
 *     old note in `Shell.tsx` said the preference was not remembered across reloads *either* —
 *     it was rebuilt from the URL, which is not the same as remembered, but it did come back.
 *   - **The back gesture no longer closes it.** On the layouts where the panel covers the screen,
 *     Android's back button and a browser's back arrow now leave the conversation instead of
 *     closing the panel over it. That is the sharpest edge of this change and it is a genuine
 *     regression on touch. The panel keeps its own visible close control, which is what it is
 *     traded against.
 *   - **A member's card cannot be linked to.** `#/c/<key>/info/<handle>` was addressable.
 *     Nothing in the application produced such a link, but it was reachable by hand.
 *
 * # Not in `SessionProvider`
 *
 * That one bridges a mutable class to React and is subscribed to by everything; this is one
 * boolean and a handle, changed by a click. Putting it there would re-render the whole tree on
 * every disclosure. It is a context rather than props because the four places that open it —
 * the header, the rail, a mention, an author card — are scattered, and threading a callback
 * through each would be a prop drilled four levels to carry one setter.
 */

/** The detail column's state: absent when closed, `handle` naming an expanded member's card. */
export type Detail = { handle?: string } | undefined;

interface DetailStore {
  detail: Detail;
  /** Opens the column on the conversation, or on one member when a handle is given. */
  open: (handle?: string) => void;
  close: () => void;
}

const Context = createContext<DetailStore | null>(null);

export function DetailProvider({ children }: { children: ReactNode }) {
  const [detail, setDetail] = useState<Detail>(undefined);

  const open = useCallback((handle?: string) => {
    // `handle` and not `{ handle }`: calling `open()` with nothing opens the column on the
    // conversation, which is a different thing from opening it on a member and has to stay
    // expressible without inventing a sentinel.
    setDetail(handle === undefined ? {} : { handle });
  }, []);

  const close = useCallback(() => setDetail(undefined), []);

  const store = useMemo(() => ({ detail, open, close }), [detail, open, close]);

  return <Context.Provider value={store}>{children}</Context.Provider>;
}

/**
 * The detail column's state.
 *
 * Throws outside a provider rather than returning a closed column, which is the rule the other
 * contexts in this directory follow: a component that reads this and renders nothing looks like a
 * feature that is switched off, and the mistake surfaces as a missing panel rather than as an
 * error naming its cause.
 */
export function useDetail(): DetailStore {
  const store = useContext(Context);
  if (store === null) throw new Error("useDetail used outside DetailProvider");
  return store;
}
