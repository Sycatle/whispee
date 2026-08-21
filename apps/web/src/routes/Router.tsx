/**
 * The route, as React state, and the one way to change it.
 *
 * # What this replaces, guarantee by guarantee
 *
 * `App.tsx:196-221` intercepts the Android back gesture by hand today: at one panel, opening a
 * conversation pushes a synthetic history entry, a `popstate` listener closes the conversation,
 * and a `pushedEntry` ref tracks whether that entry is still on the stack so the cleanup can pop
 * it — but never one too many, because one too many closes the application. That block is
 * removed by the shell batch, not kept: two things cannot share one history stack. Both would
 * answer the same `popstate`, and the URL and the React state would drift apart within one
 * gesture.
 *
 * Removing it is only defensible if every guarantee it made survives. They do, by construction
 * rather than by bookkeeping:
 *
 * - *The back gesture closes the conversation instead of leaving the app.* `#/c/<key>` is a real
 *   history entry, pushed by `navigate` when the conversation is opened. Back pops it and lands
 *   on `#/`. The entry is no longer synthetic, so nothing has to remember that it exists.
 * - *The entry is removed when the conversation is closed some other way.* The single-pane back
 *   chevron calls `history.back()` — see the rule below — which pops the very entry that opening
 *   the conversation pushed. There is nothing left to clean up on unmount.
 * - *Never consuming one entry too many.* The `pushedEntry` flag existed because the pushed entry
 *   was invisible: nothing in the URL said whether it was still there. Here the URL *is* the
 *   flag. This module never calls `history.back()` on its own behalf, so it can never eat an
 *   entry belonging to the page before ours.
 * - *Widening the window must not disturb the stack.* The old block ran on `[duo, active]`, so a
 *   resize tore down the effect and popped the entry. Layout is not a route here: `useDuo()`
 *   changes which panes are mounted and the URL does not move.
 *
 * # The rule the shell has to follow
 *
 * **A control that *undoes* a navigation calls `history.back()`. A control that *goes somewhere*
 * navigates.**
 *
 * The single-pane back chevron undoes. If it navigated to `#/`, every list ↔ conversation
 * round trip would stack an entry, and leaving the application would take ten presses of the
 * Android back button. Conversely a link to settings goes somewhere, and must push, or the back
 * gesture would skip past the screen the user came from.
 *
 * # Why `replace` is not decorative
 *
 * The two-pane shell opens the first conversation when none is selected and the window is wide
 * (`App.tsx:241-243`). That selection is the layout filling a void, not a destination the user
 * asked for. Pushed, it would sit in the history as an entry whose removal changes nothing on
 * screen — the user's first back press would appear to do nothing at all. It must be `replace`.
 */
import {
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useMemo,
  useSyncExternalStore,
} from "react";

import { type Route, format, parse, same } from "./route.ts";

export interface NavigateOptions {
  /**
   * Overwrite the current history entry instead of adding one.
   *
   * For navigations the user did not ask for: automatic selection, and correcting a URL into its
   * canonical form.
   */
  replace?: boolean;
}

export type Navigate = (route: Route, options?: NavigateOptions) => void;

/**
 * Everyone currently listening to the hash.
 *
 * Module scope rather than component state because `navigate` has to notify them, and
 * `history.pushState` fires no event — neither `popstate`, which is for user-driven history
 * moves, nor `hashchange`, which the History API deliberately does not raise. Without this set,
 * a programmatic navigation would change the address bar and render nothing.
 */
const listeners = new Set<() => void>();

function announce(): void {
  for (const listener of listeners) listener();
}

/**
 * Both events, and they are not redundant.
 *
 * `popstate` covers the back and forward gestures, including the Android hardware button.
 * `hashchange` covers a hash edited in the address bar or reached through an `href="#/…"`, which
 * `popstate` does not report. When a single move raises both, the extra call is free: the
 * snapshot below is a string, so an unchanged hash re-renders nothing.
 */
function subscribe(onChange: () => void): () => void {
  listeners.add(onChange);
  addEventListener("popstate", onChange);
  addEventListener("hashchange", onChange);

  return () => {
    listeners.delete(onChange);
    removeEventListener("popstate", onChange);
    removeEventListener("hashchange", onChange);
  };
}

/**
 * The snapshot is the raw hash, not the parsed route.
 *
 * `parse` allocates a new object every call, and `useSyncExternalStore` compares snapshots by
 * identity: returning a route here would report a change on every render and loop forever. The
 * string is stable by nature, and parsing it in a `useMemo` keyed on it gives the same object
 * back for as long as the URL holds still — which is what lets a child use the route as a
 * dependency.
 */
function readHash(): string {
  return globalThis.location?.hash ?? "";
}

const RouteContext = createContext<Route | null>(null);

export function RouterProvider({ children }: { children: ReactNode }) {
  const hash = useSyncExternalStore(subscribe, readHash, readHash);
  const route = useMemo(() => parse(hash), [hash]);

  return <RouteContext.Provider value={route}>{children}</RouteContext.Provider>;
}

/** Where the application currently is. Subscribes: the caller re-renders when the URL moves. */
export function useRoute(): Route {
  const route = useContext(RouteContext);
  if (route === null) throw new Error("useRoute outside a RouterProvider");
  return route;
}

/**
 * Goes to a route.
 *
 * The returned function is stable, so it is safe as an effect dependency — which matters,
 * because the automatic selection that needs `replace` lives in an effect.
 */
export function useNavigate(): Navigate {
  return useCallback((route: Route, options?: NavigateOptions) => {
    const target = format(route);

    // Already there. Pushing would add an entry whose removal changes nothing on screen, and the
    // comparison goes through the canonical form so that `""` and `"#/"` count as the same place.
    if (same(parse(readHash()), route)) return;

    // `location.hash = …` is not used, for two reasons: it always pushes, so `replace` would be
    // impossible to express, and it raises `hashchange` asynchronously, so the two paths would
    // update the tree at different moments.
    const url = new URL(location.href);
    url.hash = target;

    if (options?.replace) {
      // The existing state is carried over rather than cleared: this entry is being corrected,
      // not created, and whatever the browser attached to it — scroll restoration among other
      // things — belongs to the entry, not to the URL.
      history.replaceState(history.state, "", url);
    } else {
      history.pushState(null, "", url);
    }

    announce();
  }, []);
}
