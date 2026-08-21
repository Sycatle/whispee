/**
 * The one way to reach the session, and the rule that makes it safe.
 *
 * # `session` is never passed as a prop. Never.
 *
 * The only way to obtain it is `useSession()`, and `useSession()` subscribes. That is the whole
 * design, and everything else here is a consequence of it.
 *
 * The reason is not tidiness. `session` is a mutable object whose identity never changes: a
 * component that receives it from a parent renders correctly exactly once, and from then on its
 * freshness is a property of *its parent's* render schedule, not of the data it displays. Today
 * that happens to work, because `forceRender` sits at the root and re-renders the entire tree
 * — thirteen components deep, through three levels of prop drilling. The day anyone adds a
 * `React.memo`, or an early return, or a sibling that renders on its own, one pane quietly stops
 * updating and nothing anywhere reports it. There is no error, no warning, no failing test: just
 * a message list that stopped growing.
 *
 * Making the session unreachable except through a hook that subscribes turns that class of bug
 * into an impossibility rather than a review comment. It removes the prop drilling as a
 * side-effect, but removal is not the point — the point is that what replaces it is strictly
 * safer than what it replaces, which is rarely true of a refactor.
 *
 * # Two rules that follow from it
 *
 * **`React.memo` is forbidden on anything that reads the session.** Its props are references into
 * a mutating graph: a `ConversationView` prop is not a function of its own contents, so the
 * default shallow comparison says "unchanged" about an object whose message list just grew. A
 * memo boundary there does not slow anything down — it makes the pane wrong.
 *
 * **A `useMemo` over anything derived from the session must list `useRevision()` in its
 * dependencies.** `useMemo(() => session.unreadIn(view), [session, view])` computes once and then
 * lies for the rest of the process's life, because neither dependency will ever change identity.
 * `useRevision()` is the legitimate way out, and it exists as a named hook rather than as advice
 * so that `grep -rn "useRevision" src/` lists every place that took it.
 *
 * # The residual risk, stated plainly
 *
 * `useSyncExternalStore` is **more** granular than what it replaces, not less: only subscribers
 * re-render, where `forceRender` re-rendered from the root. That extra granularity is the only
 * thing here that could ever surface a stale view, and it can do so if and only if someone reads
 * the session without subscribing — which today means holding onto it across a prop, a ref, a
 * closure, or a module-level variable.
 *
 * That is not zero risk. It is why the rule is written at the top of this file, where it is read
 * by whoever is about to break it, rather than left to a code review that may not happen.
 */
import { createContext, use, useSyncExternalStore, type ReactNode } from "react";

import { Revision } from "./revision.ts";
import type { Session } from "../lib/session.ts";

/**
 * Imported as a type only, on purpose: `session.ts` is the largest module in the client and will
 * eventually want to reach for `bump()`. Keeping this edge type-only means the value graph stays
 * one-directional and no bundler has to break a cycle for us.
 */
export interface SessionStore {
  session: Session;
  revision: Revision;
}

const SessionContext = createContext<SessionStore | null>(null);

export function SessionProvider({ value, children }: { value: SessionStore; children: ReactNode }) {
  return <SessionContext value={value}>{children}</SessionContext>;
}

function useStore(): SessionStore {
  const store = use(SessionContext);
  // Thrown rather than returned as null: every caller would have to narrow a value that is only
  // ever absent because of a wiring mistake, and the narrowing would read as if the session were
  // genuinely optional. It is not — the gates in `App.tsx` decide that, above the provider.
  if (!store) throw new Error("useSession must be used inside a <SessionProvider>");
  return store;
}

/**
 * The session, and a subscription to every change made to it.
 *
 * The subscription **is** the fix. Returning `store.session` without it would compile, run, and
 * be wrong in the exact way this file exists to prevent, so the two are welded together in one
 * hook that cannot be half-used.
 */
export function useSession(): Session {
  const store = useStore();
  useSyncExternalStore(store.revision.subscribe, store.revision.getSnapshot);
  return store.session;
}

/**
 * Announces that the session was mutated. Replaces the `onChanged` prop.
 *
 * Whoever mutates calls this — the stream, the poll, every send. Same discipline as before, with
 * the difference that it no longer has to be threaded down through components that have nothing
 * to do with it.
 */
export function useBump(): () => void {
  return useStore().revision.bump;
}

/**
 * The current revision number, for the rare `useMemo` that genuinely needs to recompute.
 *
 * The number itself is meaningless — do not display it, do not compare two of them for anything
 * but inequality. It is a dependency, and its only job is to be different after a mutation.
 */
export function useRevision(): number {
  const store = useStore();
  return useSyncExternalStore(store.revision.subscribe, store.revision.getSnapshot);
}
