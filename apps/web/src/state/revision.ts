/**
 * A monotonic counter, and whoever is listening to it.
 *
 * # Why a counter rather than a store
 *
 * The source of truth of this client lives outside React. `lib/session.ts` is a mutable class:
 * messages are pushed into `view.messages` in place, and `session.conversations.get(key)` hands
 * back **the same object** before and after a mutation. Nothing about a session changes identity
 * when its contents change.
 *
 * That is fatal to every React equality check. `React.memo` would compare two references that are
 * equal and skip the render that a new message requires; `useMemo(…, [session, view])` would keep
 * returning the value it computed the first time, forever.
 *
 * `useSyncExternalStore` needs a `getSnapshot` that **changes** when the world changes. The
 * session cannot provide one. This counter can, and that is the whole of its job: `Session`
 * mutates in place and calls `bump()`, and the number React reads is different afterwards.
 *
 * # This holds no data, on purpose
 *
 * Rewriting `Session` as an immutable store is another piece of work, and a risky one on code
 * that advances an MLS ratchet — a lost mutation there is not a stale pixel, it is a conversation
 * that can no longer be decrypted. So the constraint is not removed here; it is made explicit and
 * hard to breach by accident. The data stays where it is.
 *
 * # What this does not solve: granularity
 *
 * There is one counter for the whole session. A message arriving bumps the same number a settings
 * toggle does, so every subscriber re-renders on every change, whatever it was actually reading.
 *
 * That is precisely today's behaviour — `forceRender` sits at the root of `App.tsx` and re-renders
 * the entire tree — so it is not a regression, and it is not the thing to fix first. A counter per
 * conversation is an optimisation to measure on a real thread with real message volume, not one to
 * assume: it would multiply the subscriptions and hand every caller of `bump()` the new duty of
 * naming what it touched, which is exactly the kind of duty that gets forgotten silently.
 */

/** Called after every `bump`. Takes no argument: the new value is read through `getSnapshot`. */
export type Listener = () => void;

export class Revision {
  #value = 0;
  readonly #listeners = new Set<Listener>();

  /**
   * Registers a listener and returns the way to remove it.
   *
   * An arrow field rather than a method: `useSyncExternalStore` re-subscribes whenever the
   * function it is handed changes identity, and a prototype method read off the instance would
   * still be stable — but only until someone destructures the object. Binding here makes
   * `const { subscribe } = revision` behave, which is how it will be used.
   */
  subscribe = (listener: Listener): (() => void) => {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  };

  /** The current value. Stable identity, for the same reason `subscribe` is. */
  getSnapshot = (): number => this.#value;

  /**
   * Records that something changed, and tells everyone.
   *
   * Iterating a copy: a listener is free to unsubscribe while being notified — a component
   * unmounting as a result of what it just read is the ordinary case — and mutating the set under
   * its own iteration would skip whoever came next.
   */
  bump = (): void => {
    this.#value += 1;
    for (const listener of [...this.#listeners]) listener();
  };
}
