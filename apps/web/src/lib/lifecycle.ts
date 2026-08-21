/**
 * What becomes of the app when you look away from it.
 *
 * # Why a messenger cannot ignore this
 *
 * On mobile, going to the background is not a pause: the system freezes timers, cuts open
 * connections, and may kill the process without warning. An app that relies on its `setInterval`
 * to stay current wakes up frozen on an hour-old state — and, worse, with a WebSocket that
 * **looks** open while nothing goes through it any more.
 *
 * Desktop browsers do a milder version of the same thing: Chrome throttles background-tab timers
 * to one firing per minute.
 *
 * # Resuming is not continuing
 *
 * On returning to the foreground, letting the interval restart is not enough: the app must poll
 * immediately and **reopen the stream**, without trying to find out whether it is still alive.
 * That question has no reliable answer — a socket cut by the system stays `OPEN` until the first
 * write — and asking it would cost more than reconnecting needlessly.
 *
 * # What this module does not do
 *
 * It knows nothing about sessions or the network. It reports transitions; what to do with them
 * belongs to the caller, the only one that knows what must be polled, reopened or relocked —
 * auto-lock, when it lands, plugs in exactly here.
 */

export type Transition =
  /** Back in the foreground. Forces a poll and a stream reopen. */
  | { kind: "resume"; awayMs: number }
  /** Moved to the background. */
  | { kind: "hidden" }
  /**
   * The network is back.
   *
   * Distinct from a resume: a laptop that regains Wi-Fi never left the foreground, and an app
   * listening only to visibility would stay silent there until the next poll.
   */
  | { kind: "network" };

/**
 * Subscribes to transitions, and returns a way to unsubscribe.
 *
 * `now` is injected so that the away duration is verifiable without a real clock.
 */
export function observeLifecycle(
  react: (transition: Transition) => void,
  now: () => number = () => Date.now(),
): () => void {
  // When the app went to the background. The away duration is for the caller: a second of
  // inattention and a whole night do not call for the same catch-up.
  let since = now();

  const visibility = () => {
    if (document.visibilityState === "hidden") {
      since = now();
      react({ kind: "hidden" });
      return;
    }
    react({ kind: "resume", awayMs: now() - since });
  };

  const online = () => react({ kind: "network" });

  document.addEventListener("visibilitychange", visibility);
  addEventListener("online", online);

  return () => {
    document.removeEventListener("visibilitychange", visibility);
    removeEventListener("online", online);
  };
}

/**
 * Is the network reported as available?
 *
 * `false` is trustworthy — no interface is up — and worth displaying. `true` guarantees nothing:
 * a captive portal, a dead server and a silent DNS all report "online". Which is why this value
 * only ever **explains** a failure, never decides whether to attempt one.
 */
export function networkReported(): boolean {
  return navigator.onLine !== false;
}

/**
 * How long away before a locked device asks for its password again.
 *
 * # Why a delay rather than an immediate lock
 *
 * Leaving the app for a second to copy a code received elsewhere is a common move, and asking
 * for the password on every round trip would get the lock removed — a lock that is too strict
 * protects nothing, it only teaches people to do without it.
 *
 * # Why not longer
 *
 * The window is exactly the one where a device left on a table is readable by whoever picks it
 * up. Five minutes is a compromise, not a threshold derived from anything; it lives here so it
 * can be argued about and changed in one place.
 */
export const RELOCK_MS = 5 * 60 * 1000;
