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
 * belongs to the caller, the only one that knows what must be polled, reopened or relocked.
 * `observeIdle` below follows the same rule: it says "nobody has touched this in a while" and
 * leaves the consequence to the caller.
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
 * How long without the user before a locked device asks for its password again.
 *
 * The same delay covers both ways of being left alone: sent to the background, and sitting in the
 * foreground untouched. One number, because the two situations put the device in exactly the same
 * place — on a table, unlocked, in front of whoever walks past.
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

/**
 * How often the idle check runs. Coarse on purpose: it decides the precision of the delay, not
 * the delay itself, and a wake-up every thirty seconds costs nothing measurable.
 */
const IDLE_TICK_MS = 30_000;

/**
 * What counts as somebody being there.
 *
 * Listened to in the capture phase, because `scroll` and `wheel` do not bubble out of the element
 * they happened in — a conversation scrolled with the wheel would otherwise look like an empty
 * room.
 *
 * `pointermove` is deliberately not in the list. It would keep the session open on a cursor
 * nudged by a passing lorry, and on a touch screen it fires only when a finger is already down,
 * which `pointerdown` has already caught. The cost is real and worth stating: **reading without
 * touching the device counts as inactivity**, so a long article read on screen re-locks. From the
 * outside that is indistinguishable from a device left on a table, which is the case this exists
 * for.
 */
const ACTIVITY = ["pointerdown", "keydown", "wheel", "scroll", "touchstart"] as const;

/**
 * Calls back once nobody has touched `target` for `delayMs`.
 *
 * # Why a clock comparison and not a `setTimeout`
 *
 * A timer does not run while the machine is asleep or the tab is frozen: a lid closed for an hour
 * would fire five minutes after it reopens, which is five minutes of readable conversations in
 * the exact situation this is meant to cover. Comparing wall-clock stamps on a tick gives the
 * truth on the first check after waking, and it costs one subtraction.
 *
 * The tick's coarseness is the only imprecision: the lock lands somewhere in the thirty seconds
 * after the delay expires, never before it.
 *
 * # What it does not do
 *
 * It does not erase anything. Re-locking drops the state the interface holds and demands the
 * password again; the key stays in the process — the WebAssembly module keeps its own state and
 * nothing in a browser lets us demand otherwise. This protects against whoever picks the device
 * up, not against whoever reads its memory.
 *
 * # Why the delay is not a setting
 *
 * It was considered and left out. A delay long enough to stop being annoying is long enough to
 * stop protecting, and the choice would be made by someone judging their own patience rather than
 * how long a laptop sits unattended in an office. Worse, the value would have to be readable
 * *before* unlocking, hence stored in the clear next to encrypted state — a small leak, but paid
 * for a setting whose only likely use is turning the protection off. `RELOCK_MS` is one constant
 * in one file; if the five minutes turn out to be wrong, they are wrong for everybody and get
 * changed here.
 */
export function observeIdle(
  relock: () => void,
  target: EventTarget,
  now: () => number = () => Date.now(),
  delayMs: number = RELOCK_MS,
): () => void {
  let last = now();
  const touched = () => {
    last = now();
  };

  const options = { capture: true, passive: true };
  for (const event of ACTIVITY) target.addEventListener(event, touched, options);

  const id = setInterval(() => {
    if (now() - last < delayMs) return;

    // The clock is restarted before calling back, so that a caller which decides it has nothing to
    // lock — no session, or no lock set — does not get asked again on every tick from then on.
    last = now();
    relock();
  }, IDLE_TICK_MS);

  return () => {
    clearInterval(id);
    for (const event of ACTIVITY) target.removeEventListener(event, touched, { capture: true });
  };
}
