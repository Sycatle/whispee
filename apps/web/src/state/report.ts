/**
 * Telling the user what just happened — both halves of it.
 *
 * # What this replaces, and what it adds
 *
 * It replaces the `onError` prop threaded down from `App.tsx`, which was the client's only
 * feedback channel. And it adds the half that has never existed: there is today **no toast, no
 * confirmation, nothing at all** anywhere in this application when an action succeeds. Sending,
 * pairing a device, rotating a key, restoring history — all of them are silent when they work.
 * Silence on success is readable when the result is visible (a message appears in the thread) and
 * unreadable when it is not (a device was revoked; was it?).
 *
 * # Two surfaces, because the two have different lifetimes
 *
 * **Errors stay until dismissed or replaced, and they are always dismissible.** That rule is
 * inherited verbatim from `App.tsx` and it is worth restating: an error you cannot wave away ends
 * up part of the scenery, and scenery is not read. It stays because an error usually means
 * something still has to be decided.
 *
 * It used to be a full-bleed banner mounted in the shell's flex column, which shrank the
 * conversation for as long as it stood. It floats now, beside the confirmations — the lifetime
 * did not move, only the rendering. `ui/Toast.tsx` draws both.
 *
 * **Successes go to a toast, one at a time, for four seconds.** A success has already happened;
 * nothing is pending on the reader, so it expires on its own. One at a time rather than a stack:
 * a stack of confirmations is a wall in front of the thread, and each new one replacing the last
 * is the honest behaviour when the last one no longer needs an answer. The cost is real and worth
 * naming — two successes within four seconds means the first is never read. That is the right
 * trade for confirmations and would be the wrong one for anything the user has to act on, which
 * is why errors are not routed here.
 *
 * # What this module does not render
 *
 * No DOM. It owns the state and the timer, and hands both out. `ui/Toast.tsx` draws both from
 * `useReported()`.
 *
 * The contract that matters for them: **the expiry lives here, not in the component.** A toast
 * component that ran its own `setTimeout` would restart it on every re-render of its parent, and
 * a busy thread would pin a confirmation on screen indefinitely. The component's job is to render
 * `reported.toast` and nothing else; when it turns null, the toast is over. `toast.id` is there to
 * be used as a React `key`, so that a replacement re-runs the entrance animation rather than
 * silently swapping the text of the one already on screen.
 */
import {
  createContext,
  createElement,
  use,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

/** How long a confirmation stays up. Long enough to read a short sentence, short enough to ignore. */
export const TOAST_MS = 4000;

/**
 * Something the reader can do about what just happened.
 *
 * Optional, and rare on purpose. A confirmation has nothing to offer — the thing already worked.
 * A failure sometimes does: "Retry" on a send that did not go out is worth more than a sentence
 * explaining that it did not.
 *
 * `run` is called on click and nothing else happens: dismissing afterwards is the caller's
 * business, because only it knows whether the retry succeeded. An action that reported its own
 * outcome would raise a second message on top of the first, and the first is what it replaced.
 */
export interface Action {
  label: string;
  run: () => void;
}

/**
 * One thing to say, whichever surface it lands on.
 *
 * # Why the error has an id now
 *
 * It did not, and that was an asymmetry with a cost. The id is what a React `key` uses to tell a
 * replacement from the same message still hanging around — "Copied" twice in a row is the ordinary
 * case for a confirmation, and two identical failures in a row is the ordinary case for a poll
 * against a server that is down. Without it the second one silently reuses the first one's node
 * and the entrance never replays, so nothing on screen says a new thing happened.
 */
export interface Message {
  id: number;
  message: string;
  action?: Action;
}

/** Kept as the old name for what a confirmation is, because that is what the callers call it. */
export type Toast = Message;

/** What the shell needs in order to draw. */
export interface Reported {
  /** The standing error, or null. Survives until dismissed or replaced. */
  error: Message | null;
  /** The confirmation currently on screen, or null. Expires by itself. */
  toast: Message | null;
  dismissError: () => void;
  /**
   * Takes a confirmation down before its time is up.
   *
   * It expires on its own, so nothing needs this to be correct — until the surface drawing it
   * lets somebody swipe or close it. A dismissal the state does not hear about is a toast that
   * reappears on the next render, which looks like a bug in the message rather than in the
   * plumbing.
   */
  dismissToast: () => void;
}

/** What everybody else needs in order to speak. */
export interface Report {
  error: (message: string, action?: Action) => void;
  done: (message: string, action?: Action) => void;
}

/**
 * Two contexts rather than one, and the reason is not symmetry.
 *
 * `Report` never changes identity, so a component that only ever *reports* — which is most of
 * them — subscribes to nothing and re-renders never. Merging the two would make every button that
 * can raise an error re-render each time an unrelated toast appears and expires.
 */
const ReportContext = createContext<Report | null>(null);
const ReportedContext = createContext<Reported | null>(null);

export function ReportProvider({ children }: { children: ReactNode }) {
  const [error, setError] = useState<Message | null>(null);
  const [toast, setToast] = useState<Message | null>(null);
  /**
   * Monotonic, and never reset. It only has to be unique within one run of the application; the
   * alternative — a timestamp — collides for two toasts raised in the same millisecond, which is
   * exactly what a loop over several devices does.
   */
  const nextId = useRef(0);
  const expiry = useRef<ReturnType<typeof setTimeout>>(undefined);

  const report = useMemo<Report>(
    () => ({
      // No timer, and that is the whole difference between the two. An error waits to be
      // dismissed or replaced; see this module's header for why.
      error: (message, action) => {
        nextId.current += 1;
        setError({ id: nextId.current, message, action });
      },
      done: (message, action) => {
        // Cleared before rescheduling: without this, the first toast's timer would still be
        // running and would take the replacement down early.
        clearTimeout(expiry.current);
        nextId.current += 1;
        setToast({ id: nextId.current, message, action });
        expiry.current = setTimeout(() => setToast(null), TOAST_MS);
      },
    }),
    [],
  );

  // The timer outlives the component if the shell unmounts mid-toast — during a re-lock, say —
  // and would then set state on something that is gone.
  useEffect(() => () => clearTimeout(expiry.current), []);

  const dismissError = useCallback(() => setError(null), []);
  const dismissToast = useCallback(() => {
    // The timer goes with it: left running it would fire against a toast that is already gone,
    // which is harmless today and would not be if this ever cleared something newer.
    clearTimeout(expiry.current);
    setToast(null);
  }, []);
  const reported = useMemo<Reported>(
    () => ({ error, toast, dismissError, dismissToast }),
    [error, toast, dismissError, dismissToast],
  );

  return createElement(
    ReportContext,
    { value: report },
    createElement(ReportedContext, { value: reported }, children),
  );
}

/**
 * How to say something happened.
 *
 * Both take a sentence already fit to be read by a person. Nothing here formats, truncates or
 * translates: an `Error` object stringified into a banner is how "TypeError: undefined is not a
 * function" reaches a user, and the only place that knows what a failure meant is the caller.
 */
export function useReport(): Report {
  const report = use(ReportContext);
  if (!report) throw new Error("useReport must be used inside a <ReportProvider>");
  return report;
}

/**
 * What is currently being shown. For the shell and for `ui/Toast.tsx` — nobody else.
 *
 * Reading this subscribes to every banner and every toast, which is the right cost for the two
 * components that draw them and a pointless one for anyone who merely reports.
 */
export function useReported(): Reported {
  const reported = use(ReportedContext);
  if (!reported) throw new Error("useReported must be used inside a <ReportProvider>");
  return reported;
}
