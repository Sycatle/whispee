import { createPortal } from "react-dom";
import type { ReactElement } from "react";
import { useReported } from "../state/report.ts";
import { cn } from "./cn.ts";
import { useEntered, useOverlayContainer } from "./Overlays.tsx";

/**
 * The confirmation that an action worked.
 *
 * # This file owns no state and no timer, and that is the contract
 *
 * `state/report.ts` holds both. It says so in its own header and the reason is worth repeating
 * here, at the place that would get it wrong: a component running its own `setTimeout` restarts
 * it on every re-render of its parent. In a thread receiving messages that means the timer never
 * expires and a four-second confirmation stays on screen until the conversation goes quiet.
 *
 * So this reads `useReported().toast` and draws it. When the field turns null, the toast is over.
 * Nothing here schedules anything.
 *
 * # `key={toast.id}`
 *
 * One toast at a time, and a new one replaces the old. Without the key React sees the same
 * component in the same position and merely swaps the text — the entrance never replays, and two
 * confirmations in a row look like one that changed its mind. The id exists in `report.ts`
 * precisely so that "Copied" following "Copied" is still visibly a second event.
 *
 * # The live region outlives the toast
 *
 * `role="status"` with `aria-live="polite"` is on the *container*, which is mounted for as long
 * as the shell is, empty or not. A live region that appears at the same moment as its content is
 * unreliable — several screen readers only announce changes to a region they were already
 * observing, so a region that mounts with its message announces nothing. Mounting it empty and
 * filling it later is what makes the announcement happen.
 *
 * Polite and not assertive: a confirmation has already happened and nothing is waiting on the
 * reader. Interrupting them mid-sentence to say an action they just took succeeded is the exact
 * habit that teaches people to ignore the channel. Errors are the assertive half and they do not
 * come here — they go to a `Banner`, per `report.ts`.
 *
 * What this does not solve: it does not stack, and it must not. Two successes within four
 * seconds means the first is never read; `report.ts` chose that deliberately and the fix, if it
 * is ever needed, is to collapse the events upstream rather than to grow a queue here.
 */
export function Toasts(): ReactElement | null {
  const { toast } = useReported();
  const container = useOverlayContainer();

  // The only null case: `index.html` has lost its `#overlays` node. Drawing a fixed-position
  // toast inside the layout instead would put it behind a pane or clip it against one, which is
  // a worse answer than showing nothing while the markup is broken.
  if (!container) return null;

  return createPortal(
    <div
      role="status"
      aria-live="polite"
      className={cn(
        // Above a dialog: an action taken *inside* a confirmation still has to be able to report
        // that it worked. `--z-index-toast` exists for this one relationship.
        "pointer-events-none fixed inset-x-0 bottom-0 z-(--z-index-toast)",
        "flex justify-center p-pane safe-bottom safe-sides",
      )}
    >
      {toast === null ? null : <Confirmation key={toast.id} message={toast.message} />}
    </div>,
    container,
  );
}

/**
 * Separate so that the key remounts it: the entrance lives in `useEntered`, which only runs from
 * the beginning when the component is new. Keying the container instead would tear down the live
 * region with every toast, and the announcement with it.
 */
function Confirmation({ message }: { message: string }) {
  const entered = useEntered();

  return (
    <div
      className={cn(
        "max-w-full rounded-control border border-(--color-border-strong)",
        "bg-(--color-surface-raised) px-pane py-snug text-body text-(--color-ink) shadow-overlay",
        "transition duration-(--duration-panel) ease-out motion-reduce:transition-none",
        entered ? "translate-y-0 opacity-100" : "translate-y-2 opacity-0",
      )}
    >
      {message}
    </div>
  );
}
