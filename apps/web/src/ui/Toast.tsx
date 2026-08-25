import * as RadixToast from "@radix-ui/react-toast";
import { createPortal } from "react-dom";
import type { ReactElement } from "react";
import type { Message } from "../state/report.ts";
import { useReported } from "../state/report.ts";
import { Button } from "./Button.tsx";
import { cn } from "./cn.ts";
import { Icon } from "./Icon.tsx";
import { IconButton } from "./IconButton.tsx";
import { useOverlayContainer } from "./Overlays.tsx";

/**
 * What just happened, said in one place.
 *
 * # Both halves come here now, and that is the change
 *
 * A confirmation always did. An error went to a `Banner` mounted as a flex child of the shell —
 * full-bleed, corners squared off through a `className`, and **shrinking the conversation to make
 * room for itself**. Up to four of those could stack. Errors float here instead; the three
 * remaining banners in `App.tsx` stay where they are because they describe standing conditions
 * (offline, an inconsistent key log) rather than events, and a standing condition belongs in the
 * layout.
 *
 * # This file still owns no state and no timer
 *
 * `state/report.ts` holds both, and the reason is worth repeating at the place that would get it
 * wrong: a component running its own `setTimeout` restarts it on every re-render of its parent. In
 * a thread receiving messages that means the timer never expires and a four-second confirmation
 * stays until the conversation goes quiet.
 *
 * Radix has a `duration` of its own, so it is set to `Infinity` on both roots — not because
 * nothing should expire, but because **two owners of one expiry is one owner too many**. What
 * closes a toast is `report.ts` letting go of it.
 *
 * # Why Radix rather than the portal this file used to be
 *
 * One reason: a toast can now carry a button, and a button that appears unbidden has to be
 * reachable by keyboard **without stealing focus**. That is not a `<button>` in a `<div>`; it is a
 * viewport in the tab order, a recall hotkey, and an announcement whose urgency matches the
 * message. Radix implements the pattern and this file would have implemented it worse.
 *
 * It also buys an exit. `ui/Overlays.tsx` records that `useEntered` has no counterpart because
 * Radix unmounts content the moment it closes; `RadixToast` keeps the node through
 * `data-state="closed"`, so a dismissed message fades instead of blinking out.
 *
 * # Which one interrupts
 *
 * `type="foreground"` for an error, `"background"` for a confirmation. That is the same
 * distinction `ui/Banner.tsx` draws between `role="alert"` and `role="status"`, and the same
 * sentence `docs/ACCESSIBILITY.md` writes: interrupt somebody mid-sentence only when they must
 * stop for it. A confirmation has already happened and nothing waits on the reader.
 */
export function Toasts(): ReactElement | null {
  const { error, toast, dismissError, dismissToast } = useReported();
  const container = useOverlayContainer();

  // The only null case: `index.html` has lost its `#overlays` node. Drawing a fixed-position
  // toast inside the layout instead would put it behind a pane or clip it against one, which is
  // a worse answer than showing nothing while the markup is broken.
  if (!container) return null;

  return (
    // `swipeDirection` is what makes a touch dismissal possible at all; both roots are controlled,
    // so a swipe reaches `report.ts` rather than closing something that reappears on the next
    // render.
    <RadixToast.Provider swipeDirection="down" duration={Infinity}>
      {error === null ? null : (
        <Reported
          key={`error-${error.id}`}
          message={error}
          tone="danger"
          onDismiss={dismissError}
        />
      )}
      {toast === null ? null : (
        <Reported key={`toast-${toast.id}`} message={toast} tone="ok" onDismiss={dismissToast} />
      )}

      {createPortal(
        <RadixToast.Viewport
          // **`aria-label` and not the `label` prop.** Radix documents `label` as the accessible
          // name and its types accept it, but in 1.2.23 it reaches no attribute: the rendered
          // `<ol>` carries `tabindex` and `class` and nothing else. Checked in the browser rather
          // than assumed, because a prop that silently does nothing is worse than no prop — it
          // reads as solved.
          //
          // Named at all because the viewport is focusable, so a screen reader navigating by
          // region would otherwise find an anonymous list. F8 is the key Radix binds to reach it.
          aria-label="Messages from Whispee (F8)"
          className={cn(
            // Above a dialog — and more so since the settings became one: an action taken *inside*
            // a dialog still has to be able to report that it worked. `--z-index-toast` exists for
            // this one relationship.
            "pointer-events-none fixed inset-x-0 bottom-0 z-(--z-index-toast)",
            // The portal mounts outside the layout, so the shell's insets do not reach it.
            "flex flex-col items-center gap-snug p-pane safe-bottom safe-sides",
            // No `outline-none`: the viewport is focusable on purpose — it is how a keyboard user
            // reaches a message that appeared without being asked for.
            "m-0 list-none",
          )}
        />,
        container,
      )}
    </RadixToast.Provider>
  );
}

/**
 * One message, whichever surface raised it.
 *
 * Keyed by its id from the caller, so a replacement is a new node: without that React sees the
 * same component in the same position and merely swaps the text — the entrance never replays, and
 * two failures in a row look like one that changed its mind. The id exists in `report.ts`
 * precisely so that the second is visibly a second event.
 */
function Reported({
  message,
  tone,
  onDismiss,
}: {
  message: Message;
  tone: "danger" | "ok";
  onDismiss: () => void;
}) {
  return (
    <RadixToast.Root
      // Controlled, and closing always goes through `report.ts`. Radix closes on a swipe, on the
      // cross, and on the hotkey; every one of those has to reach the state or the message comes
      // back on the next render.
      open
      onOpenChange={(next) => {
        if (!next) onDismiss();
      }}
      // See the module header: the expiry lives in `report.ts`, and two owners of it is one too
      // many.
      duration={Infinity}
      type={tone === "danger" ? "foreground" : "background"}
      className={cn(
        "pointer-events-auto flex w-full max-w-md items-start gap-gutter",
        "rounded-control border bg-(--color-surface-raised) px-pane py-snug shadow-overlay",
        // The hairline is mandatory rather than decorative: over the dark palette's ground a black
        // shadow is very nearly invisible, so the border is what separates the surface from what
        // is behind it. `index.css` says so where the shadow is defined.
        tone === "danger" ? "border-(--color-danger)" : "border-(--color-border-strong)",
        // Entrance and exit both, through tokens — `prefers-reduced-motion` collapses them to 1ms
        // in `index.css`, so nothing here reads the preference.
        "transition-all duration-(--duration-panel) ease-out motion-reduce:transition-none",
        "data-[state=open]:translate-y-0 data-[state=open]:opacity-100",
        "data-[state=closed]:translate-y-2 data-[state=closed]:opacity-0",
        "data-[swipe=end]:translate-y-full data-[swipe=end]:opacity-0",
      )}
    >
      {/*
        * The text is the same ink in both tones. Colour is not what tells the two apart — the
        * border is, and it carries 3:1 against the surface, which is what `docs/ACCESSIBILITY.md`
        * asks of a border that means something. Tinting the sentence red would say the same thing
        * a second time, to the readers who could already see it.
        */}
      <RadixToast.Description className="min-w-0 flex-1 text-body text-(--color-ink)">
        {message.message}
      </RadixToast.Description>

      {message.action === undefined ? null : (
        // `altText` is what a screen reader is offered in place of the button when the toast is
        // announced — Radix requires it, and rightly: "Retry" alone says nothing about what would
        // be retried once the sentence has scrolled past.
        <RadixToast.Action asChild altText={`${message.action.label}: ${message.message}`}>
          <Button size="sm" variant="secondary" onClick={message.action.run}>
            {message.action.label}
          </Button>
        </RadixToast.Action>
      )}

      <RadixToast.Close asChild>
        <IconButton label="Dismiss" icon={<Icon name="close" />} size="sm" className="shrink-0" />
      </RadixToast.Close>
    </RadixToast.Root>
  );
}
