import type { ReactElement, ReactNode } from "react";
import * as RadixPopover from "@radix-ui/react-popover";
import { cn } from "./cn.ts";
import { useOverlayContainer } from "./Overlays.tsx";

/**
 * A panel of arbitrary content, anchored to whatever opened it.
 *
 * # Why this exists next to `Menu`
 *
 * They look alike and they are not interchangeable. `Menu` is a Radix `DropdownMenu`, which
 * gives every child `role="menuitem"` and moves between them with the arrow keys in one
 * dimension. The first caller here is an emoji grid of 1,595 cells: announced as a menu it would
 * be 1,595 menu items, and navigated as one it would take 1,595 presses of the down arrow to
 * cross. A grid is a grid, and `Popover` is the primitive that lets it be one — it contributes
 * a labelled dialog and nothing else, and its content owns its own keyboard model.
 *
 * # Controlled, always
 *
 * `open` and `onOpenChange` are required rather than optional. A picker closes when something is
 * picked, which is a decision the content makes and the trigger cannot see; leaving the state
 * inside Radix would mean the panel stays open after every choice.
 *
 * # The layout rules are `Menu`'s, for the same reasons
 *
 * No fixed width, no absolute `max-w`, no positioning of our own: Radix computes the available
 * space after deciding which way to flip, and anything absolute here overrides the measurement
 * and reintroduces the overflow it just avoided. `side` and `align` are preferences, not
 * instructions — in a 480px window a panel asked to open to the right will open to the left, and
 * that is correct.
 *
 * The hairline is `border-strong` and that is not decoration: in the dark palette a black shadow
 * over an L=0.22 ground is invisible, so the edge is the only thing separating this from what is
 * behind it. `index.css` says so in the elevation note.
 *
 * # What this does not solve
 *
 * It is not modal. The rest of the page stays interactive and is not marked inert, which is
 * right for a panel you open beside your work and wrong for a question you must answer — that is
 * `Dialog`, or `Sheet`. On a single-pane screen a popover is the wrong shape entirely and the
 * caller should mount its content in a `Sheet` instead; `useDuo()` is how that choice is made.
 */
export function Popover({
  trigger,
  open,
  onOpenChange,
  label,
  align = "start",
  side = "top",
  children,
}: {
  /** The control that opens the panel. Cloned by Radix, so it must forward its ref. */
  trigger: ReactNode;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * The accessible name of the panel. Required, because Radix gives the content `role="dialog"`
   * and an unnamed dialog is announced as "dialog" and nothing else.
   */
  label: string;
  align?: "start" | "center" | "end";
  side?: "top" | "bottom" | "left" | "right";
  children: ReactNode;
}): ReactElement {
  const container = useOverlayContainer();

  return (
    <RadixPopover.Root open={open} onOpenChange={onOpenChange}>
      <RadixPopover.Trigger asChild>{trigger}</RadixPopover.Trigger>

      {/* Without `container`, Radix mounts in `document.body` — outside the node the shell owns,
          and therefore outside the safe areas. See `Overlays.tsx`. */}
      <RadixPopover.Portal container={container ?? undefined}>
        <RadixPopover.Content
          aria-label={label}
          side={side}
          align={align}
          sideOffset={6}
          collisionPadding={8}
          className={cn(
            "z-(--z-index-overlay) rounded-control border border-(--color-border-strong)",
            "bg-(--color-surface-raised) shadow-menu",
            // Measured by Radix after it has decided which way to flip.
            "max-w-(--radix-popover-content-available-width)",
            "max-h-(--radix-popover-content-available-height)",
            "safe-sides safe-bottom",
          )}
        >
          {children}
        </RadixPopover.Content>
      </RadixPopover.Portal>
    </RadixPopover.Root>
  );
}
