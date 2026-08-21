import type { ReactElement, ReactNode } from "react";
import * as RadixTooltip from "@radix-ui/react-tooltip";
import { cn } from "./cn.ts";
import { useOverlayContainer } from "./Overlays.tsx";

/**
 * One delay for the whole application.
 *
 * Mounted once by the shell, above everything. Radix's provider is what makes the *second*
 * tooltip in a row appear instantly: without a shared provider each tooltip re-runs its own
 * delay, and running a pointer along a row of icon buttons becomes a sequence of pauses.
 *
 * 500ms before the first one, and 300ms of grace during which moving to a neighbour opens
 * immediately. Long enough that a tooltip is never something that merely happened while the
 * pointer crossed the screen.
 */
export function TooltipProvider({ children }: { children: ReactNode }): ReactElement {
  return (
    <RadixTooltip.Provider delayDuration={500} skipDelayDuration={300}>
      {children}
    </RadixTooltip.Provider>
  );
}

/**
 * A label that appears next to a control, for a pointer that lingers.
 *
 * # It is a description, not a name, and never a substitute for one
 *
 * Radix wires the content as `aria-describedby`. That is deliberate on their part and correct:
 * the control's name is its own, and a tooltip is extra. So `Tooltip` **does not** give an
 * unlabelled control a name — `IconButton` says the same thing from the other side, which is why
 * its `label` stays required even when a tooltip repeats the word.
 *
 * # And it never opens for a finger
 *
 * There is no hover on a touch screen. Radix opens a tooltip on focus and on pointer-enter, and
 * a tap does neither in a way that leaves the tooltip up. Anything a touch user must be able to
 * read has to be somewhere else — a visible label, a caption under the control, or a sheet. This
 * component is an affordance for the pointer, and treating it as documentation loses every
 * mobile reader.
 *
 * # No arrow
 *
 * `Tooltip.Arrow` renders an SVG whose fill has to be given a literal colour to match the
 * surface, and it would be the only place in the tree carrying one. The offset and the
 * proximity already say which control the tooltip belongs to.
 *
 * What this does not solve: `children` must be a single element that forwards its ref, because
 * `Trigger asChild` clones it. A bare string breaks it, and the error Radix raises names the
 * Slot rather than this call site.
 */
export function Tooltip({
  label,
  side = "top",
  children,
}: {
  /** Short. A sentence in a tooltip is a sentence nobody finished reading. */
  label: string;
  side?: "top" | "bottom" | "left" | "right";
  children: ReactNode;
}): ReactElement {
  const container = useOverlayContainer();

  return (
    <RadixTooltip.Root>
      <RadixTooltip.Trigger asChild>{children}</RadixTooltip.Trigger>

      <RadixTooltip.Portal container={container ?? undefined}>
        <RadixTooltip.Content
          side={side}
          sideOffset={6}
          collisionPadding={8}
          className={cn(
            "z-(--z-index-overlay) rounded-control border border-(--color-border-strong)",
            "bg-(--color-surface-raised) px-snug py-tight text-caption text-(--color-ink) shadow-menu",
            // A tooltip that overhangs the window is a tooltip that gets clipped; Radix
            // measures the room left after it has flipped.
            "max-w-(--radix-tooltip-content-available-width)",
            // Outside the layout, so the shell's insets do not reach it.
            "safe-sides",
          )}
        >
          {label}
        </RadixTooltip.Content>
      </RadixTooltip.Portal>
    </RadixTooltip.Root>
  );
}
