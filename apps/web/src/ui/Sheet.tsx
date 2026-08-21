import type { ReactElement, ReactNode } from "react";
import * as RadixDialog from "@radix-ui/react-dialog";
import { cn } from "./cn.ts";
import { Icon } from "./Icon.tsx";
import { IconButton } from "./IconButton.tsx";
import { useEntered, useOverlayContainer } from "./Overlays.tsx";

/**
 * The same modal as [`Dialog`], presented as a screen instead of a card.
 *
 * # Same API, and that is the point
 *
 * A caller switching one for the other changes the import and nothing else. The difference is
 * presentation, not semantics: both are modal, both trap focus, both mark the rest of the page
 * inert, both lock scrolling, both give focus back to their trigger. Two components rather than
 * a `variant` prop on one because the choice is made once per screen and never varies at run
 * time — a settings editor is a sheet on a phone and a sheet on a desktop, it does not become a
 * dialog when the window widens.
 *
 * # Full screen below `duo`, a card above it
 *
 * Below 48rem there is one pane, so a modal that covers 80% of it is a card floating on a
 * postage stamp. It takes the whole screen instead, and the entrance slides it up from the
 * bottom — which is the edge the gesture came from. Above `duo` there is room for it to be a
 * card again, anchored near the top rather than centred so that growing content does not make it
 * creep upwards as it fills.
 *
 * The layout is a flex column with the body scrolling and the header and the actions pinned.
 * That is the whole reason this is not [`Dialog`] with different classes: a full-screen surface
 * whose actions scroll away has put its primary button below the fold on a long form.
 *
 * `safe-top`, `safe-bottom` and `safe-sides` are all three present and all three necessary here
 * specifically. A card in the middle of the screen never meets a notch; a surface pinned to
 * every edge of a phone meets all of them, and this is the exact component on which the audit's
 * missing insets would have shown.
 *
 * # One breakpoint, expressed in CSS and not in JavaScript
 *
 * `useDuo()` exists and is deliberately not used here. It answers "which pane do I mount", which
 * is a question about state; this is a question about appearance, and a `duo:` variant answers it
 * before the first paint rather than after the first effect. A sheet that flashed as a card while
 * `matchMedia` was consulted would be the worst of both.
 *
 * What this does not solve: it does not swipe down to dismiss. That is the native gesture for
 * this shape and its absence is felt, but implementing it means owning the drag, the velocity
 * threshold and the rubber-banding, and doing it badly is worse than not having it.
 */
export function Sheet({
  open,
  onOpenChange,
  title,
  hideTitle = false,
  description,
  actions,
  children,
  tone = "default",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The accessible name, and normally the visible heading. Never empty, never optional. */
  title: string;
  /** Moves the heading out of view. The name stays in the accessibility tree either way. */
  hideTitle?: boolean;
  /** One or two sentences under the heading: what this is about, and what it costs. */
  description?: string;
  /** The buttons that answer the question. Pinned to the bottom, never scrolled away. */
  actions?: ReactNode;
  children?: ReactNode;
  tone?: "default" | "danger";
}): ReactElement {
  const container = useOverlayContainer();
  // Driven by `open` rather than by this component's own mount: `Sheet` stays mounted between
  // openings, so an entrance tied to the mount would play once and never again.
  const entered = useEntered(open);

  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      {/* Without `container`, Radix mounts in `document.body` — outside the node the shell owns,
          and therefore outside the safe areas. See `Overlays.tsx`. */}
      <RadixDialog.Portal container={container ?? undefined}>
        <RadixDialog.Overlay
          className={cn(
            "fixed inset-0 z-(--z-index-overlay)",
            // Literal, for the reason spelled out in `Dialog.tsx`: a scrim must darken, and no
            // role token darkens in both palettes.
            "bg-[oklch(0_0_0_/_0.45)]",
          )}
        />

        <RadixDialog.Content
          data-tone={tone}
          className={cn(
            "fixed z-(--z-index-overlay) flex flex-col bg-(--color-surface)",
            // One pane: the sheet *is* the screen. Every inset applies, and all four edges are met.
            "inset-0 safe-top safe-bottom safe-sides",
            // Two panes and up: a card near the top. Centred with `margin`, not with a transform,
            // so the transform stays free for the entrance below.
            "duo:inset-x-0 duo:bottom-auto duo:top-16 duo:mx-auto",
            "duo:max-h-[calc(100dvh-8rem)] duo:w-[calc(100%-2rem)] duo:max-w-lg",
            "duo:rounded-control duo:border duo:shadow-overlay",
            tone === "danger" ? "duo:border-(--color-danger)" : "duo:border-(--color-border-strong)",
            // `--duration-panel` and not `--duration-quick`: this is a surface arriving, not a
            // menu popping. Both collapse to 1ms under `prefers-reduced-motion`, so nothing here
            // reads the preference.
            "transition duration-(--duration-panel) ease-out motion-reduce:transition-none",
            entered
              ? "translate-y-0 opacity-100"
              : // From below at one pane, because that is the edge a sheet belongs to. Barely at
                // all above `duo`, where the same distance would read as a slam.
                "translate-y-full opacity-0 duo:translate-y-2",
          )}
        >
          <div
            className={cn(
              "flex shrink-0 items-start gap-gutter border-b p-pane",
              tone === "danger" ? "border-(--color-danger)" : "border-(--color-border-subtle)",
            )}
          >
            <div className="min-w-0 flex-1">
              <RadixDialog.Title
                className={cn(
                  hideTitle
                    ? "sr-only"
                    : cn(
                        "text-title font-medium",
                        tone === "danger" ? "text-(--color-danger)" : "text-(--color-ink)",
                      ),
                )}
              >
                {title}
              </RadixDialog.Title>

              {description === undefined ? null : (
                <RadixDialog.Description
                  className={cn("text-body text-(--color-ink-muted)", hideTitle ? null : "mt-snug")}
                >
                  {description}
                </RadixDialog.Description>
              )}
            </div>

            {/* Escape and a tap outside already close it; this is for the reader looking for a
                cross, which on a full-screen surface is the only visible way out. */}
            <RadixDialog.Close asChild>
              <IconButton label="Close" icon={<Icon name="close" />} className="-mr-snug -mt-snug" />
            </RadixDialog.Close>
          </div>

          {/* The only part that scrolls. `min-h-0` because a flex child defaults to `min-height:
              auto`, which refuses to shrink below its content — the usual reason an overflow
              inside a flex column pushes the footer off the screen instead of scrolling. */}
          <div className="min-h-0 flex-1 overflow-y-auto p-pane text-body">{children}</div>

          {actions === undefined ? null : (
            <div className="flex shrink-0 flex-wrap justify-end gap-snug border-t border-(--color-border-subtle) p-pane">
              {actions}
            </div>
          )}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}
