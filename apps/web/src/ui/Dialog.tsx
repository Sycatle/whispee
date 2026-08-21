import type { ReactElement, ReactNode } from "react";
import * as RadixDialog from "@radix-ui/react-dialog";
import { cn } from "./cn.ts";
import { Icon } from "./Icon.tsx";
import { IconButton } from "./IconButton.tsx";
import { useOverlayContainer } from "./Overlays.tsx";

/**
 * A modal that asks for one answer before anything else can happen.
 *
 * # Four absences, all bought by Radix rather than written here
 *
 * The audit listed them separately; they are one omission. This application had no modal at all,
 * and every hand-rolled modal omits the same things because they are invisible when missing:
 *
 *   - **The focus trap.** Tab out of a dialog with no trap and focus walks into the conversation
 *     behind it, where a keyboard user is now typing into something they cannot see.
 *   - **`inert` on the rest.** Not the same as the trap: it is what stops a screen reader from
 *     reading the page underneath as if it were still the subject.
 *   - **The scroll lock.** Scrolling the thread behind a confirmation makes the confirmation
 *     look like part of the page rather than a question about it.
 *   - **Restoring focus to the trigger on close.** The one nobody writes, and the one that
 *     decides whether a keyboard user is back where they were or back at the top of the document.
 *
 * Radix does all four. That is the reason this file is thirty lines of layout around
 * `@radix-ui/react-dialog` and not an implementation.
 *
 * # `title` is required, and it is required in the type
 *
 * A dialog with no accessible name is announced as "dialog", which tells the reader that
 * something has taken over the screen and nothing about what. Making it a required `string`
 * rather than a `ReactNode` is the same move `IconButton` makes for `label`: the name is text,
 * and a name assembled from elements is a name that can end up empty.
 *
 * `hideTitle` covers the case where the heading would be redundant on screen — a dialog whose
 * whole content already says what it is. It moves the title out of view; **it never removes
 * it.** Radix would otherwise warn, and more to the point the dialog would lose its name for
 * exactly the readers who cannot see the content that made it redundant.
 *
 * # `tone="danger"` is for what does not come back
 *
 * Forgetting an identity, revoking a device, leaving a group. It reddens the edge and the
 * heading and leaves the body in normal ink — the same doctrine as [`Panel`], for the same
 * reason: the paragraph explaining what will be lost is the one thing that has to be readable.
 * The tone does not change the buttons; a destructive dialog still has to be given a
 * `variant="destructive"` action by its caller, because only the caller knows which of its
 * actions is the dangerous one.
 *
 * What this does not solve: nothing here debounces. A dialog opened by a key that repeats, or by
 * two components at once, is a call-site problem — `open` is controlled, and whoever owns it
 * owns that.
 */
export function Dialog({
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
  /** The buttons that answer the question. Laid out at the end, cancel first by convention. */
  actions?: ReactNode;
  children?: ReactNode;
  tone?: "default" | "danger";
}): ReactElement {
  const container = useOverlayContainer();

  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      {/* Without `container`, Radix mounts in `document.body` — outside the node the shell owns.
          See `Overlays.tsx` for why that is not merely untidy. */}
      <RadixDialog.Portal container={container ?? undefined}>
        <RadixDialog.Overlay
          className={cn(
            "fixed inset-0 z-(--z-index-overlay)",
            /* A literal colour, and one of the only ones in the tree. A scrim has to *darken*,
               and no role token darkens in both palettes: `--color-ink` is near-white in dark,
               `--color-surface-sunken` is near-white in light. This mirrors the shadow tokens in
               `index.css`, which are literal black for the same reason.

               What it does not solve: over the dark palette's L=0.17 ground it separates weakly,
               which is why the hairline and the shadow on the panel below are not decoration. */
            "bg-[oklch(0_0_0_/_0.45)]",
          )}
        />

        <RadixDialog.Content
          data-tone={tone}
          className={cn(
            "fixed left-1/2 top-1/2 z-(--z-index-overlay) -translate-x-1/2 -translate-y-1/2",
            // Never wider than the window minus a margin, never taller than it: a dialog that
            // overflows the viewport puts its actions off-screen, where they cannot be reached.
            "w-[calc(100%-2rem)] max-w-md max-h-[calc(100dvh-2rem)] overflow-y-auto",
            // The portal is outside the layout, so the shell's insets do not reach it.
            "safe-sides",
            "rounded-control border bg-(--color-surface-raised) p-pane shadow-overlay",
            tone === "danger" ? "border-(--color-danger)" : "border-(--color-border-strong)",
          )}
        >
          <div className="flex items-start gap-gutter">
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
                  className={cn(
                    "text-body text-(--color-ink-muted)",
                    hideTitle ? null : "mt-snug",
                  )}
                >
                  {description}
                </RadixDialog.Description>
              )}
            </div>

            {/* Escape and a click outside already close it; this is for the pointer user who
                looks for a cross, and for the touch user who has neither. */}
            <RadixDialog.Close asChild>
              <IconButton label="Close" icon={<Icon name="close" />} className="-mr-snug -mt-snug" />
            </RadixDialog.Close>
          </div>

          {children === undefined ? null : <div className="mt-pane text-body">{children}</div>}

          {actions === undefined ? null : (
            <div className="mt-section flex flex-wrap justify-end gap-snug">{actions}</div>
          )}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}
