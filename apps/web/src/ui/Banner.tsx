import { forwardRef, type ReactNode } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn.ts";
import { Icon } from "./Icon.tsx";
import { IconButton } from "./IconButton.tsx";

/**
 * A message about the state of things, addressed to the reader and not to a field.
 *
 * # One component, because there was already one component written nine times
 *
 * `App.tsx:376,448`, `Lock.tsx:121,215,307,394`, `Onboarding.tsx:72,139`,
 * `Verification.tsx:43,65`, `Pairing.tsx:173` and `Attachment.tsx:167` are all the same block:
 * `role="alert"`, a danger border, a tinted background, a medium-weight line and a muted
 * explanation. They differ in ways nobody chose — some are `bg-(--color-danger)/20` and some
 * `/10`, some have a border on one side and some all round, some are dismissible and some are
 * not for no reason anyone could state. Writing it once removes nine chances to write it
 * differently.
 *
 * # `role` follows the tone, and that is the part that matters
 *
 * `role="alert"` interrupts a screen reader mid-sentence. That is right for `danger` and `warn`
 * — a wrong password, a fingerprint that changed, a browser that cannot do Ed25519 — and wrong
 * for everything else. An `info` banner explaining that the vault is enabled does not deserve to
 * cut across whatever the reader was in the middle of; `role="status"` queues it politely and it
 * is heard at the next pause.
 *
 * Getting this backwards is not a small mistake. A reader who is interrupted by routine
 * information learns to tune the interruption out, and the day the fingerprint changes the alert
 * arrives in a channel that has already been dismissed. Same argument as `Verification.tsx`:
 * silence in the nominal case is what buys attention for the anomaly.
 *
 * # Dismissal is a glyph, and the earlier argument for a word does not survive
 *
 * This used to read "the close control is a labelled Dismiss button — an icon-only ✕ in a
 * full-width banner is a smaller target and one more thing to guess at". The target half was
 * simply wrong: `IconButton` carries `touch:min-h-11 touch:min-w-11`, so on the pointer type
 * where target size decides anything the glyph is a 44 px square and the word was never bigger.
 * The guessing half is answered by the rule written at the top of `IconButton`: dismissal is
 * frequent, reversible — the banner comes back if the condition is still true — and ✕ is the one
 * glyph nobody has to be taught. It keeps its accessible name, "Dismiss", through `label`.
 *
 * `onDismiss` is optional: a banner reporting a condition that is still true should not be
 * dismissible, since waving it away would only make the interface lie until the next render.
 *
 * What this does not solve: nothing here throttles repetition. Nine identical banners stacked by
 * nine failed sends is a call-site problem — the state that produces them should be collapsed
 * before it reaches this component.
 */
/*
  # The radius is written the long way round, and it has to be

  `rounded-(--radius-surface)` and not `rounded-surface`, which is the same border radius by the
  same token. The difference is where Tailwind puts the two rules in the emitted stylesheet, and
  that decides an override this component does not control.

  `cn` is `clsx` alone — see the argument in `ui/cn.ts` — so a caller's class does not replace
  this one, it joins it, and the winner is whichever Tailwind emitted last. `App.tsx` mounts four
  banners edge to edge across the window and squares them off with `rounded-none`. Tailwind emits
  named radii in name order, so `.rounded-none` lands before `.rounded-surface` and after
  `.rounded-control`: the class that used to sit here lost to the caller, and the obvious
  replacement would silently start winning. Full-bleed banners would grow 12 px corners, cutting
  notches out of the top of the window, and nothing would fail — not `tsc`, not the tests, not
  the build.

  The arbitrary-property form resolves the same variable and is emitted with the arbitrary
  utilities, ahead of every named radius, so the caller keeps the last word exactly as before.

  What this does not solve: it is still stylesheet order deciding a conflict, which is the thing
  `ui/cn.ts` says is unreliable by design. It is pinned here rather than fixed. The fix is a prop
  on this component for a square-edged, full-width banner, so that the layout decision is made in
  the type instead of being smuggled through `className` — and that is a change to `App.tsx`'s
  call sites, not to this line.

  # Which tones keep an edge, and why it is not all of them

  `warn` and `danger` keep their border, and it is not decoration: they are the two tones that
  carry `role="alert"`, and a warning told apart only by a wash of colour at ten percent opacity
  is a warning a colour-blind reader, a night-shift screen or a glance does not receive. The
  border is the redundant channel that makes the tint legible rather than pretty, and removing it
  to save a line would be spending the one thing this component exists to buy.

  `info` and `ok` lose theirs. Neither interrupts, neither is asking for a decision, and both
  already sit on a fill that separates them from the page — a distinct surface for `info`, a
  tinted one for `ok`. An `info` banner is a paragraph with a background, and a rectangle drawn
  around every paragraph in the interface is how a screen ends up looking like a form.

  What this does not solve: `ok` now rests on `bg-(--color-ok)/10` alone, and ten percent of
  green over a light surface is a faint signal. It is the correct amount of signal for "this
  worked" — the case where nothing needs doing — but a reader who cannot see the hue reads it as
  a plain block, and the sentence inside has to say what happened without help from the colour.
*/
const banner = cva("flex items-start gap-gutter rounded-(--radius-surface) p-gutter text-body", {
  variants: {
    tone: {
      info: "bg-(--color-surface-raised) text-(--color-ink)",
      ok: "bg-(--color-ok)/10 text-(--color-ink)",
      warn: "border border-(--color-warn) bg-(--color-warn)/10 text-(--color-ink)",
      danger: "border border-(--color-danger) bg-(--color-danger)/10 text-(--color-ink)",
    },
  },
  defaultVariants: { tone: "info" },
});

const heading = cva("font-medium", {
  variants: {
    tone: {
      info: "text-(--color-ink)",
      ok: "text-(--color-ok)",
      warn: "text-(--color-warn)",
      danger: "text-(--color-danger)",
    },
  },
  defaultVariants: { tone: "info" },
});

export interface BannerProps extends VariantProps<typeof banner> {
  /** The one line that says what happened. Optional: a bare sentence is often the whole banner. */
  title?: ReactNode;
  /** The explanation, and where the honesty about consequences goes. */
  children?: ReactNode;
  /** Present only when the condition can genuinely be waved away. */
  onDismiss?: () => void;
  className?: string;
}

export const Banner = forwardRef<HTMLDivElement, BannerProps>(function Banner(
  { tone = "info", title, children, onDismiss, className },
  ref,
) {
  const interrupts = tone === "danger" || tone === "warn";

  return (
    <div
      ref={ref}
      role={interrupts ? "alert" : "status"}
      data-tone={tone}
      className={cn(banner({ tone }), className)}
    >
      <div className="min-w-0 flex-1">
        {title === undefined ? null : <p className={cn(heading({ tone }))}>{title}</p>}
        {children === undefined ? null : (
          <div
            className={cn(
              "text-(--color-ink-muted)",
              title === undefined ? null : "mt-tight",
            )}
          >
            {children}
          </div>
        )}
      </div>

      {onDismiss === undefined ? null : (
        <IconButton
          label="Dismiss"
          icon={<Icon name="close" />}
          size="sm"
          onClick={onDismiss}
          className="shrink-0"
        />
      )}
    </div>
  );
});
