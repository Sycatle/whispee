import { forwardRef, type ReactNode } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn.ts";
import { Button } from "./Button.tsx";

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
 * # Dismissal is a word, not a glyph
 *
 * The close control is a labelled "Dismiss" button, following `App.tsx:448` — an icon-only ✕ in
 * a full-width banner is a smaller target and one more thing to guess at. `onDismiss` is
 * optional: a banner reporting a condition that is still true should not be dismissible, since
 * waving it away would only make the interface lie until the next render.
 *
 * What this does not solve: nothing here throttles repetition. Nine identical banners stacked by
 * nine failed sends is a call-site problem — the state that produces them should be collapsed
 * before it reaches this component.
 */
const banner = cva("flex items-start gap-gutter rounded-control border p-gutter text-body", {
  variants: {
    tone: {
      info: "border-(--color-border-subtle) bg-(--color-surface-raised) text-(--color-ink)",
      ok: "border-(--color-ok) bg-(--color-ok)/10 text-(--color-ink)",
      warn: "border-(--color-warn) bg-(--color-warn)/10 text-(--color-ink)",
      danger: "border-(--color-danger) bg-(--color-danger)/10 text-(--color-ink)",
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
        <Button variant="quiet" size="sm" onClick={onDismiss} className="shrink-0">
          Dismiss
        </Button>
      )}
    </div>
  );
});
