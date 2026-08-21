import { forwardRef, type TextareaHTMLAttributes } from "react";
import { cn } from "./cn.ts";

/**
 * A multi-line text field.
 *
 * Same split as [`Input`] and for the same reason: no `label` prop, because labelling belongs to
 * [`Field`] where it is mandatory rather than offered. Same 16px floor too — iOS zooms into any
 * field under that size on focus and does not zoom back out, and the alternative fix would be to
 * disable pinch-zoom for everyone.
 *
 * # `field-sizing-content` by default, with a ceiling left to the caller
 *
 * A textarea that stays one row high hides what has already been written; one that grows without
 * limit eats the view it lives in. `field-sizing-content` gives the first half for free — the
 * box follows its content with no measurement code, no hidden mirror element and no resize
 * listener, which is what the composer used to need.
 *
 * The ceiling is deliberately **not** set here. The composer caps at `max-h-32` because it sits
 * above a conversation it must not swallow; a recovery-phrase field wants to show all twelve
 * words at once. The right limit is a property of the surrounding pane, so the caller passes it.
 *
 * What this does not solve: `field-sizing` is unsupported in Firefox as of writing, where the
 * field falls back to its `rows` attribute and stops growing. Callers should therefore pass a
 * `rows` that is usable on its own rather than assume the box will stretch.
 */
export interface TextareaProps
  extends Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "className"> {
  invalid?: boolean;
  describedBy?: string;
  className?: string;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { invalid = false, describedBy, className, ...rest },
  ref,
) {
  return (
    <textarea
      ref={ref}
      aria-invalid={invalid || undefined}
      aria-describedby={describedBy}
      data-state={invalid ? "invalid" : "valid"}
      className={cn(
        "w-full resize-none rounded-control border bg-(--color-surface-raised) px-gutter py-snug text-prose text-(--color-ink)",
        "field-sizing-content placeholder:text-(--color-ink-muted)",
        "transition-colors duration-(--duration-quick) ease-out motion-reduce:transition-none",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent)",
        "disabled:opacity-50",
        // `border-strong`, not the `border-subtle` hairline that separates two things sitting
        // side by side: this border is the only thing saying where the field begins, which makes
        // it a user interface component under WCAG 1.4.11 and puts a floor of 3:1 under it.
        // `border-subtle` measured 1.35:1 against the field's own background.
        invalid ? "border-(--color-danger)" : "border-(--color-border-strong)",
        "touch:min-h-11",
        className,
      )}
      {...rest}
    />
  );
});
