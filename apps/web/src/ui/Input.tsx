import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "./cn.ts";

/**
 * A single-line text field, and only the field.
 *
 * # There is no `label` prop, and that is the whole design
 *
 * A `label` prop here would make labelling a *choice*, and the tree records what happens to
 * choices: seven `<input type="text">` with no label at all, leaning on `placeholder`
 * (`ConversationList.tsx:93`, `Onboarding.tsx:82,91`, and four in `Lock.tsx`). Placeholder text
 * disappears the moment someone types, so it is not a label; it is a hint that vanishes exactly
 * when a person needs to check what they are filling in.
 *
 * The labelling lives in [`Field`], where it is a required prop rather than an available one.
 * This component takes `id`, `describedBy` and `invalid` — the three things `Field` computes —
 * and nothing else. Splitting them is what makes the requirement enforceable: on its own this
 * component cannot label anything, so it has to be wrapped.
 *
 * # 16 pixels, for one platform's sake
 *
 * `text-prose` is 1rem, not the `text-body` this interface otherwise uses for controls. Below
 * 16px iOS Safari zooms into a field on focus and does **not** zoom back out on blur, leaving
 * the reader in a magnified page they have to pinch out of. The tree already solved it this way
 * in the composer (`Conversation.tsx:267-270`), with the reasoning that matters: the other fix
 * is `user-scalable=no`, which takes zoom away from the people who most need it. A slightly
 * larger field costs nothing by comparison.
 *
 * What this does not solve: `type="date"` and friends draw their own controls, and their
 * internal type size is the platform's business, not this class list's.
 */
export interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "className"> {
  /** Marks the value as rejected: sets `aria-invalid` and paints the border. */
  invalid?: boolean;
  /** Ids of the hint and error text. Supplied by [`Field`]; rarely written by hand. */
  describedBy?: string;
  className?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { invalid = false, describedBy, className, ...rest },
  ref,
) {
  return (
    <input
      ref={ref}
      aria-invalid={invalid || undefined}
      aria-describedby={describedBy}
      data-state={invalid ? "invalid" : "valid"}
      className={cn(
        "w-full rounded-control border bg-(--color-surface-raised) px-gutter py-snug text-prose text-(--color-ink)",
        "placeholder:text-(--color-ink-muted)",
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
