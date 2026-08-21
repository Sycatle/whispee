import { forwardRef, useId, type InputHTMLAttributes, type ReactNode } from "react";
import { cn } from "./cn.ts";

/**
 * A checkbox with a label and, almost always, a line explaining what it costs.
 *
 * # Why this shape, and not a generic checkbox
 *
 * The pattern `label > input + span + span.text-xs` is written five times, character for
 * character, in `Signals.tsx:42,58,74`, `Notices.tsx:82` and `Vault.tsx:148`. It is not a
 * coincidence of style: in this application a privacy toggle is never just a toggle. "Read
 * receipts" is followed by "turning them off also stops you from seeing other people's";
 * "Typing indicator" by what the server can still see either way. The explanatory line is where
 * the honesty of the settings screens lives, and it is part of the control, not decoration
 * beside it.
 *
 * So `description` is a first-class prop rendered inside the same `<label>`. Inside, because
 * that is what makes the sentence clickable along with the checkbox — a 44px target instead of
 * a 16px one — and what keeps the two from drifting apart when a screen is rearranged.
 *
 * # Why the native input, dressed rather than replaced
 *
 * A `<div role="checkbox">` has to re-implement the space key, the indeterminate state, form
 * participation, and the focus ring. The native control has all of that, and `accent-color`
 * tints it from a token on every engine this application runs in. The only thing given up is
 * total control of the mark's shape, which no requirement here asks for.
 *
 * What this does not solve: `accent-color` colours the box and the tick together, so a very
 * light accent gives a pale tick on a pale box. `--color-accent` is dark in the light palette
 * and light in the dark one, and the tick is drawn by the engine to contrast with it.
 */
export interface CheckboxProps
  extends Omit<InputHTMLAttributes<HTMLInputElement>, "className" | "type"> {
  /** The name of the setting. */
  label: ReactNode;
  /** What turning it on or off actually does — usually what it costs. */
  description?: ReactNode;
  className?: string;
}

export const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(function Checkbox(
  { label, description, className, checked, id, ...rest },
  ref,
) {
  const generated = useId();
  const inputId = id ?? generated;
  const descriptionId = `${inputId}-description`;

  return (
    <label
      htmlFor={inputId}
      className={cn(
        "flex cursor-pointer items-start gap-snug text-body text-(--color-ink)",
        "has-disabled:cursor-default has-disabled:opacity-50",
        // The label is the target, not just the box: a whole settings row is easy to hit, a
        // 16px square between two paragraphs is not.
        "touch:min-h-11",
        className,
      )}
    >
      <input
        ref={ref}
        id={inputId}
        type="checkbox"
        checked={checked}
        aria-describedby={description === undefined ? undefined : descriptionId}
        // Radix emits `data-state` on its own controls; a native input emits nothing, so it is
        // restated here to keep `data-[state=checked]:…` a single vocabulary across `ui/`.
        data-state={checked === undefined ? undefined : checked ? "checked" : "unchecked"}
        className={cn(
          "mt-tight size-4 shrink-0 accent-(--color-accent)",
          "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent)",
        )}
        {...rest}
      />
      <span className="flex flex-col gap-tight">
        <span>{label}</span>
        {description === undefined ? null : (
          <span id={descriptionId} className="text-caption text-(--color-ink-muted)">
            {description}
          </span>
        )}
      </span>
    </label>
  );
});
