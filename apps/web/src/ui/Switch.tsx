import { forwardRef, type ComponentPropsWithoutRef, type ElementRef } from "react";
import * as RadixSwitch from "@radix-ui/react-switch";
import { cn } from "./cn.ts";

/**
 * An on/off control that takes effect immediately.
 *
 * # Switch or checkbox, decided by when the change lands
 *
 * A checkbox states an intention that a later submit carries out; a switch *is* the action, and
 * flipping it is expected to have happened by the time the finger lifts. In this application
 * that distinction is real — "I understand my history will no longer be protected"
 * (`Vault.tsx:148`) is a checkbox gating a button, while "read receipts" writes to the session
 * the instant it moves. Using the same widget for both would promise the wrong thing twice.
 * [`Checkbox`] is the other half of this pair, and it carries the explanatory line; a switch
 * usually sits in a row that already has one.
 *
 * # Why Radix here and native there
 *
 * There is no native switch element. The alternative is `role="switch"` on a button plus the
 * space and enter handling, `aria-checked`, and the form association — the exact list of things
 * the hand-written accessibility code in this tree got wrong. Radix also emits
 * `data-state="checked|unchecked"` on both the root and the thumb, which is what lets the whole
 * visual state be expressed in CSS with no conditional class in JavaScript.
 *
 * # The name
 *
 * `label` is required and becomes `aria-label`, for the same reason it is required on
 * [`IconButton`]: the control is a shape, and a shape has no name. When a visible label already
 * exists in the row, pass `aria-labelledby` pointing at it — it is spread after, it wins per
 * spec, and the visible text is then the accessible name.
 *
 * What this does not solve: a switch inside a `<form>` submits through a hidden input Radix
 * renders, but it has no validation and no `required` semantics. A switch that must be on before
 * a form can be sent is a checkbox.
 */
export interface SwitchProps
  extends Omit<ComponentPropsWithoutRef<typeof RadixSwitch.Root>, "className" | "children"> {
  /** The accessible name. Overridden by `aria-labelledby` when a visible label exists. */
  label: string;
  className?: string;
}

export const Switch = forwardRef<ElementRef<typeof RadixSwitch.Root>, SwitchProps>(function Switch(
  { label, className, ...rest },
  ref,
) {
  return (
    <RadixSwitch.Root
      ref={ref}
      aria-label={label}
      className={cn(
        "inline-flex h-6 w-10 shrink-0 items-center rounded-pill border border-(--color-border-subtle) p-px",
        "transition-colors duration-(--duration-quick) ease-out motion-reduce:transition-none",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent)",
        "disabled:pointer-events-none disabled:opacity-50",
        "data-[state=unchecked]:bg-(--color-surface-sunken)",
        "data-[state=checked]:border-(--color-accent) data-[state=checked]:bg-(--color-accent)",
        className,
      )}
      {...rest}
    >
      <RadixSwitch.Thumb
        className={cn(
          "block size-5 rounded-pill bg-(--color-surface-raised) shadow-menu",
          "transition-transform duration-(--duration-quick) ease-out motion-reduce:transition-none",
          "data-[state=checked]:translate-x-4",
        )}
      />
    </RadixSwitch.Root>
  );
});
