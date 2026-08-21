import { forwardRef, useId, type ReactNode } from "react";
import { cn } from "./cn.ts";

/**
 * A labelled form control: the label, the hint, the error, and the wiring between them.
 *
 * # Why `label` is required rather than optional
 *
 * There are seven unlabelled text inputs in this tree — `ConversationList.tsx:93`,
 * `Onboarding.tsx:82,91`, four in `Lock.tsx` — every one of them relying on a `placeholder` that
 * disappears as soon as a character is typed. They could be fixed one at a time. They would then
 * be fixed until the next input is written.
 *
 * `label` is therefore a required prop, not an available one. A field with no label does not
 * render badly and does not fail a review: it fails `tsc --noEmit`, in the same run that already
 * gates the build. That is what "fixing accessibility inside the redesign rather than beside it"
 * means — the defect is not corrected, it is made unrepresentable.
 *
 * The same reasoning put the labelling here rather than on [`Input`]. A `label` prop on the
 * input would be one more optional prop; here it is the only way to get an input onto the screen
 * at all, because the input has no labelling of its own.
 *
 * # `labelHidden`, and why it hides rather than removes
 *
 * Some labels genuinely should not be seen: the rail's filter sits under a magnifier in a 288px
 * column where a "Filter conversations" line above it would cost more than it explains. The
 * escape hatch is `labelHidden`, and it renders the label `sr-only` — still in the DOM, still
 * the field's accessible name, just not painted. Deleting it is never an option this component
 * offers, because the two cases are indistinguishable at the call site and one of them is a bug.
 *
 * # The wiring
 *
 * `id` from `useId`, so two of the same field on one screen do not collide; `htmlFor` pointing
 * at it; `aria-describedby` listing the hint and the error, in that order, and omitted entirely
 * when there is neither — an empty `aria-describedby` is a dangling reference. `aria-invalid`
 * follows the presence of `error`, so the two cannot disagree.
 *
 * The child is a function because these three values have to reach the control, and a function
 * says so at the call site: `<Field label="Handle">{(c) => <Input {...c} />}</Field>`. The
 * alternative — cloning the child and injecting props — hides the contract and breaks the moment
 * the control is wrapped in anything.
 *
 * What this does not solve: nothing forces the returned element to *use* the props it is given.
 * A caller who ignores `c.id` gets an unlabelled field again. The type makes the labelling
 * available and unavoidable to receive; it cannot make it unavoidable to apply.
 */
export interface FieldControl {
  id: string;
  describedBy: string | undefined;
  invalid: boolean;
}

export interface FieldProps {
  /** The visible name of the control. Required: see above. */
  label: string;
  /** Renders the label `sr-only`. It stays the accessible name. */
  labelHidden?: boolean;
  /** A permanent line under the control: what the value is for, or what it costs. */
  hint?: ReactNode;
  /** What is wrong with the current value. Its presence is what makes the field invalid. */
  error?: ReactNode;
  children: (control: FieldControl) => ReactNode;
  className?: string;
}

export const Field = forwardRef<HTMLDivElement, FieldProps>(function Field(
  { label, labelHidden = false, hint, error, children, className },
  ref,
) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;

  const described = [hint === undefined ? null : hintId, error === undefined ? null : errorId]
    .filter((value): value is string => value !== null)
    .join(" ");

  return (
    <div ref={ref} className={cn("flex flex-col gap-snug", className)}>
      <label
        htmlFor={id}
        className={cn(
          labelHidden ? "sr-only" : "text-body font-medium text-(--color-ink)",
        )}
      >
        {label}
      </label>

      {children({
        id,
        describedBy: described === "" ? undefined : described,
        invalid: error !== undefined,
      })}

      {hint === undefined ? null : (
        <p id={hintId} className="text-caption text-(--color-ink-muted)">
          {hint}
        </p>
      )}

      {/*
        `role="alert"` rather than a plain paragraph: an error that appears after a submit is a
        change the reader did not cause on this element, and without it a screen reader user
        discovers it only by navigating back to the field they thought they had finished with.
      */}
      {error === undefined ? null : (
        <p id={errorId} role="alert" className="text-caption text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
});
