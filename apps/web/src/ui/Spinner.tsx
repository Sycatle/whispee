import { forwardRef } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn.ts";

/**
 * A pending indicator, sized to sit inside a control.
 *
 * # Why the rotation stops rather than slows
 *
 * An indefinite spin is the canonical example of what `prefers-reduced-motion` exists to
 * suppress: it never ends, it is in the corner of the eye the whole time an action takes, and
 * for a reader with vestibular sensitivity it is the difference between using the application
 * and not. `motion-reduce:animate-none` is therefore not a nicety here.
 *
 * What is left when it stops is a static three-quarter ring — still a recognisable "working"
 * mark, and never the only one: [`Button`] pairs it with `aria-busy` and a disabled control, so
 * the state is announced and enforced whether or not anything moves.
 *
 * # Why the label is optional and defaults to silence
 *
 * Inside a `Button` the spinner is decoration: the button already says `aria-busy`, and a
 * screen reader that also read "loading" would report the same fact twice. Standing on its own
 * — a pane waiting for its content — it is the only thing on screen, and then it needs to say
 * so. Passing `label` switches it from `aria-hidden` to `role="status"` with an off-screen text.
 *
 * What this does not solve: `role="status"` announces on *change*, so a spinner already present
 * at first paint may say nothing at all. A view that loads slowly should render its own live
 * region rather than rely on this one.
 */
const spinner = cva("shrink-0 animate-spin motion-reduce:animate-none", {
  variants: {
    size: {
      sm: "size-4",
      md: "size-5",
    },
  },
  defaultVariants: { size: "sm" },
});

export interface SpinnerProps extends VariantProps<typeof spinner> {
  /** Announced to assistive technology. Omit inside a control that already says `aria-busy`. */
  label?: string;
  className?: string;
}

export const Spinner = forwardRef<SVGSVGElement, SpinnerProps>(function Spinner(
  { size, label, className },
  ref,
) {
  return (
    <>
      <svg
        ref={ref}
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
        className={cn(spinner({ size }), className)}
      >
        {/* The full ring at low opacity, then a quarter of it opaque. One shape would either be
            a bare arc with no track or a complete circle with nothing to see turning. */}
        <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.5" opacity="0.25" />
        <path
          d="M8 1.5a6.5 6.5 0 0 1 6.5 6.5"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>
      {label === undefined ? null : (
        <span role="status" className="sr-only">
          {label}
        </span>
      )}
    </>
  );
});
