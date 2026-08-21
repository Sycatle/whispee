import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn.ts";
import { Spinner } from "./Spinner.tsx";

/**
 * Every button in the application.
 *
 * # What one variant table settles that twenty-one call sites did not
 *
 * The audit found four defects that are all the same defect: a button is written by hand each
 * time, so whatever is not remembered is absent. Putting them in the base row means they are no
 * longer remembered — they are the default, and writing a non-conforming button is now harder
 * than writing a conforming one.
 *
 *   - **Focus.** There was no `:focus-visible` rule in the project. `index.css` now declares a
 *     floor for everything focusable; the ring is restated here because a component that sets
 *     its own `outline` would otherwise win silently.
 *   - **Contrast.** A literal white laid on `--color-accent` measured 2.1:1 in twenty-one
 *     places. The filled variants use `--color-accent-ink` and `--color-state-ink`, defined
 *     against their fill in both palettes. There is no literal colour here to get wrong again.
 *   - **Target size.** `touch:min-h-11` was applied to some controls and not others. It is in
 *     the base, and `touch:` rather than a breakpoint because the question is what is pointing
 *     at the screen, not how wide it is.
 *   - **Motion.** `transition-colors duration-(--duration-quick)` reads a token that collapses to 1ms under
 *     `prefers-reduced-motion`; `motion-reduce:transition-none` removes it outright.
 *
 * # `busy` keeps the label, and reserves its slot even when idle
 *
 * The tree replaced a button's label with `…` while waiting — `Conversation.tsx:242`,
 * `Vault.tsx:86,166`, `Lock.tsx:212,303`. "Reload from the vault" becoming "…" is a button that
 * shrinks by a hundred pixels at the moment it is pressed, dragging whatever sits beside it
 * across the screen, and leaving nothing to read for anyone who wants to know what is running.
 *
 * So `busy` keeps the label, adds `disabled` and `aria-busy="true"`, and puts a spinner in a
 * slot **whose width is reserved whether or not it is spinning**. The reservation is the point:
 * a slot that appears with the spinner would move the label by the width of an icon, which is
 * the same layout jump one size smaller.
 *
 * The slot exists exactly when the `busy` prop is passed at all, `false` included — a button
 * that can never be busy should not carry an empty box. That distinction is the reason `busy`
 * is `boolean | undefined` and not defaulted to `false`.
 *
 * # Why `busy` and `asChild` are mutually exclusive in the type
 *
 * `asChild` hands rendering to Radix's `Slot`, which merges props into **one** child element and
 * throws on more. The spinner slot is a second child, so the two cannot both be honoured. Rather
 * than drop the spinner at runtime and leave a caller wondering why nothing spins, the props are
 * a discriminated union and `tsc` refuses the combination.
 *
 * `icon` is excluded from the same branch and for the same reason — it is a sibling too. Under
 * `asChild` the child element owns its own contents, which is what `asChild` means.
 *
 * What this does not solve: `asChild` on a non-`<button>` element gets `disabled`, which does
 * nothing on an anchor. A link that must be inert has to not be a link.
 */
const button = cva(
  [
    "inline-flex items-center justify-center gap-tight rounded-control font-medium",
    "transition-colors duration-(--duration-quick) ease-out motion-reduce:transition-none",
    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent)",
    "disabled:pointer-events-none disabled:opacity-50",
    // 44px, the smallest target a finger hits reliably. Only under a coarse pointer: on a
    // desktop settings panel it would make every row a third taller for no one's benefit.
    "touch:min-h-11",
  ],
  {
    variants: {
      variant: {
        /** The one action a screen is for. At most one per view, or none of them is primary. */
        primary: "bg-(--color-accent) text-(--color-accent-ink) hover:bg-(--color-accent)/90",
        /** Everything else that is still an action: cancel, close, a second option. */
        secondary:
          "border border-(--color-border-subtle) bg-(--color-surface-raised) text-(--color-ink) hover:bg-(--color-surface-sunken)",
        /** Reads as text until pointed at. For actions that must be reachable but not offered. */
        quiet: "text-(--color-ink-muted) hover:bg-(--color-surface-sunken) hover:text-(--color-ink)",
        /** Deletes something that does not come back. Filled, because it must not be misread. */
        destructive: "bg-(--color-danger) text-(--color-state-ink) hover:bg-(--color-danger)/90",
      },
      size: {
        /** Inside a row, a banner, a panel header. */
        sm: "px-gutter py-control text-caption",
        /** The default everywhere else. */
        md: "px-pane py-snug text-body",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

type ButtonBase = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "className"> &
  VariantProps<typeof button> & {
    className?: string;
    /** Rendered before the label. Decoration: the label is what names the action. */
    icon?: ReactNode;
  };

export type ButtonProps = ButtonBase &
  ({ asChild: true; busy?: never; icon?: never } | { asChild?: false; busy?: boolean });

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(props, ref) {
  const {
    variant,
    size,
    icon,
    busy,
    asChild = false,
    className,
    children,
    disabled,
    type,
    ...rest
  } = props as ButtonBase & { asChild?: boolean; busy?: boolean };

  const Component = asChild ? Slot : "button";
  // Passing `busy` at all is the declaration that this button waits sometimes; the slot is then
  // permanent, so the width never depends on the state.
  const reservesSlot = busy !== undefined;

  return (
    <Component
      ref={ref}
      // `submit` is the HTML default and it navigates, which is almost never what a button in
      // this application means. Callers inside a form pass `type="submit"` deliberately.
      type={asChild ? type : (type ?? "button")}
      disabled={disabled === true || busy === true}
      aria-busy={busy === true ? true : undefined}
      data-state={reservesSlot ? (busy === true ? "busy" : "idle") : undefined}
      className={cn(button({ variant, size }), className)}
      {...rest}
    >
      {asChild ? (
        children
      ) : (
        <>
          {icon}
          {children}
          {reservesSlot ? (
            <span aria-hidden="true" className="inline-flex size-4 shrink-0 items-center justify-center">
              {busy === true ? <Spinner size="sm" /> : null}
            </span>
          ) : null}
        </>
      )}
    </Component>
  );
});
