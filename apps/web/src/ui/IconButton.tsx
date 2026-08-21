import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn.ts";

/**
 * A button whose whole content is a glyph.
 *
 * # `label` is required, and it is required in the type
 *
 * An icon-only control has no accessible name unless one is written, and "unless one is
 * written" is exactly the condition that fails under deadline. The tree shows both halves of
 * the problem: `Conversation.tsx:239` gives its paperclip a `title="Attach a file"`, which a
 * screen reader may or may not read depending on the engine, and other icon controls give
 * nothing at all.
 *
 * So `label` is a required string, it becomes `aria-label`, and a nameless icon button is a
 * `tsc` error rather than a defect someone has to notice. This is the same move `Field` makes
 * for inputs, applied to the other half of the same problem.
 *
 * # How a tooltip attaches later without touching this file
 *
 * Radix's `Tooltip.Trigger asChild` clones its child, merges its own handlers and `aria-*` onto
 * it, and needs to place a ref on it. Both requirements are already met: the component forwards
 * its ref and spreads every remaining prop onto the element, so
 * `<Tooltip.Trigger asChild><IconButton …/></Tooltip.Trigger>` works with no change here. The
 * same holds for a dropdown trigger.
 *
 * There is deliberately no `asChild` of its own, unlike [`Button`]. `Slot` merges props into a
 * child the caller supplies, and this component supplies its own child — the glyph wrapper — so
 * the two are contradictory. An icon-shaped control that must render as an anchor is a different
 * component, not a flag on this one.
 *
 * What this does not solve: a tooltip does not replace the label. Radix's tooltip content is
 * `aria-describedby`, not a name, and it never opens for a touch user at all. `label` stays
 * mandatory even when a tooltip repeats it.
 */
const iconButton = cva(
  [
    "inline-flex shrink-0 items-center justify-center rounded-control",
    "transition-colors duration-(--duration-quick) ease-out motion-reduce:transition-none",
    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent)",
    "disabled:pointer-events-none disabled:opacity-50",
    // Square as well as tall: a 44px-high target 20px wide is still a miss waiting to happen.
    "touch:min-h-11 touch:min-w-11",
  ],
  {
    variants: {
      variant: {
        primary: "bg-(--color-accent) text-(--color-accent-ink) hover:bg-(--color-accent)/90",
        secondary:
          "border border-(--color-border-subtle) bg-(--color-surface-raised) text-(--color-ink) hover:bg-(--color-surface-sunken)",
        quiet: "text-(--color-ink-muted) hover:bg-(--color-surface-sunken) hover:text-(--color-ink)",
        destructive: "bg-(--color-danger) text-(--color-state-ink) hover:bg-(--color-danger)/90",
      },
      size: {
        sm: "p-tight",
        md: "p-snug",
      },
    },
    defaultVariants: { variant: "quiet", size: "md" },
  },
);

export interface IconButtonProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "className" | "children">,
    VariantProps<typeof iconButton> {
  /** The accessible name. Names the action — "Close", not "Cross". */
  label: string;
  icon: ReactNode;
  className?: string;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, icon, variant, size, className, type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      className={cn(iconButton({ variant, size }), className)}
      {...rest}
    >
      {/* Hidden from the accessibility tree: the name is `aria-label`, and a glyph that also
          announced itself would be read twice, or read as a lone emoji. */}
      <span aria-hidden="true" className="inline-flex items-center justify-center">
        {icon}
      </span>
    </button>
  );
});
