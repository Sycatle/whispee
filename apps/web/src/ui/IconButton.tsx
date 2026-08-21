import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn.ts";

/**
 * A button whose whole content is a glyph.
 *
 * # When a control may be a glyph, and when it owes the reader a word
 *
 * The tree had the same gesture written both ways — `DetailPanel.tsx` closed with `[✕]` while
 * `Devices.tsx`, `Lock.tsx` and `Pairing.tsx` closed with the word "Close" — which is not a
 * disagreement about anything, just two people writing on different days. This is the rule that
 * settles it.
 *
 * **A glyph alone** for a gesture that is frequent, reversible, and drawn by a picture nobody has
 * to be taught: close, dismiss, cancel, back, search, attach, send. All three conditions, not any
 * one of them. Frequent, because a glyph is learned by repetition and a control seen once a
 * quarter never gets learned. Reversible, because the price of guessing wrong has to be one
 * click. Unambiguous, because there is no such thing as a self-explanatory icon — there are only
 * icons a reader has already met somewhere else, and ✕ and ‹ are those, while a strongbox and a
 * padlock are already a stretch.
 *
 * **A word** for a gesture that is rare or irreversible: "Revoke", "Erase", "Hand over",
 * "Leave the group", "Change the account key", "Remove moderator". The deciding case is two
 * destructive actions next to each other. A trash can beside a trash can does not say which of
 * "revoke this device" and "change your account key" is about to happen, and the reader who
 * needs to know is exactly the reader who is in a hurry. A word is slower to scan and that is
 * the point: the pause belongs there.
 *
 * A word may also be the right answer for a rare gesture that is perfectly safe, simply because
 * nobody will have met its glyph. Rarity alone is enough to disqualify an icon; danger makes it
 * certain.
 *
 * What this does not solve, and it is the honest part: "frequent", "reversible" and
 * "unambiguous" are judgements, not tests. Nothing here can be checked by `tsc`, no lint rule
 * can read a glyph, and two reasonable people will disagree about "Done" or about a copy button.
 * The rule exists so that a disagreement is about *this paragraph* rather than about taste, and
 * so the answer, once argued, lands in one place instead of being re-decided per file. When a
 * case is genuinely on the line, a word is the safer error: it is merely wordy, whereas a wrong
 * glyph is a mystery, and on the destructive side it is a mystery with consequences.
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
