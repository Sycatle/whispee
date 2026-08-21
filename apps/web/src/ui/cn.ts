/**
 * Joins class names. Nothing more, and the "nothing more" is the decision.
 *
 * # Why this is `clsx` alone, and not `twMerge(clsx(...))`
 *
 * The usual recipe wraps `clsx` in `tailwind-merge` so that a caller's `className` can override
 * a component's own class without the two both landing in the attribute and the winner being
 * decided by stylesheet order. That is a real problem and `tailwind-merge` is the usual answer,
 * so it was measured against **this** vocabulary before being kept. It failed, in two ways that
 * matter here more than the problem it solves.
 *
 * It does not know this project's names. Every distance, radius, duration and shadow in
 * `index.css` is a semantic theme key — `p-gutter`, `rounded-control`, `duration-quick`,
 * `gap-tight`. `tailwind-merge` ships a table of Tailwind's *default* scales, so it reads those
 * as unrelated utilities and keeps both:
 *
 *     twMerge("p-gutter", "p-pane")             -> "p-gutter p-pane"
 *     twMerge("rounded-control", "rounded-pill") -> "rounded-control rounded-pill"
 *     twMerge("gap-tight", "gap-snug")           -> "gap-tight gap-snug"
 *
 * So on the exact classes these primitives are made of, it does not merge — the thing it is
 * installed to do. Colours happen to work, because `bg-(--color-accent)` is arbitrary-variable
 * syntax that it does parse; but colours are the case that needs it least.
 *
 * Worse, it is actively wrong on one pairing this tree writes constantly. A custom font size and
 * a token colour are both `text-…`, and it collapses them into one conflict group:
 *
 *     twMerge("text-body", "text-(--color-danger)")      -> "text-(--color-danger)"
 *     twMerge("text-body", "text-(color:--color-danger)") -> "text-(color:--color-danger)"
 *
 * A component whose base says `text-body` silently loses its size the moment a caller recolours
 * it, and the disambiguating `(color:…)` form does not save it. A merger that drops a rule
 * nobody asked it to drop is worse than no merger: unmerged classes are visible in the DOM,
 * a swallowed one is not.
 *
 * Repairing that means `extendTailwindMerge` with a hand-written map of every theme key — 8 kB
 * of library plus a correspondence table that has to be edited every time `index.css` gains a
 * token, and that is silently wrong until someone notices a size went missing. That is a worse
 * trade than the one it replaces, so the dependency was removed from `package.json` rather than
 * configured.
 *
 * # What replaces it, and what it does not solve
 *
 * The contract is positional: **every primitive puts `className` last**, so a caller's class is
 * emitted after the component's own. That covers the ordinary case because Tailwind v4 emits
 * utilities in a stable, source-independent order, and two utilities in the same CSS layer with
 * equal specificity are resolved by that order — not by the order in the attribute.
 *
 * Which is precisely what this does not solve: `cn("p-pane", "p-gutter")` yields both classes,
 * and which one paints depends on where Tailwind placed them in the sheet, not on the argument
 * order. Overriding a primitive's padding from outside is therefore unreliable **by design** —
 * if a call site needs a different distance, the variant table is the place to add it. The
 * conditional and array forms of `clsx` are the supported way to vary classes; a same-property
 * override is not.
 */
import { clsx, type ClassValue } from "clsx";

export type { ClassValue };

export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}
