import { cn } from "./cn.ts";

/**
 * The look a menu has, wherever it was opened from.
 *
 * Extracted when the context menu arrived, because the alternative was a second copy of two
 * class lists carrying about forty lines of argument between them — the elevation rule, the
 * contrast measurement behind the highlight, the reason `border-strong` and not `border-subtle`.
 * Copied, the two would have agreed for exactly as long as nobody edited one of them.
 *
 * A dropdown and a context menu are the same object opened two ways, and they should be
 * indistinguishable once open. That is not a saving, it is the point: a reader who right-clicks
 * a message and a reader who presses the ⋯ button are looking at the same menu.
 *
 * The width constraints stay with each caller. Radix names its own CSS variables per primitive —
 * `--radix-dropdown-menu-content-available-height` is not the context menu's — so those cannot be
 * shared even though everything else can.
 */
export const surface = cn(
  "z-(--z-index-overlay) overflow-y-auto rounded-control border border-(--color-border-strong)",
  "bg-(--color-surface-raised) p-tight shadow-menu",
  // Radix measures these after it has decided which way to flip. Anything absolute here would
  // override the measurement and reintroduce the overflow it just avoided.
  // The portal sits outside the layout: in landscape on a notched phone the menu can otherwise
  // open under the notch.
  "safe-sides safe-bottom",
);

export const item = cn(
  "group flex cursor-default select-none items-center gap-gutter rounded-control px-gutter py-snug text-body",
  // Radix moves the highlight with the pointer *and* with the arrow keys, so styling
  // `data-highlighted` covers both; a `hover:` rule would leave keyboard users with no cursor.
  //
  // The fill is the accent and not a half-tone of the surface. `outline-none` above removes the
  // focus ring, which makes this fill the *only* thing telling a keyboard user which item the
  // arrows have reached — and `surface-sunken` on `surface-raised` measures 1.14:1 in light and
  // 1.16:1 in dark. That is not a faint highlight, it is no highlight: the item under the
  // cursor and the item beside it were the same colour to anyone not looking for the
  // difference. An indicator carrying that much meaning owes 3:1; this one is at 4.93:1 and
  // 6.95:1.
  "outline-none data-[highlighted]:bg-(--color-accent) data-[highlighted]:text-(--color-accent-ink)",
  "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
  "touch:min-h-11",
);
