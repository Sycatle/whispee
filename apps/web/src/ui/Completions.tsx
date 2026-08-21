import type { ReactNode } from "react";

import { cn } from "@/ui/cn";

/**
 * The list that hangs above the composer while something is being completed.
 *
 * # Why this is shared, and what exactly is shared
 *
 * Two completions live in the composer — `:shortcode:` and `@mention` — and what they have in
 * common is not the rows, which are an emoji in one case and a person in the other. It is the
 * awkward part: a `listbox` whose options are addressed by id from a field that keeps the focus,
 * a highlight that has to be announced rather than merely drawn, and a pick that must happen on
 * `mousedown` because a click blurs the field first and the blur is what closes the menu.
 *
 * Written twice, those are two chances to get `aria-activedescendant` pointing at an id that is
 * not in the document — a defect no test in this project can see and no reader notices, because
 * it only ever shows up in a screen reader saying nothing where it should have read a row.
 *
 * # It is a combobox and not a menu
 *
 * The field stays focused throughout: typing is the activity, and a menu that took focus would
 * end it. That is what `aria-activedescendant` is for — focus stays put and the *active option*
 * moves — which is why the caller's `<textarea>` takes `role="combobox"` and this takes
 * `role="listbox"`. Deliberately not a Radix `Popover`, which moves focus by design.
 */

/** The id of one option. The field's `aria-activedescendant` has to name exactly this. */
export function completionId(listbox: string, index: number): string {
  return `${listbox}-${index}`;
}

export function Completions<T>({
  id,
  label,
  rows,
  active,
  onPick,
  children,
  className,
}: {
  id: string;
  /** Names the list for a screen reader. The field has its own label; this one names the offer. */
  label: string;
  rows: readonly T[];
  active: number;
  onPick: (at: number) => void;
  /** Draws one row. The `<li>`, its id, its selected state and its picking are not its business. */
  children: (row: T, index: number) => ReactNode;
  className?: string;
}) {
  if (rows.length === 0) return null;

  return (
    <ul
      id={id}
      role="listbox"
      aria-label={label}
      className={cn(
        "absolute bottom-full left-0 z-(--z-index-overlay) mb-tight w-full max-w-sm overflow-hidden",
        "rounded-control border border-(--color-border-strong) bg-(--color-surface-raised) shadow-menu",
        className,
      )}
    >
      {rows.map((row, index) => (
        <li
          // The index is the position in the offer, which is derived from the query: nothing in
          // this list is reordered, and a row is replaced rather than moved when the query
          // changes.
          key={index}
          id={completionId(id, index)}
          role="option"
          aria-selected={index === active}
          // `onMouseDown` and not `onClick`: a click would blur the textarea first, and a blur is
          // what closes the menu, so the click would land on nothing.
          onMouseDown={(event) => {
            event.preventDefault();
            onPick(index);
          }}
          className={cn(
            "flex cursor-pointer items-center gap-snug px-snug py-tight text-caption",
            index === active ? "bg-(--color-surface-sunken)" : "hover:bg-(--color-surface-sunken)",
          )}
        >
          {children(row, index)}
        </li>
      ))}
    </ul>
  );
}
