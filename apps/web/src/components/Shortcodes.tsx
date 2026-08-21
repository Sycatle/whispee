import { useEffect, useMemo, useState } from "react";

import { type Catalogue, type Tone, applyTone, catalogue } from "@/lib/emoji";
import { type Completion, closed, completions, typed } from "@/lib/shortcode";
import { useSession } from "@/state/SessionProvider";
import { Completions, completionId } from "@/ui/Completions";
import { Emoji } from "@/ui/Emoji";

/**
 * The `:shortcode:` completion menu, and the hook that drives it.
 *
 * # Why this is a hook returning a list, and not a component owning a field
 *
 * The composer's `<textarea>` cannot be wrapped: it carries the draft, the caret, the send
 * shortcut and the software-keyboard inset, all of which belong to `Conversation`. So this owns
 * the *decision* — what is being typed, what it could become, which row is highlighted — and
 * hands back both the rows to draw and the key handler to install. `Conversation` keeps the
 * field.
 *
 * # It is a combobox, not a menu, and the difference is announced
 *
 * The field stays focused throughout: a menu that took focus would break typing, which is the
 * entire activity here. That is exactly what `aria-activedescendant` is for — the focus stays put
 * and the *active option* moves — and it is why the textarea takes `role="combobox"` while the
 * list takes `role="listbox"`. A screen reader then reads each suggestion as the arrow keys move
 * through it, which a `div` of buttons behind a focused field would not.
 *
 * # Enter is contested, and the menu wins while it is open
 *
 * Enter sends the message. It also accepts the highlighted suggestion. Both are right, and the
 * menu being open is what decides between them — the same rule every editor with a completion
 * popup uses. Tab accepts too, because it is what hands expect from a completion, and Escape
 * closes without inserting so that a literal `:word` remains possible.
 *
 * # The catalogue is fetched on the first colon
 *
 * Not at mount. A conversation that nobody types a shortcode into should not pay 296 kB for the
 * possibility, and by the time two characters have followed the colon the import has landed.
 */

/** How many rows the menu shows. Enough to choose from, few enough to sit above a composer. */
const ROWS = 8;

export interface Shortcodes {
  /** The suggestions to draw, or none when the menu is shut. */
  rows: Completion[];
  /** Index into `rows` of the highlighted suggestion. */
  active: number;
  /** The id the field must carry in `aria-activedescendant`, or undefined when shut. */
  activeId: string | undefined;
  /** True while the menu is open, which is what makes Enter accept rather than send. */
  open: boolean;
  /** Handles Up, Down, Enter, Tab and Escape. Returns true when it consumed the event. */
  onKeyDown: (event: React.KeyboardEvent) => boolean;
  /** Accepts a row, by click or by key. */
  accept: (at: number) => void;
  /** Shuts the menu without inserting anything. */
  dismiss: () => void;
  /**
   * Turns a just-closed `:name:` into its emoji, and says whether it did.
   *
   * Called by the field on every change rather than on a key, because the closing colon can also
   * arrive by paste or by a software keyboard's autocorrect, neither of which is a keystroke.
   */
  settle: (value: string, position: number) => boolean;
}

/**
 * Watches a draft and its caret, and offers the emoji whose name is being typed.
 *
 * `replace` is given the span to overwrite and what to put there, which is the same operation the
 * picker's insertion performs — `Conversation` owns the field, so it owns the edit.
 */
export function useShortcodes({
  text,
  caret,
  replace,
}: {
  text: string;
  caret: number;
  replace: (from: number, to: number, insertion: string) => void;
}): Shortcodes {
  const session = useSession();
  const tone = (session.preferences.skinTone ?? 0) as Tone;

  const [loaded, setLoaded] = useState<Catalogue | null>(null);
  const [active, setActive] = useState(0);
  // Dismissing has to survive the keystrokes that follow it: without remembering *which* token
  // was waved away, the menu would reappear on the very next character of the same word.
  const [dismissed, setDismissed] = useState<string | null>(null);

  const token = typed(text, caret);

  useEffect(() => {
    if (!token || loaded) return;
    let live = true;
    void catalogue().then((value) => {
      if (live) setLoaded(value);
    });
    return () => {
      live = false;
    };
  }, [token, loaded]);

  const rows = useMemo(() => {
    if (!loaded || !token || dismissed === token.query) return [];
    return completions(loaded, token.query, ROWS);
  }, [loaded, token, dismissed]);

  // The highlight goes back to the first row whenever the query changes: keeping index 3 after a
  // keystroke that reshuffled the list points it at something the reader never chose.
  useEffect(() => {
    setActive(0);
  }, [token?.query]);

  const open = rows.length > 0;
  const at = Math.min(active, rows.length - 1);

  const accept = (index: number) => {
    const hit = rows[index];
    if (!hit || !token) return;
    replace(token.from, token.to, applyTone(hit.entry, tone));
    setDismissed(null);
  };

  /**
   * The closing colon, handled here rather than in the field.
   *
   * `Conversation` calls this on every change so that `:joy:` becomes the emoji whether or not
   * the menu was ever open — which is the whole point of that gesture for anybody who already
   * knows the name and is not looking at the screen.
   */
  const settle = (value: string, position: number): boolean => {
    if (!loaded) return false;
    const hit = closed(loaded, value, position);
    if (!hit) return false;
    replace(hit.from, hit.to, hit.char);
    return true;
  };

  const onKeyDown = (event: React.KeyboardEvent): boolean => {
    if (!open) return false;

    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      // Wrapping, because a list of eight is short enough that running off the end and having to
      // come back the long way is just friction.
      setActive((current) => (current + step + rows.length) % rows.length);
      return true;
    }

    if (event.key === "Enter" || event.key === "Tab") {
      event.preventDefault();
      accept(at);
      return true;
    }

    if (event.key === "Escape") {
      event.preventDefault();
      setDismissed(token?.query ?? null);
      return true;
    }

    return false;
  };

  return {
    rows,
    active: at,
    activeId: open ? completionId(LISTBOX_ID, at) : undefined,
    open,
    onKeyDown,
    accept,
    dismiss: () => setDismissed(token?.query ?? null),
    settle,
  };
}

export const LISTBOX_ID = "shortcode-suggestions";

/**
 * The rows themselves: an emoji, the name it matched under, and what it is called.
 *
 * The list, its ARIA and its picking live in `ui/Completions.tsx`, shared with the mention menu —
 * see the argument there. What is left here is what is specific to an emoji.
 */
export function ShortcodeMenu({
  rows,
  active,
  onPick,
}: {
  rows: Completion[];
  active: number;
  onPick: (at: number) => void;
}) {
  return (
    <Completions
      id={LISTBOX_ID}
      label="Emoji suggestions"
      rows={rows}
      active={active}
      onPick={onPick}
    >
      {(hit) => (
        <>
          <Emoji char={hit.entry.char} className="h-[1.5em] w-[1.5em]" />
          <span className="text-(--color-ink)">:{hit.code}:</span>
          <span className="truncate text-(--color-ink-muted)">{hit.entry.label}</span>
        </>
      )}
    </Completions>
  );
}
