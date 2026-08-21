import { useEffect, useMemo, useState } from "react";

import { completions, typed } from "@/lib/mention";
import { compactNameOf, formatHandle } from "@/lib/naming";
import { useNames } from "@/state/names";
import { Avatar } from "@/ui/Avatar";
import { Completions, completionId } from "@/ui/Completions";

/**
 * The `@mention` completion menu, and the hook that drives it.
 *
 * A near-twin of `Shortcodes.tsx`, deliberately: the composer's `<textarea>` cannot be wrapped —
 * it carries the draft, the caret, the send shortcut and the software-keyboard inset, all of
 * which belong to `Conversation` — so this owns the decision and hands back the rows to draw and
 * the key handler to install. The list itself is `ui/Completions.tsx`, shared between the two.
 *
 * # What it inserts is the handle, and the thread shows the name
 *
 * Accepting a row writes `@charlie8295` into the draft, never `@Charlie`. The argument is at the
 * top of `lib/mention.ts` and is worth restating where somebody will be tempted to change it: a
 * display name is self-asserted, not unique, and editable. The handle is the anchor, and the
 * thread resolves it back to a name at render time — which is what keeps a message written last
 * year correct after its subject renames themselves.
 *
 * The visible consequence is that the field says `@charlie8295` while the sent line will say
 * `@Charlie`. That gap closes with a `contenteditable` chip and not before; the format is already
 * the one that change would want.
 *
 * # Enter is contested, three ways now
 *
 * Enter sends the message, accepts a shortcode, and accepts a mention. Only one menu can be open
 * at a time — a caret cannot be inside a `:token` and an `@token` at once, since neither admits
 * the other's sigil — but the order in the field's `onKeyDown` is still written down rather than
 * left to chance. Tab accepts too, and Escape closes without inserting so that a literal
 * `@word` stays possible.
 */

/** How many rows the menu shows. A conversation rarely has more; a large group would. */
const ROWS = 8;

export const LISTBOX_ID = "mention-suggestions";

export interface Mentions {
  /** The handles to offer, or none when the menu is shut. */
  rows: string[];
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
}

/**
 * Watches a draft and its caret, and offers the people this conversation can address.
 *
 * `among` is the members of *this* thread and nothing wider. Offering somebody who is not in the
 * room would let the writer address a person who will never receive the message — and the
 * renderer, which resolves against the same set, would draw the result as plain text anyway.
 */
export function useMentions({
  among,
  text,
  caret,
  replace,
}: {
  among: readonly string[];
  text: string;
  caret: number;
  replace: (from: number, to: number, insertion: string) => void;
}): Mentions {
  const names = useNames();

  const [active, setActive] = useState(0);
  // Dismissing has to survive the keystrokes that follow it: without remembering *which* token
  // was waved away, the menu would reappear on the very next character of the same word.
  const [dismissed, setDismissed] = useState<string | null>(null);

  const token = typed(text, caret);

  const rows = useMemo(() => {
    if (!token || dismissed === token.query) return [];
    return completions(among, names, token.query, ROWS);
  }, [among, names, token, dismissed]);

  // The highlight goes back to the first row whenever the query changes: keeping index 3 after a
  // keystroke that reshuffled the list points it at somebody the writer never chose.
  useEffect(() => {
    setActive(0);
  }, [token?.query]);

  const open = rows.length > 0;
  const at = Math.min(active, rows.length - 1);

  const accept = (index: number) => {
    const hit = rows[index];
    if (hit === undefined || !token) return;
    // The trailing space is not a nicety: without it the caret sits at the end of a live token,
    // the menu reopens on the handle that was just accepted, and the next keystroke edits it.
    replace(token.from, token.to, `${formatHandle(hit)} `);
    setDismissed(null);
  };

  const onKeyDown = (event: React.KeyboardEvent): boolean => {
    if (!open) return false;

    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
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
  };
}

/**
 * The rows: a face, a name, and the handle underneath it.
 *
 * The handle is drawn next to the name and not instead of it, on every row, because that is the
 * one string that identifies the account — and because the row is a *search result*, where the
 * reader has to tell two people with similar names apart before choosing. `compactNameOf`
 * already collapses to the handle when a name is ambiguous within the group, so a row showing
 * `@alice @alice` is the honest rendering of two people claiming one name.
 */
export function MentionMenu({
  rows,
  active,
  among,
  seedOf,
  onPick,
}: {
  rows: readonly string[];
  active: number;
  among: readonly string[];
  seedOf: (handle: string) => string | undefined;
  onPick: (at: number) => void;
}) {
  const names = useNames();

  return (
    <Completions id={LISTBOX_ID} label="People" rows={rows} active={active} onPick={onPick}>
      {(handle) => {
        const name = compactNameOf(handle, names, among);
        return (
          <>
            <Avatar seed={seedOf(handle)} label={name} size="sm" />
            <span className="truncate text-(--color-ink)">{name}</span>
            {name !== formatHandle(handle) && (
              <span className="truncate text-(--color-ink-muted)">{formatHandle(handle)}</span>
            )}
          </>
        );
      }}
    </Completions>
  );
}
