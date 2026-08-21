/**
 * Every shortcut this application has, in one list.
 *
 * # Why a list and not a call site per shortcut
 *
 * `lib/shortcuts.ts` used to say, in prose, that the shell wired `mod+k`, `mod+,` and `mod+i`.
 * One of the three existed. The sentence had been true of an intention and became false without
 * a line of code changing, and nothing could have caught it — a comment cannot be compiled, and
 * a help screen written by hand is the same comment with a nicer font.
 *
 * A shortcut has three consumers that must agree: the binding that answers it, the help screen
 * that lists it, and the hint a menu draws beside the matching item. Written three times they
 * drift in exactly one direction, because two of the three are the ones nobody tests. Written
 * once, an id that does not exist is a type error, and the help screen cannot list a chord
 * nobody answers — `app/Shortcuts.tsx` builds it from the bindings that are actually mounted.
 *
 * # Why these four and not more
 *
 * Every entry answers a gesture made many times a day. `mod+k` reaches the conversation you want
 * without the mouse; `mod+i` and `mod+,` open the two panels; `?` is how anybody finds the other
 * three.
 *
 * Deliberately absent, with the reason, so the argument does not have to be had twice:
 *
 *   - **Next and previous conversation.** The rail is sorted by activity, so "next" names a
 *     different conversation depending on whether a message has just arrived. A shortcut whose
 *     target moves under the fingers teaches people not to trust it. The arrow keys in the rail
 *     do the same job and show where they are going.
 *   - **New conversation.** `mod+n` belongs to the browser and cannot be intercepted; neither can
 *     `mod+shift+n`. There is no free chord for it, and that is the whole reason.
 *   - **Send.** Enter already sends.
 *
 * Escape is not here either, and that is a different reason: it is contextual everywhere — it
 * closes the filter, steps out of an action bar, dismisses a dialog — and each of those already
 * handles it where the context lives. A global binding would have to know all of them.
 */
import type { BindingId } from "./keymap-ids.ts";

export type { BindingId };

/** One shortcut: what answers it, how it is typed, and how it is described. */
export interface Binding {
  id: BindingId;
  /** In the `lib/shortcuts.ts` spelling — `"mod+k"`. */
  combo: string;
  /** Sentence case, imperative, as the help screen shows it. */
  label: string;
  /** The heading it appears under. Grouping only; it carries no behaviour. */
  group: "Navigation" | "Panels" | "Help";
}

export const KEYMAP: readonly Binding[] = [
  {
    id: "rail.filter",
    combo: "mod+k",
    label: "Go to a conversation",
    group: "Navigation",
  },
  {
    id: "detail.toggle",
    combo: "mod+i",
    label: "Show conversation details",
    group: "Panels",
  },
  {
    id: "settings.open",
    combo: "mod+,",
    label: "Open settings",
    group: "Panels",
  },
  {
    id: "help.shortcuts",
    combo: "?",
    label: "Keyboard shortcuts",
    group: "Help",
  },
];

/**
 * The binding behind an id.
 *
 * Throws rather than returning `undefined`. An id that names nothing is a programming mistake,
 * and every id in the codebase is a literal checked against `BindingId` — so reaching this throw
 * means the map and the union have been allowed to disagree, which is the one failure this
 * module exists to prevent. Failing loudly on the first render is how it stays prevented.
 */
export function bindingOf(id: BindingId): Binding {
  const found = KEYMAP.find((binding) => binding.id === id);
  if (found === undefined) throw new Error(`no binding for ${id}`);
  return found;
}

/** The bindings under each heading, in the order the headings are declared. */
export function grouped(ids: readonly BindingId[]): [Binding["group"], Binding[]][] {
  const groups: Binding["group"][] = ["Navigation", "Panels", "Help"];

  return groups
    .map((group): [Binding["group"], Binding[]] => [
      group,
      KEYMAP.filter((binding) => binding.group === group && ids.includes(binding.id)),
    ])
    .filter(([, bindings]) => bindings.length > 0);
}
