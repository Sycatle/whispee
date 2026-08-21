import type { Catalogue, Entry } from "./emoji.ts";

/**
 * `:shortcode:` in the composer: what is being typed, and what it could become.
 *
 * All of it is pure, and none of it touches React or the DOM — the completion menu is a thin
 * layer over these three functions, which is what makes the awkward parts testable. The awkward
 * parts are real: a caret in the middle of a sentence, a colon that is a smiley rather than the
 * start of a name, and a word that only becomes a shortcode once it is closed.
 *
 * # Two ways to reach an emoji, and they are not the same gesture
 *
 * `typed()` drives the menu: type `:sm`, see the matches, pick one. It is for discovery — you
 * know roughly what you want and not what it is called.
 *
 * `closed()` fires on the second colon: type `:smile:` and it becomes the emoji with no menu
 * involved. It is for people who already know the name and are not looking at the screen, and it
 * is the reason the menu never has to be *used* to get anywhere.
 *
 * # What is deliberately not matched
 *
 * A colon that follows a word character. `http://` and `10:30` and `note:this` are not the start
 * of a shortcode, and treating them as one puts a menu over the composer every time somebody
 * types a time or a URL. The colon has to open a token: start of the text, or after a space or
 * an opening bracket.
 */

/** The token under the caret, when the caret is inside one. */
export interface Typed {
  /** Index of the opening colon. */
  from: number;
  /** Index just past the caret — where a replacement ends. */
  to: number;
  /** What follows the colon, without it. */
  query: string;
}

/**
 * Shortcodes are lowercase ASCII with `_`, `+` and `-`.
 *
 * `+` is there for `:+1:`, which is the one shortcode almost everybody knows and the only one
 * that would be dropped by the tidier character class.
 */
const TOKEN = /(?:^|[\s([{])(:[a-z0-9_+-]*)$/;

/**
 * Below this many characters the menu stays shut.
 *
 * One character matches several hundred sequences, which is not a suggestion list, it is a wall
 * that appears every time somebody types a colon. Two is where the list starts saying something.
 */
const MINIMUM = 2;

/** The `:query` immediately before the caret, if the caret is in one. */
export function typed(text: string, caret: number): Typed | null {
  const match = TOKEN.exec(text.slice(0, caret));
  if (!match) return null;

  const token = match[1] ?? "";
  const query = token.slice(1);
  if (query.length < MINIMUM) return null;

  return { from: caret - token.length, to: caret, query };
}

/** One suggestion: the emoji, and the name it matched under. */
export interface Completion {
  entry: Entry;
  code: string;
}

/**
 * Suggestions for a partial shortcode, best first.
 *
 * Exact, then prefix, then substring — the same shape as `search()` in `lib/emoji.ts` and for the
 * same reason: the first row is what Enter takes, so it had better not be arbitrary. An emoji
 * appears once, under its best-matching name, because `:+1:` and `:thumbsup:` offered as two rows
 * would be two ways to insert the same character.
 *
 * The cap is not a detail. Without it `:a` would propose eight hundred rows, and the menu has to
 * fit above a composer that sits at the bottom of the window.
 */
export function completions(from: Catalogue, query: string, limit = 8): Completion[] {
  const needle = query.toLowerCase();

  const exact: Completion[] = [];
  const prefix: Completion[] = [];
  const loose: Completion[] = [];

  for (const entry of from.entries) {
    let best: Completion[] | null = null;
    let code = "";

    for (const candidate of entry.codes ?? []) {
      if (candidate === needle) {
        best = exact;
        code = candidate;
        break;
      }
      if (candidate.startsWith(needle)) {
        if (best !== prefix) {
          best = prefix;
          code = candidate;
        }
      } else if (candidate.includes(needle) && best === null) {
        best = loose;
        code = candidate;
      }
    }

    if (best) best.push({ entry, code });
  }

  return [...exact, ...prefix, ...loose].slice(0, limit);
}

/**
 * The `:name:` that was just completed by a closing colon, if there is one.
 *
 * Only an **exact** name counts. A prefix match here would turn `:sm:` into whatever happened to
 * sort first, which is a silent substitution of something the writer did not ask for — quite
 * different from picking a row off a list they can see.
 */
export function closed(from: Catalogue, text: string, caret: number): (Typed & { char: string }) | null {
  const before = text.slice(0, caret);
  if (!before.endsWith(":")) return null;

  const match = /(?:^|[\s([{])(:([a-z0-9_+-]{2,}):)$/.exec(before);
  if (!match) return null;

  const token = match[1] ?? "";
  const name = match[2] ?? "";

  const entry = from.entries.find((candidate) => candidate.codes?.includes(name));
  if (!entry) return null;

  return { from: caret - token.length, to: caret, query: name, char: entry.char };
}
