/**
 * Emoji, as artwork rather than as whatever font the machine happens to have.
 *
 * # Why they are images
 *
 * The system font was the previous answer, and it fails on our own desktop build: a Linux
 * distribution that ships no colour emoji font draws tofu, and the three platforms that do ship
 * one draw three different pictures for the same message. In a messenger, "the sender and the
 * receiver see the same thing" is not a nicety.
 *
 * The tidy fix would be a self-hosted colour font — the glyphs stay text, selection and copy come
 * free. It is not available: the formats that can carry this artwork are COLRv1, which WebKit does
 * not implement, and OT-SVG, which WebKitGTK leaves switched off by default. WebKitGTK is the
 * engine behind the Tauri build on Linux. What every browser does support is COLRv0, which has no
 * gradients and so cannot express any of these sets.
 *
 * So: substitution. `segment()` splits a message into runs of text and runs of emoji, and
 * `ui/Emoji.tsx` renders the latter as artwork. Discord, Slack and X all do exactly this, for
 * exactly this reason — and Telegram and Signal do it too, from Apple's set, which is not ours
 * to redistribute.
 *
 * # Twemoji, and why it replaced Fluent
 *
 * Not taste. Fluent draws 1,595 emoji and **no country flag at all**, so `🇫🇷` arriving from a
 * peer had nothing to draw and fell back to the platform — the letters "FR" on Windows. Twemoji
 * (`jdecked/twemoji`, CC-BY 4.0) covers Unicode completely: flags, keycaps, `©️`, `®️`. The
 * coverage question stops being a question, and one set means one licence.
 *
 * # Nothing here needs the catalogue to render
 *
 * `segment()` and `keyOf()` are synchronous and data-free: one asks Unicode whether a grapheme
 * is pictographic, the other computes a key from codepoints. That matters because a message
 * bubble cannot await a promise — a catalogue-gated renderer would flash unstyled text on every
 * mount, on every conversation switch.
 *
 * The catalogue is loaded only by the picker, which is the only thing that needs to enumerate,
 * name and search emoji. It is a dynamic import, so its bulk stays out of the initial bundle.
 * The *artwork* travels separately, in sprite sheets — see `lib/emoji-sprite.ts`, which explains
 * why 4,009 files became seven.
 */

/** One emoji, as the picker needs to know it. */
export interface Entry {
  /** The character itself, exactly as it travels on the wire. */
  char: string;
  /** The CLDR name — "thumbs up". What a screen reader announces, and what search matches. */
  label: string;
  keywords: string[];
  /** Index into `Catalogue.groups`. */
  group: number;
  /**
   * The `:shortcode:` names this emoji answers to, most canonical first.
   *
   * Emojibase's own preset rather than GitHub's: 3,979 sequences against 1,870, and it keeps the
   * familiar spellings as aliases — `:joy:` alongside `:tears_of_joy:` — so nothing anybody
   * already types is lost by taking the larger set. `lib/shortcode.ts` is what reads them.
   */
  codes?: string[];
  /**
   * The five toned variants, lightest first, when this emoji takes a skin tone.
   *
   * Absent rather than a five-fold repetition of `char`: 1,584 of the 1,914 emoji take no tone,
   * and an array of identical values would say they do.
   */
  tones?: string[];
}

export interface Catalogue {
  groups: string[];
  entries: Entry[];
}

/**
 * The tone a reader has settled on, as an index.
 *
 * Zero is the yellow glyph, which is the **absence** of a skin tone rather than one of them —
 * hence six values for five modifiers. `Preferences.skinTone` is optional on top of that, so
 * "never chose" stays distinguishable from "chose yellow".
 */
export type Tone = 0 | 1 | 2 | 3 | 4 | 5;

/**
 * The hand the picker's six tone swatches are drawn from, neutral first.
 *
 * Data rather than a constant in the component, because the generator needs it too: these six
 * sequences are copied into the **base** sheet even though five of them carry a modifier. Without
 * that, opening the picker fetches all five tone sheets at once — 4.5 MB — just to draw six
 * swatches a reader may never click, which is precisely what sharding by tone exists to avoid.
 *
 * A hand rather than an abstract swatch, because the setting is about hands and faces and a row
 * of coloured squares does not say so — and because the swatch then *is* the artwork, so what you
 * pick is exactly what you will see.
 */
export const TONE_SAMPLES = ["\u270b", "\u270b\u{1f3fb}", "\u270b\u{1f3fc}", "\u270b\u{1f3fd}", "\u270b\u{1f3fe}", "\u270b\u{1f3ff}"];

/**
 * The key a sequence is filed under, in the sprite sheets and in the generator.
 *
 * This is the most breakable line in the feature, and the rule is **not** the obvious one.
 *
 * `FE0F` is the variation selector: "draw the previous character as a picture, not as text".
 * Twemoji drops it from its names — except when the sequence also contains a zero-width joiner,
 * where it keeps it. That is not a quirk we can normalise away, it is upstream's own rule
 * (`twemoji.js`, `grabTheRightIcon`), and 972 of the 4,009 names depend on it:
 *
 * ```
 * ❤️   2764 fe0f             -> 2764                   no joiner: the selector goes
 * 🏴‍☠️  1f3f4 200d 2620 fe0f  -> 1f3f4-200d-2620-fe0f   joiner: the selector stays
 * ```
 *
 * Strip it unconditionally — which is what this did while the artwork was Fluent's — and the
 * pirate flag, the rainbow flag, the trans flag and every gendered person (`🏃‍♀️`, `🧑‍⚕️`) find
 * no artwork. Keep it unconditionally and `❤️`, the most-sent emoji there is, finds none.
 *
 * The generator imports this very function rather than restating it, because the failure is
 * silent on the side that picked the emoji and visible only on the side that received it.
 *
 * Skin tone modifiers are always kept: they name separate artworks.
 */
export function keyOf(char: string): string {
  const codepoints = [...char].map((glyph) => glyph.codePointAt(0) ?? 0);
  const joined = codepoints.includes(0x200d);

  const key = codepoints
    .filter((codepoint) => joined || codepoint !== 0xfe0f)
    .map((codepoint) => codepoint.toString(16))
    .join("-");

  return EXCEPTIONS[key] ?? key;
}

/**
 * The one sequence upstream files against its own rule.
 *
 * `👁️‍🗨️` carries a joiner, so by the rule above it should keep both selectors — and Twemoji
 * names it `1f441-200d-1f5e8` anyway, with neither. It is a single, long-standing quirk in the
 * upstream tree, not a pattern to generalise from.
 *
 * It lives here rather than in the generator because both sides must agree: the generator writes
 * the sheet under this key, the renderer looks it up under this key, and the bijection check that
 * found this exception in the first place only means anything while there is one definition.
 */
const EXCEPTIONS: Record<string, string> = {
  "1f441-fe0f-200d-1f5e8-fe0f": "1f441-200d-1f5e8",
};

/**
 * Does this grapheme want to be drawn as an emoji?
 *
 * `Extended_Pictographic` covers the pictures; `Regional_Indicator` covers flags, whose two
 * letters are not pictographic on their own. Deliberately **not** a coverage test, and it no
 * longer needs to be one: the generator refuses to emit a catalogue entry it has no artwork for,
 * so anything Unicode calls an emoji is something the sheets can draw.
 *
 * Digits and `#`/`*` are excluded on purpose. They are pictographic only when followed by
 * `FE0F 20E3` (the keycap sequence), and treating a bare `7` in a message as an emoji would turn
 * every phone number into a row of pictures.
 *
 * The keycaps themselves need the third clause, and it is not a redundancy: `1️⃣` is `31 FE0F 20E3`
 * and **not one of its three codepoints is `Extended_Pictographic`**. Without the enclosing keycap
 * mark named here, all twelve of them fell through to prose and were drawn by the platform font —
 * invisibly so while the artwork was Fluent's, which had no keycaps to draw either.
 */
function pictographic(grapheme: string): boolean {
  if (/^[0-9#*]$/u.test(grapheme)) return false;
  return /\p{Extended_Pictographic}|\p{Regional_Indicator}|\u20e3/u.test(grapheme);
}

/** A stretch of a message: either prose, or one emoji to be drawn. */
export type Run = { text: string } | { emoji: string };

const GRAPHEMES = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/**
 * Splits a message into runs of prose and runs of emoji.
 *
 * Grapheme segmentation rather than a regular expression over codepoints, because an emoji is
 * routinely several codepoints — `👨‍💻` is three, `👍🏽` is two, `🇫🇷` is two — and splitting one
 * in the middle produces a pair of glyphs nobody sent. `Intl.Segmenter` knows the rules; a regex
 * written by hand would be re-learning them badly, and would need editing at every Unicode
 * release.
 *
 * Consecutive prose graphemes are coalesced into one run so the result stays a handful of nodes:
 * rendering a message as one React child per character would make a bubble of 200 characters
 * into 200 elements, and break `wrap-anywhere` besides.
 */
export function segment(text: string): Run[] {
  const runs: Run[] = [];
  let prose = "";

  for (const { segment: grapheme } of GRAPHEMES.segment(text)) {
    if (!pictographic(grapheme)) {
      prose += grapheme;
      continue;
    }

    if (prose) {
      runs.push({ text: prose });
      prose = "";
    }
    runs.push({ emoji: grapheme });
  }

  if (prose) runs.push({ text: prose });
  return runs;
}

/**
 * Does this message consist of emoji and nothing else?
 *
 * Whitespace between them does not count as prose: "👍 👎" is two emoji with a space, not a
 * sentence. Every messenger draws such a message larger, and the reason is that at body size a
 * lone emoji sent as a whole reply reads as an accident rather than as the reply.
 */
export function onlyEmoji(text: string): boolean {
  const runs = segment(text.trim());
  return (
    runs.length > 0 &&
    runs.some((run) => "emoji" in run) &&
    runs.every((run) => "emoji" in run || run.text.trim() === "")
  );
}

let pending: Promise<Catalogue> | null = null;

/**
 * The catalogue, loaded once.
 *
 * Memoised on the **promise** and not on the result: two pickers opening in the same frame — a
 * reaction bar and the composer, which is a normal thing to do — would otherwise each start their
 * own import and each parse 185 kB of JSON.
 */
export function catalogue(): Promise<Catalogue> {
  pending ??= import("./generated/emoji-index.json").then(
    (module) => module.default as Catalogue,
  );
  return pending;
}

/**
 * Strips diacritics and case, so that a French keyboard finds "café" under "cafe".
 *
 * The catalogue is English — Emojibase's CLDR names are — but the person typing may not have an
 * English keyboard, and `é` is one keystroke on theirs.
 */
function fold(value: string): string {
  return value
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .toLowerCase();
}

/**
 * Emoji matching a query, best first.
 *
 * Four tiers, and the order is the whole point: typing "sm" should offer "smile" before
 * "blacksmith", and a name should beat a keyword. Without the tiers the results are alphabetical
 * noise and the first cell — the one Enter selects — is essentially random.
 *
 * The last tier is why a query may be several words. The names are CLDR's, and CLDR punctuates:
 * the French flag is `flag: France`, so "flag france" matched **nothing at all** while the only
 * test was whether the whole query appeared as a substring. Requiring every term to appear
 * somewhere in the name or the keywords, in any order, is what makes a two-word query behave the
 * way anybody typing one expects — and it sits below the substring tiers, so a contiguous match
 * still wins.
 */
export function search(from: Catalogue, query: string): Entry[] {
  const needle = fold(query.trim());
  if (!needle) return [];

  const terms = needle.split(/\s+/);

  const exact: Entry[] = [];
  const prefix: Entry[] = [];
  const loose: Entry[] = [];
  const scattered: Entry[] = [];

  for (const entry of from.entries) {
    const label = fold(entry.label);

    if (label === needle) exact.push(entry);
    else if (label.startsWith(needle)) prefix.push(entry);
    else if (label.includes(needle)) loose.push(entry);
    else {
      const haystack = `${label} ${entry.keywords.map(fold).join(" ")}`;
      if (terms.every((term) => haystack.includes(term))) scattered.push(entry);
    }
  }

  return [...exact, ...prefix, ...loose, ...scattered];
}

/**
 * The entry as it should be shown at the reader's chosen tone.
 *
 * Returns the neutral character for an emoji that takes no tone, rather than refusing to render
 * it: a preference for dark skin is a preference about hands and faces, and says nothing about a
 * pizza.
 */
export function applyTone(entry: Entry, tone: Tone): string {
  if (tone === 0 || !entry.tones) return entry.char;
  return entry.tones[tone - 1] ?? entry.char;
}

/**
 * The base character of a possibly-toned one.
 *
 * Used to keep the recents list from filling with five variants of the same thumb: what is
 * remembered is the emoji, and the tone is applied on the way out.
 */
export function withoutTone(char: string): string {
  return [...char]
    .filter((glyph) => {
      const codepoint = glyph.codePointAt(0) ?? 0;
      return codepoint < 0x1f3fb || codepoint > 0x1f3ff;
    })
    .join("");
}
