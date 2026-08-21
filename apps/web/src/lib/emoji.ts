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
 * free. It is not available: the formats that can carry Fluent's artwork are COLRv1, which WebKit
 * does not implement, and OT-SVG, which WebKitGTK leaves switched off by default. WebKitGTK is
 * the engine behind the Tauri build on Linux. What every browser does support is COLRv0, which
 * has no gradients, so no Fluent.
 *
 * So: substitution. `segment()` splits a message into runs of text and runs of emoji, and
 * `ui/Emoji.tsx` renders the latter as `<img>`. Discord, Slack and X all do exactly this, for
 * exactly this reason.
 *
 * # Nothing here needs the catalogue to render
 *
 * `segment()` and `fileOf()` are synchronous and data-free: one asks Unicode whether a grapheme
 * is pictographic, the other computes a filename from codepoints. That matters because a message
 * bubble cannot await a promise — a catalogue-gated renderer would flash unstyled text on every
 * mount, on every conversation switch.
 *
 * The catalogue is loaded only by the picker, which is the only thing that needs to enumerate,
 * name and search emoji. It is a dynamic import, so its 185 kB stay out of the initial bundle.
 *
 * # What this does not solve
 *
 * Coverage. Fluent draws 1,595 emoji and Unicode defines more, so `ui/Emoji.tsx` keeps a
 * fallback to the raw character for anything it fails to fetch. The notable gap is **country
 * flags**, which Microsoft omits from the set entirely: `🇫🇷` arrives from a peer, finds no
 * artwork, and falls back to the platform — which on Windows means the letters "FR".
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
   * The five toned variants, lightest first, when this emoji takes a skin tone.
   *
   * Absent rather than a five-fold repetition of `char`: 1,285 of the 1,595 emoji take no tone,
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
 * Where the artwork for a sequence lives.
 *
 * `FE0F` is dropped, and this is the most breakable line in the feature. The variation selector
 * means "draw the previous character as an emoji, not as text": the generator's filenames omit
 * it, while text typed on any platform almost always carries it — `❤️` is `2764 FE0F`. Drop it in
 * one place and not the other and the emoji renders for whoever picked it, whose string came
 * from the catalogue, and not for whoever received it, whose string came from the wire.
 *
 * Zero-width joiners and skin tone modifiers are **kept**: they distinguish separate artworks.
 */
export function fileOf(char: string): string {
  const codepoints = [...char]
    .map((glyph) => glyph.codePointAt(0) ?? 0)
    .filter((codepoint) => codepoint !== 0xfe0f)
    .map((codepoint) => codepoint.toString(16));

  return `/emoji/${codepoints.join("-")}.svg`;
}

/**
 * Does this grapheme want to be drawn as an emoji?
 *
 * `Extended_Pictographic` covers the pictures; `Regional_Indicator` covers flags, whose two
 * letters are not pictographic on their own. Deliberately **not** a coverage test: whether Fluent
 * actually drew this one is answered by the image failing to load, which needs no data here and
 * cannot go stale against the generated tree.
 *
 * Digits and `#`/`*` are excluded on purpose. They are pictographic only when followed by
 * `FE0F 20E3` (the keycap sequence), and treating a bare `7` in a message as an emoji would turn
 * every phone number into a row of pictures.
 */
function pictographic(grapheme: string): boolean {
  if (/^[0-9#*]$/u.test(grapheme)) return false;
  return /\p{Extended_Pictographic}|\p{Regional_Indicator}/u.test(grapheme);
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
 * The catalogue is English — Fluent's CLDR names are — but the person typing may not have an
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
 * Three tiers, and the order is the whole point: typing "sm" should offer "smile" before
 * "blacksmith", and a name should beat a keyword. Without the tiers the results are alphabetical
 * noise and the first cell — the one Enter selects — is essentially random.
 */
export function search(from: Catalogue, query: string): Entry[] {
  const needle = fold(query.trim());
  if (!needle) return [];

  const exact: Entry[] = [];
  const prefix: Entry[] = [];
  const loose: Entry[] = [];

  for (const entry of from.entries) {
    const label = fold(entry.label);

    if (label === needle) exact.push(entry);
    else if (label.startsWith(needle)) prefix.push(entry);
    else if (label.includes(needle)) loose.push(entry);
    else if (entry.keywords.some((keyword) => fold(keyword).includes(needle))) loose.push(entry);
  }

  return [...exact, ...prefix, ...loose];
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
