import { keyOf } from "./emoji.ts";
import { Revision } from "../state/revision.ts";

/**
 * Where emoji artwork actually comes from, and why it is not four thousand files.
 *
 * # The cost was never the bytes
 *
 * The first version of this shipped one SVG per emoji and let `loading="lazy"` fetch them. It
 * was slow, and the reason is worth writing down because the intuition points the wrong way:
 * the whole untoned set is **3.3 MB**, which is one photograph. What made it slow was **4,009
 * requests** — six at a time over HTTP/1.1 in development, and one round trip apiece through
 * Tauri's custom protocol on the desktop. Opening the picker asked for hundreds of them.
 *
 * Telegram reached the same conclusion and ships five webp sheets; Signal ships images too.
 * Neither serves a file per emoji, and neither should we.
 *
 * # Seven sheets, and how we know which one to ask for
 *
 * `shardOf()` is computed from the character, with no table to consult — the same property that
 * makes `keyOf()` safe to call while a bubble renders. A sequence carrying no skin tone modifier
 * is in `base`; one carrying a single modifier is in that tone's sheet; the couples and
 * handshakes that carry two are in `mixed`, which is 380 sequences nobody sends by accident.
 *
 * That split is not cosmetic. It means choosing a skin tone costs one 0.9 MB request instead of
 * putting 4.5 MB of tone variants in front of every reader who never opens the picker.
 *
 * # A sheet is injected whole, in one mutation, and this is the load-bearing decision
 *
 * The obvious design injects one `<symbol>` per emoji, on first sight, so the document only ever
 * holds what has been displayed. It was written that way, and it **froze the tab for over eight
 * seconds** on a grid of 1,914 cells. Appending a symbol to a sprite that hundreds of live
 * `<use>` elements already point into makes every one of them re-resolve: the work is quadratic
 * in the number of emoji on screen, and a picker is where that number is largest.
 *
 * Measured on the same page, the whole base sheet as a single `innerHTML` on a detached element
 * costs **55 ms** — 2 to build the markup, 49 to parse, 4 to attach. Seven mutations for a whole
 * session instead of two thousand.
 *
 * The price is stated plainly: injecting a sheet whole puts roughly **16,000 inert nodes and
 * 24 MB** into the document whether or not anybody looks at those emoji. That is the cost of the
 * word "preloaded". A `<symbol>` nothing references is parsed but never laid out or painted, and
 * a session that opens the picker would have paid it anyway.
 *
 * The markup strings are dropped once parsed — only the set of keys is kept — so the 3.3 MB of
 * JSON does not sit in the heap alongside the DOM it produced.
 *
 * # What `<use>` buys beyond the request count
 *
 * Geometry is stored once. A thread with thirty 👍 holds one copy of the path data and thirty
 * references to it, where thirty `<img>` were thirty decodes. This is the part that matters on
 * a phone.
 */

/** The sheets, named exactly as they are on disk. */
export type Shard = "base" | "tone-1" | "tone-2" | "tone-3" | "tone-4" | "tone-5" | "mixed";

/**
 * The five skin tone modifiers, in the order the picker offers them.
 *
 * Index + 1 is the sheet number, and also `Preferences.skinTone` — the three have to agree, so
 * they are derived from this one array rather than written out three times.
 */
const MODIFIERS = [0x1f3fb, 0x1f3fc, 0x1f3fd, 0x1f3fe, 0x1f3ff];

/**
 * The symbol drawn for a sequence its sheet does not carry.
 *
 * There is no fallback to the platform font any more — that was the whole point of the change,
 * since the platform font is what drew tofu on Linux and three different pictures on three
 * systems. But silence would be worse than a wrong picture: a message would arrive and simply
 * not be there. So the generator puts one neutral glyph in `base`, and anything unrecognised
 * gets it. In practice this is only reachable by a Unicode release newer than the pinned tag.
 */
export const UNKNOWN = "unknown";

const SVG = "http://www.w3.org/2000/svg";

/** Keys the document now holds a `<symbol>` for. The markup itself is not retained. */
const drawn = new Set<string>();

/** In-flight and settled sheet loads, memoised on the promise. */
const sheets = new Map<Shard, Promise<void>>();

/** Sheets whose symbols are in the document — distinct from "requested". */
const ready = new Set<Shard>();

/** Bumped when a sheet lands, so components showing an emoji from it draw it. */
export const revision = new Revision();

let sprite: SVGSVGElement | null = null;

/**
 * Which sheet holds this sequence.
 *
 * A `Set` and not a count: a couple where both people share a tone carries the modifier twice
 * and belongs in that tone's sheet, not in `mixed`. Counting occurrences would file it wrong,
 * and the generator — which imports this same function — would file it wrong identically, so
 * the bijection check would pass and the emoji would still be missing at runtime.
 */
export function shardOf(char: string): Shard {
  const tones = new Set(
    [...char]
      .map((glyph) => glyph.codePointAt(0) ?? 0)
      .filter((codepoint) => MODIFIERS.includes(codepoint)),
  );

  if (tones.size === 0) return "base";
  if (tones.size > 1) return "mixed";
  return `tone-${MODIFIERS.indexOf([...tones][0] ?? 0) + 1}` as Shard;
}

/**
 * Fetches a sheet and puts its symbols in the document, once.
 *
 * Memoised on the promise rather than on the result: a conversation mounting twenty bubbles in
 * one frame would otherwise start twenty identical requests and parse the same 3.3 MB twenty
 * times over.
 *
 * A failed sheet is forgotten rather than remembered as failed, so that coming back from a
 * network outage retries instead of leaving the reader with a permanently empty thread.
 */
export function load(shard: Shard): Promise<void> {
  const pending = sheets.get(shard);
  if (pending) return pending;

  const started = fetch(`/emoji/${shard}.json`)
    .then((response) => {
      if (!response.ok) throw new Error(`emoji sheet ${shard}: ${response.status}`);
      return response.json() as Promise<Record<string, string>>;
    })
    .then((sheet) => {
      inject(sheet);
      ready.add(shard);
      revision.bump();
    })
    .catch((cause: unknown) => {
      sheets.delete(shard);
      console.error(`could not load emoji sheet ${shard}`, cause);
    });

  sheets.set(shard, started);
  return started;
}

/**
 * The base sheet, at idle.
 *
 * Everything a message can contain that is not skin-toned is in here, so one request after first
 * paint is the difference between emoji appearing instantly for the rest of the session and
 * appearing a beat late, once each.
 */
export function preload(): void {
  void load("base");
}

/**
 * The symbol id to point a `<use>` at, or `null` while its sheet is still on the way.
 *
 * Pure: it reads two sets and touches nothing. The version of this that injected on demand had
 * to justify mutating the document during render, and then turned out to be the thing making the
 * picker unusable — so the justification and the mutation both went.
 */
export function symbolOf(char: string): string | null {
  const shard = shardOf(char);
  if (!ready.has(shard)) {
    void load(shard);
    return null;
  }

  const key = keyOf(char);
  return `e-${drawn.has(key) ? key : UNKNOWN}`;
}

/**
 * One sheet's worth of `<symbol>`, built detached and attached in a single mutation.
 *
 * `innerHTML` on an element in the SVG namespace, so the fragment is parsed as SVG rather than
 * as HTML — `createElement("symbol")` would produce an unknown HTML element that no `<use>` can
 * reach, and the failure is invisible because nothing throws.
 *
 * The viewBox is written here rather than in the sheet because every drawing shares it. The
 * handful authored on another grid carry a nested `<svg>` of their own, which the generator adds
 * and which letterboxes them inside this one.
 */
function inject(sheet: Record<string, string>): void {
  const keys = Object.keys(sheet);
  const holder = document.createElementNS(SVG, "svg");

  holder.innerHTML = keys
    .map((key) => `<symbol id="e-${key}" viewBox="0 0 36 36">${sheet[key]}</symbol>`)
    .join("");

  root().append(holder);
  for (const key of keys) drawn.add(key);
}

function root(): SVGSVGElement {
  if (sprite) return sprite;

  sprite = document.createElementNS(SVG, "svg");
  sprite.setAttribute("aria-hidden", "true");
  // Out of the flow and out of the accessibility tree. `display: none` would be simpler and is
  // wrong: several engines refuse to resolve a `<use>` into a subtree that is not rendered.
  sprite.setAttribute("style", "position:absolute;width:0;height:0;overflow:hidden");
  document.body.prepend(sprite);
  return sprite;
}
