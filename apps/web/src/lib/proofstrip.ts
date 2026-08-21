/**
 * Deterministic visual derivations of an account fingerprint.
 *
 * # What the proof strip is, and what it is not
 *
 * Twelve marks over three levels carry log2(3) * 12 ≈ **19 bits**. That is very far from enough
 * to resist a deliberate collision: an attacker who controls the generation of their own key can
 * grind out a fingerprint whose strip is pixel-identical to someone else's in a few million
 * tries, which is seconds of CPU.
 *
 * **The strip is therefore not a verification mechanism, it is a change-detection mechanism.**
 * It says that something happened, never that everything is fine. Verification remains the full
 * hexadecimal fingerprint compared out of band, in the detail panel — see `Fingerprint.tsx`,
 * which exists precisely because comparing a continuous string by eye is the hard part.
 *
 * # Why it is worth having anyway
 *
 * Because it is free at the point of use and it is *everywhere*. In the nominal case the strip
 * is painted in `border-subtle` and reads as a decorative underline nobody notices. But it is
 * the data. The day the fingerprint moves, the pattern moves and the colour turns `danger` — in
 * the rail, in the conversation header and in the panel at once, with no text added anywhere.
 * The ornament *is* the state. That generalises the doctrine already written in
 * `Verification.tsx`: silence in the nominal case, bluntness on anomaly.
 *
 * # Why the identicon lives in the same file
 *
 * It is the same seed, the same hash, and above all **the same caveat**: two accounts can
 * produce drawings the eye confuses. Splitting them across two modules would mean writing the
 * caveat twice, and one of the two copies would eventually rot. Neither function is a means of
 * verification; both are means of noticing a change.
 *
 * # What this module does not do
 *
 * It draws nothing. No canvas, no SVG, no DOM: it returns numbers, so that `node --test` can
 * check the derivation without a renderer, and so the same numbers can be drawn at three scales
 * without three chances to disagree.
 */

/** Marks in a strip. Twelve is what fits at 24 px with a legible pitch. */
export const MARK_COUNT = 12;

/** Height levels a mark can take. Three: absent-looking, medium, full. */
export const MARK_LEVELS = 3;

/** A 5x5 identicon is small enough to read at 20 px and large enough to differ. */
export const GRID_SIZE = 5;

const FNV_OFFSET = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

/**
 * FNV-1a over the UTF-16 code units, byte by byte.
 *
 * Not a cryptographic hash, and it does not pretend to be one — see the caveat at the top of the
 * file. What is required here is only avalanche: two fingerprints differing by one hex digit
 * must give unrelated strips, otherwise a substitution could pass for a typo.
 */
function digest(seed: string): number {
  let hash = FNV_OFFSET;
  for (let index = 0; index < seed.length; index += 1) {
    const code = seed.charCodeAt(index);
    hash = Math.imul(hash ^ (code & 0xff), FNV_PRIME);
    hash = Math.imul(hash ^ (code >>> 8), FNV_PRIME);
  }
  return hash >>> 0;
}

/**
 * Xorshift32 over the digest.
 *
 * A single 32-bit digest cannot feed twelve marks plus a grid plus a hue without reusing bits in
 * a visible way. Expanding it into a stream keeps every drawn value a function of the whole
 * fingerprint, and keeps a short or truncated fingerprint from producing a short strip.
 */
function source(seed: number): () => number {
  // Zero is xorshift's fixed point: it would emit zero forever, so the whole strip would flatten
  // to level 0 for the one seed that hashes to it. Substituting 1 costs nothing and removes the
  // case entirely.
  let state = seed === 0 ? 1 : seed;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };
}

/**
 * Height levels, one per mark, in `0 .. MARK_LEVELS - 1`.
 *
 * `count` is a parameter rather than a constant because the detail scale may one day want a
 * longer strip across a full-width panel. It does not change what the strip means.
 *
 * The modulo over a 32-bit value biases the low levels by about one part in 1.4 billion, which
 * is not a quantity anyone can see and not a quantity that matters for a value this weak anyway.
 */
export function marks(fingerprint: string, count = MARK_COUNT): number[] {
  const next = source(digest(fingerprint));
  const levels: number[] = [];
  for (let index = 0; index < count; index += 1) {
    levels.push(next() % MARK_LEVELS);
  }
  return levels;
}

export interface Identicon {
  /** `GRID_SIZE * GRID_SIZE` cells, row-major, mirrored across the vertical axis. */
  cells: boolean[];
  /** Hue in degrees, for OKLCH. Lightness and chroma are fixed by the renderer, not derived. */
  hue: number;
}

/**
 * A symmetric identicon derived from a seed — the account fingerprint, or a group's hex key.
 *
 * The grid is mirrored across the vertical axis because an asymmetric 5x5 scatter reads as
 * noise, whereas a symmetric one reads as *a shape*: the eye takes it in as a single object and
 * can therefore notice when it becomes a different object. Symmetry halves the entropy, which
 * would matter if this were a verification device. It is not.
 */
export function identicon(seed: string): Identicon {
  const next = source(digest(seed));
  const hue = next() % 360;

  const cells = new Array<boolean>(GRID_SIZE * GRID_SIZE).fill(false);
  const half = Math.ceil(GRID_SIZE / 2);
  for (let row = 0; row < GRID_SIZE; row += 1) {
    for (let column = 0; column < half; column += 1) {
      const filled = next() % 2 === 0;
      cells[row * GRID_SIZE + column] = filled;
      cells[row * GRID_SIZE + (GRID_SIZE - 1 - column)] = filled;
    }
  }

  // An empty grid would render as a flat disc — indistinguishable from the neutral placeholder
  // shown before the first poll. That is the one collision this component cannot tolerate, since
  // the whole point of the placeholder is that it never becomes *another* drawing. One chance in
  // 32768, and one line to remove.
  if (!cells.some(Boolean)) {
    for (let row = 0; row < GRID_SIZE; row += 1) {
      cells[row * GRID_SIZE + half - 1] = true;
    }
  }

  return { cells, hue };
}
