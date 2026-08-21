/**
 * Message padding, so that size stops informing the server.
 *
 * # What size reveals
 *
 * The content is encrypted, but its **length** is not: it crosses MLS almost unchanged, and the
 * server reads it on every envelope. That is enough to tell "yes" from "I'll call you back in ten
 * minutes", to spot a pasted password, to recognise a boilerplate message. Over a conversation
 * followed for a while, the sequence of lengths is a signature.
 *
 * # The trade-off, which is real
 *
 * Padding costs bandwidth: one byte transmitted for nothing per byte added. Buckets that are too
 * fine hide nothing, too wide waste. The chosen buckets start at 256 bytes — above the
 * overwhelming majority of written messages, which therefore all become **the same size** — then
 * double.
 *
 * Doubling bounds the waste to under 100 % and gives a logarithmic scale: the server only learns
 * the order of magnitude, never the size.
 *
 * # What this does not hide
 *
 * Who writes, to whom, and when. The rhythm of a conversation stays entirely legible, and it often
 * says more than the lengths. Masking it would take decoy traffic — a permanent cost, including
 * when nobody is talking.
 *
 * Attachments go through here too, with a ceiling — see `attachments.ts`. Their size is dominated
 * by the file, so the first buckets never apply to them; what applies is the doubling, and the
 * bandwidth it costs is far from free on a file of several megabytes.
 */

/** First bucket. Chosen above nearly all written messages. */
const FIRST_BUCKET = 256;

/**
 * End-of-content marker, then zeroes — ISO/IEC 7816-4.
 *
 * Plain zero filling would be ambiguous: content legitimately ending in a zero would become
 * indistinguishable from its padding. The marker removes the ambiguity for no more than one byte.
 */
const MARKER = 0x80;

/**
 * The bucket reaching at least `length`, never above `ceiling`.
 *
 * A ceiling is not a refinement of the scheme, it is a concession to a transport that has one:
 * everything between the last reachable doubling and the ceiling collapses into a single final
 * bucket. That bucket leaks no more than the doubling would have — "larger than the last bucket"
 * is exactly the class the next doubling would have carved out — but it costs more bandwidth,
 * because a payload just past the last doubling is inflated all the way to the ceiling.
 */
function bucket(length: number, ceiling: number): number {
  let size = FIRST_BUCKET;
  while (size < length && size < ceiling) size *= 2;
  return Math.min(size, ceiling);
}

/**
 * Pads up to the next bucket.
 *
 * The marker is **always** added, even when the length falls exactly on a bucket: without it,
 * removal would not know whether the last byte belongs to the content.
 *
 * `ceiling` caps the largest bucket, for a caller whose transport refuses anything above a size.
 * It throws rather than returning something shorter than asked: a caller that hands over more
 * than `ceiling - 1` bytes has a bug in its own limit, and silently padding to less than the
 * ceiling would produce a size that identifies the payload — the opposite of the point.
 */
export function pad(body: Uint8Array, ceiling = Number.POSITIVE_INFINITY): Uint8Array {
  if (body.length + 1 > ceiling) {
    throw new Error(`body of ${body.length} bytes does not fit under a ceiling of ${ceiling}`);
  }

  const size = bucket(body.length + 1, ceiling);
  const out = new Uint8Array(size);
  out.set(body);
  out[body.length] = MARKER;
  return out;
}

/**
 * Removes the padding.
 *
 * Throws on malformed padding rather than guessing: these bytes were authenticated by MLS, so they
 * do come from a member — but a member can send anything at all, by mistake or on purpose, and a
 * loose reading here would become a difference of interpretation between clients.
 */
export function unpad(padded: Uint8Array): Uint8Array {
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0x00) end -= 1;

  if (end < 0 || padded[end] !== MARKER) {
    throw new Error("malformed padding");
  }

  return padded.subarray(0, end);
}
