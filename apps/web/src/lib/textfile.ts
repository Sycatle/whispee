/**
 * Reading an attachment as text, and refusing to when it is not.
 *
 * # `fatal: true` is the decoder, in the sense `lib/preview.ts` means
 *
 * That file states the rule the whole attachment path follows: the received bytes are never
 * rendered, they are put through something that either produces a neutral representation or
 * rejects. For an image that is `createImageBitmap`. Here it is `TextDecoder` with `fatal: true`,
 * and the flag is the entire mechanism.
 *
 * Without it, `TextDecoder` replaces every invalid byte with U+FFFD and returns happily: a 3 MB
 * executable becomes a wall of diamonds that this code would then display as if it had read it.
 * With it, bytes that are not UTF-8 do not get through the door.
 *
 * This is a *stronger* position than the image path holds, and worth saying once: what comes out
 * of here is a `string`, and a string is never a document. There is no equivalent of "an SVG that
 * turns out to run script" for text, because nothing downstream interprets it — React puts it in
 * as text nodes and `lib/highlight.ts` only labels substrings.
 *
 * # Valid UTF-8 is not the same as text
 *
 * A file of NUL bytes is perfectly valid UTF-8. So is one full of C0 control characters. Neither
 * is something to show in a `<pre>`, and the second is worse than useless: control characters
 * reorder and overwrite what surrounds them, and the bidirectional overrides make a line print in
 * an order it does not have — the same trick `lib/link.ts` refuses in a hostname.
 *
 * So there is a second filter. It is deliberately not a security measure — a string cannot
 * execute — but a refusal to pretend a `.bin` is a document.
 *
 * # Why the ceiling here is in bytes, where the image's is in pixels
 *
 * `preview.ts` explains at length why a byte ceiling is nearly useless for an image: compression
 * ratio is unbounded, so a few hundred kilobytes can describe a gigapixel, and what costs memory
 * is width × height × 4 rather than the file size. It also admits the ceiling it does use lands
 * *after* the allocation it means to prevent.
 *
 * Text has neither problem. It is not compressed, so `blob.size` bounds the decoded string within
 * a small factor, and the ceiling applies before any work is done rather than after.
 */

/** Largest file decoded at all. Past it, the row keeps its download and offers no preview. */
export const MAX_TEXT_BYTES = 1024 * 1024;

/** Most lines kept. Beyond this the tail is dropped and the viewer says so. */
export const MAX_TEXT_LINES = 4000;

/**
 * Longest line kept, in characters.
 *
 * The ceiling the other two do not cover: a minified bundle is *one* line of a megabyte, so it
 * passes the byte test and the line test and then hands the browser a single text node nothing
 * can lay out. Truncating it loses the tail of something already unreadable.
 */
export const MAX_LINE_CHARS = 2000;

/** What a file turned out to be. */
export interface TextFile {
  readonly lines: readonly string[];
  /** Whatever the name's extension said. `lib/highlight.ts` decides whether it knows it. */
  readonly lang: string | null;
  readonly truncatedLines: boolean;
  readonly truncatedColumns: boolean;
}

/**
 * Control characters that disqualify a file.
 *
 * C0 minus tab, newline and carriage return; DEL; and the bidirectional overrides, which are the
 * ones that matter in a browser.
 */
// eslint-disable-next-line no-control-regex -- naming control characters is the whole purpose
const FORBIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u;

/**
 * Decodes, or returns `null`.
 *
 * Never throws: a caller wanting to know *why* would have nothing to do differently, and the row
 * has one fallback — the download link — for every reason there is.
 */
export function decodeText(bytes: ArrayBuffer): string | null {
  let text: string;

  try {
    // `ignoreBOM` stays at its default of false, so a leading U+FEFF is consumed rather than left
    // at the head of the first line. A UTF-16 BOM is not valid UTF-8 and fails here, which is the
    // right answer: guessing encodings is how a file gets shown as the wrong language entirely,
    // and the download link is right beside it.
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }

  return FORBIDDEN.test(text) ? null : text;
}

/**
 * The language, taken from the extension.
 *
 * The extension comes from the sender, like the MIME type, and trusting it is safe here for a
 * reason worth stating: it decides which set of patterns `lib/highlight.ts` applies — that is,
 * which substrings get which class. The worst a lie can do is colour a file wrongly. The text
 * displayed is identical byte for byte whichever language is chosen, because the tokeniser's own
 * invariant is that its output reassembles into its input.
 *
 * No mapping table: the extensions people use are already the aliases `highlight.ts` knows —
 * `rs`, `py`, `ts`, `yml`. One that is not simply has no grammar, and gets no colour.
 */
export function langOf(name: string): string | null {
  const base = name.split(/[\\/]/).pop() ?? "";
  const dot = base.lastIndexOf(".");

  return dot > 0 ? base.slice(dot + 1).toLowerCase() : null;
}

/**
 * Splits decoded text into the lines a viewer can hold.
 *
 * The ceilings apply in the order they cost: bytes before decoding, lines after, columns last.
 */
export function prepare(text: string, name: string): TextFile {
  const all = text.split(/\r\n|\n|\r/);
  const truncatedLines = all.length > MAX_TEXT_LINES;
  const kept = truncatedLines ? all.slice(0, MAX_TEXT_LINES) : all;

  let truncatedColumns = false;
  const lines = kept.map((line) => {
    if (line.length <= MAX_LINE_CHARS) return line;
    truncatedColumns = true;
    return line.slice(0, MAX_LINE_CHARS);
  });

  return { lines, lang: langOf(name), truncatedLines, truncatedColumns };
}

/**
 * The whole trip, for a caller holding a blob.
 *
 * `null` for anything that is not text this can show — too large, not UTF-8, or carrying control
 * characters. The size test comes first because it is the only one that does no work.
 */
export async function readText(blob: Blob, name: string): Promise<TextFile | null> {
  if (blob.size > MAX_TEXT_BYTES) return null;

  const text = decodeText(await blob.arrayBuffer());
  return text === null ? null : prepare(text, name);
}
