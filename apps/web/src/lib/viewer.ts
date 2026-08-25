/**
 * Which decoder to try on a received file, and nothing more than that.
 *
 * # It classifies, it does not vouch
 *
 * Both inputs come from the sender. The MIME type is the hint `lib/preview.ts` already refuses to
 * trust, and the name is the one `Attachment.tsx` already refuses to treat as a path. Nothing here
 * starts believing either.
 *
 * What this function decides is which decoder is worth *attempting*, and every decoder downstream
 * keeps its own right of refusal: `createImageBitmap` rejects what is not a raster image,
 * `TextDecoder` with `fatal: true` rejects what is not UTF-8, pdf.js rejects what is not a
 * document. A refusal always falls back to the same place — the download link, which is present
 * beside every viewer and is never replaced by one.
 *
 * That is the existing contract of `looksLikeImage`, generalised: *not a security gate — the
 * decoder is the security gate*. A lie in either direction costs a wasted decode attempt or a
 * missing preview, and neither is worth defending against.
 *
 * # The order is the safety
 *
 * The branches are tried in sequence, and the sequence is not stylistic:
 *
 *   1. **PDF** first, because `application/pdf` is unambiguous and a `.pdf` that turns out not to
 *      be one is refused by pdf.js rather than falling through to something more permissive.
 *   2. **Audio** next. It is the one viewer that hands the received bytes to a system decoder
 *      (see `lib/audio.ts`), so it must be reached only by files that actually announce
 *      themselves as audio — never as a fallback for something unrecognised.
 *   3. **Image**, and this branch is narrower than it looks: `looksLikeImage` reads the declared
 *      MIME and *never* the extension. So the only files that reach it are the ones a sender
 *      explicitly called an image, which is what makes it safe to try before text.
 *   4. **Text**, which therefore catches every markup file that did not announce itself as an
 *      image — a `.html`, `.xml` or `.svg` arriving as `application/octet-stream`, or as
 *      `text/html`. It is shown as *source*, in text nodes, and reaches nothing that could treat
 *      it as a document.
 *   5. `null` — download only. The honest answer for everything else.
 *
 * The one case worth stating outright, because it looks like a contradiction: a declared
 * `image/svg+xml` lands in the **image** branch, not the text one. That is deliberate.
 * `createImageBitmap` rasterises it into pixels this code drew — a strictly stronger answer than
 * showing its markup, and the behaviour that already ships. An `.svg` with no image MIME gets the
 * text treatment instead, because nothing claimed it was a picture.
 *
 * # Why the predicates live here and the decoders do not
 *
 * Classification is one subject and it is testable in one file: a table of MIME types and
 * extensions, with no I/O and no DOM. The decoding modules — `preview.ts`, `textfile.ts`,
 * `audio.ts`, `pdf.ts` — own the part that can fail on real bytes. Splitting the table across four
 * modules would mean four places to look when a file lands in the wrong viewer, and a matrix test
 * that has to import all four to ask one question.
 */
import { looksLikeImage } from "./preview.ts";

/** Which viewer a file should be offered to, or `null` for download only. */
export type ViewerKind = "image" | "text" | "audio" | "pdf";

/**
 * What every viewer is handed, whether it is drawn under the message or filling the screen.
 *
 * One interface rather than one per viewer: the caller switches on `ViewerKind` and must be able
 * to render the result without knowing which branch it took.
 */
export interface ViewerProps {
  /** The decrypted file. Its integrity is already established — the AEAD rejected anything else. */
  blob: Blob;
  /** The sender's name for it. Shown as text, never interpreted as a path. */
  name: string;
  /**
   * `inline` is the preview under the message; `full` is the viewer sheet.
   *
   * A flag and not two components, because the decoder, the ceilings and the refusal are the same
   * on both paths. Only the resolution asked for and the surrounding chrome differ.
   */
  mode: "inline" | "full";
  /** Called when the bytes did not survive this viewer's decoder. Wording reaches the user. */
  onRefused: (message: string) => void;
  /**
   * What the decoder found, once it has found it. Optional: a viewer with nothing to report
   * simply never calls it.
   *
   * The frame around a viewer cannot read this off the DOM. An `<img>` reports the size of the
   * re-encoding it was given, which for a large photograph is the thumbnail's size and not the
   * file's — so a frame that measured its own child would confidently state the wrong numbers.
   */
  onMeta?: (meta: { width: number; height: number }) => void;
}

/** Strips the parameters (`; charset=…`) and the casing a sender may have used. */
function baseType(mime: string): string {
  return mime.split(";", 1)[0].trim().toLowerCase();
}

/**
 * The file's extension, lowercased, or `""`.
 *
 * Everything after the **last** dot of the last path segment. Three cases this gets right and a
 * naive split does not: `archive.tar.gz` is `gz` and not `tar.gz`; `.gitignore` has no extension,
 * because a leading dot names a hidden file rather than opening one; `README` has none either.
 *
 * The separators are stripped first. Not because a path would be followed — nothing here or in
 * `Attachment.tsx` ever treats this string as one — but because `../../etc/passwd.txt` should
 * yield `txt` rather than something that depends on where the dots fell.
 */
export function extensionOf(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "";
  const dot = base.lastIndexOf(".");

  return dot > 0 ? base.slice(dot + 1).toLowerCase() : "";
}

const PDF_TYPES = new Set(["application/pdf", "application/x-pdf"]);

/**
 * Container formats a browser may be able to play.
 *
 * Listed rather than matched on the `audio/` prefix alone, because the prefix is also how a great
 * many things nobody can play announce themselves. Both routes are accepted below; this table is
 * what lets a `.opus` arriving as `application/octet-stream` still reach the player.
 */
const AUDIO_EXTENSIONS = new Set([
  "mp3",
  "m4a",
  "aac",
  "ogg",
  "oga",
  "opus",
  "wav",
  "flac",
  "weba",
  "webm",
]);

/**
 * Types that are text even though they do not say `text/`.
 *
 * The `+json` and `+xml` suffixes are the structured-syntax convention from RFC 6839, and they
 * cover far more than any list could: `application/ld+json`, `image/svg+xml`, and whatever is
 * registered next.
 */
const TEXT_TYPES = new Set([
  "application/json",
  "application/xml",
  "application/javascript",
  "application/ecmascript",
  "application/x-sh",
  "application/x-shellscript",
  "application/toml",
  "application/yaml",
  "application/x-yaml",
]);

/**
 * Extensions that mean source or prose.
 *
 * Deliberately generous on code, because that is what gets pasted into a conversation about code
 * and it almost always arrives as `application/octet-stream`. Being wrong costs a decode attempt
 * that `TextDecoder` refuses.
 */
const TEXT_EXTENSIONS = new Set([
  "txt", "text", "log", "md", "markdown", "rst", "adoc",
  "csv", "tsv", "json", "jsonl", "ndjson", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "env",
  "ts", "tsx", "js", "jsx", "mjs", "cjs", "rs", "py", "rb", "go", "java", "kt", "kts", "swift",
  "c", "h", "cc", "cpp", "hpp", "cs", "php", "pl", "lua", "sh", "bash", "zsh", "fish", "ps1",
  "sql", "graphql", "gql", "proto", "css", "scss", "sass", "less", "html", "htm", "xhtml", "svg",
  "vue", "svelte", "astro", "diff", "patch", "gitignore", "dockerfile", "makefile", "lock",
]);

/**
 * Files whose whole name is the type.
 *
 * `extensionOf` returns `""` for these by design — a leading dot does not open an extension, and
 * `Makefile` has no dot at all — so they are matched on the name instead.
 */
const TEXT_NAMES = new Set([
  "readme", "license", "licence", "changelog", "authors", "contributing", "notice",
  "makefile", "dockerfile", "gemfile", "rakefile", "procfile", "justfile",
  ".gitignore", ".gitattributes", ".dockerignore", ".editorconfig", ".env", ".npmrc", ".nvmrc",
]);

/** Whether a decode as PDF is worth attempting. */
export function looksLikePdf(mime: string, name: string): boolean {
  return PDF_TYPES.has(baseType(mime)) || extensionOf(name) === "pdf";
}

/**
 * Whether to offer the audio player.
 *
 * This is the only thing the declared type decides here, and it decides less than elsewhere: the
 * browser sniffs the bytes to pick a demuxer and ignores what the `Blob` claims. A lie costs a
 * button that appears where it should not, or one that fails to appear.
 */
export function looksLikeAudio(mime: string, name: string): boolean {
  return baseType(mime).startsWith("audio/") || AUDIO_EXTENSIONS.has(extensionOf(name));
}

/**
 * Whether to offer the text viewer.
 *
 * The union of the two hints and not their intersection: a `.rs` almost always arrives as
 * `application/octet-stream`, and a `text/plain` with no extension at all is ordinary. Requiring
 * both would lose the common case in each direction.
 */
export function looksLikeText(mime: string, name: string): boolean {
  const type = baseType(mime);
  if (type.startsWith("text/")) return true;
  if (TEXT_TYPES.has(type)) return true;
  if (type.endsWith("+json") || type.endsWith("+xml")) return true;

  const base = (name.split(/[\\/]/).pop() ?? "").toLowerCase();
  return TEXT_EXTENSIONS.has(extensionOf(name)) || TEXT_NAMES.has(base);
}

/**
 * Which viewer to offer, or `null` for a download link on its own.
 *
 * See the module comment for why the branches are in this order. The short version: text is tried
 * before image so that markup is shown as source, and `image/svg+xml` is the one exception, which
 * reaches the image branch because rasterising it is the stronger answer.
 */
export function chooseViewer(mime: string, name: string): ViewerKind | null {
  if (looksLikePdf(mime, name)) return "pdf";
  if (looksLikeAudio(mime, name)) return "audio";
  if (looksLikeImage(mime)) {
    // Only a *declared* image reaches this branch early, and only to keep SVG out of the text
    // viewer. An `.svg` with no image MIME still falls through to text below, where its markup is
    // shown rather than rendered.
    return "image";
  }
  if (looksLikeText(mime, name)) return "text";

  return null;
}
