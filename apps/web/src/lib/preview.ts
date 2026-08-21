/**
 * Showing an attached image without ever rendering the bytes that arrived.
 *
 * # The rule this module exists to keep
 *
 * `Attachment.tsx` refuses to display a received file, and the reason is sound: the MIME type
 * comes from the sender, so it is a hint and not a proof. A file declared `image/png` that is
 * really SVG or HTML, handed to the browser as a document, runs script on this origin — the
 * origin holding the MLS state and the identity key in IndexedDB. One hostile peer is enough.
 *
 * Nothing here starts trusting that hint. Instead the bytes are put through
 * `createImageBitmap`, which is an **image decoder**: it either produces a raster of pixels or
 * it rejects. What comes out the far side is a `<canvas>` re-encoding — pixels this code drew,
 * not a document the sender wrote. An SVG cannot survive that trip carrying a `<script>`, and
 * an HTML file does not survive it at all.
 *
 * The declared MIME is still read, twice, and both times for something that cannot hurt: to
 * decide whether attempting a decode is worth the memory, and to word the caption on an
 * animated format. Neither is a trust decision; a lie in either direction costs a wasted decode
 * or a slightly wrong caption.
 *
 * # Why the ceiling is in pixels and not in bytes
 *
 * There is already a 25 MiB ceiling on an attachment, and it is nearly useless as a bound on
 * decoding: compression ratio is unbounded, so a few hundred kilobytes of PNG can describe a
 * gigapixel. What costs memory is width × height × 4, and that number is not in the file size.
 *
 * So the bound is `MAX_PREVIEW_PIXELS`, checked on the decoded bitmap. The honest limitation:
 * **the check happens after the allocation it is meant to prevent**. No browser API reports an
 * image's dimensions without decoding it, and `createImageBitmap`'s `resizeWidth` cannot express
 * "shrink to fit, never grow". What the ceiling buys is that an oversized image is released
 * immediately instead of being scaled, re-encoded and held for the life of the conversation
 * view — and that the failure is a download link rather than a dead tab. What it does not buy is
 * protection from the peak of the decode itself. That peak is the browser's image pipeline,
 * which is hardened against exactly this and is not, in any case, something this module could
 * do better.
 *
 * # What a preview is not
 *
 * It is not the file. Animated formats keep one frame, colour profiles are flattened to sRGB by
 * the canvas, and metadata is dropped. The download link stays available beside every preview
 * for precisely that reason: the preview is a look, not a substitute.
 */

/**
 * Largest bitmap accepted for a preview, in pixels.
 *
 * 25 megapixels covers a full-resolution photo from any phone or consumer camera, which is what
 * people actually send. Above it, a file is a scan, a poster, or a deliberate decode bomb —
 * and for all three a download link is the better answer than a thumbnail nobody asked to wait
 * for. At four bytes a pixel this bounds the retained bitmap at roughly 100 MB.
 */
export const MAX_PREVIEW_PIXELS = 25_000_000;

/**
 * Longest edge of the preview actually kept, in CSS pixels.
 *
 * The bubble is at most 75% of a pane, so nothing wider than this is ever visible; 1280 leaves
 * enough for a high-density display without keeping a second full-size copy of every image in
 * memory. A preview never grows an image — a 200px icon stays 200px.
 */
export const MAX_PREVIEW_EDGE = 1280;

/**
 * Container formats that can hold more than one frame.
 *
 * Used only to word a caption. WebP and AVIF are listed because they *may* animate, not because
 * they usually do: saying "first frame only" about a still WebP is a harmless inaccuracy, and
 * saying nothing about an animation that silently froze is not.
 */
const ANIMATABLE = new Set(["image/gif", "image/apng", "image/webp", "image/avif"]);

/** Strips the parameters (`; charset=…`) and the casing a sender may have used. */
function baseType(mime: string): string {
  return mime.split(";", 1)[0].trim().toLowerCase();
}

/**
 * Whether a decode is worth attempting.
 *
 * Not a security gate — the decoder is the security gate. This only avoids spending a decode
 * attempt on every PDF and zip that goes past, and it fails in the harmless direction: a file
 * mislabelled `application/octet-stream` loses its preview and keeps its download link.
 */
export function looksLikeImage(mime: string): boolean {
  return baseType(mime).startsWith("image/");
}

/** Whether the caption should warn that the preview is a single frame. */
export function mayAnimate(mime: string): boolean {
  return ANIMATABLE.has(baseType(mime));
}

/** Whether a decoded bitmap is small enough to keep. See `MAX_PREVIEW_PIXELS`. */
export function withinPixelBudget(width: number, height: number): boolean {
  return width > 0 && height > 0 && width * height <= MAX_PREVIEW_PIXELS;
}

/**
 * The size to draw at: the image scaled down to fit `maxEdge`, never scaled up.
 *
 * Rounds to at least one pixel on each axis, because a canvas of zero width throws and an image
 * one pixel tall is a legitimate thing to receive.
 */
export function fitWithin(
  width: number,
  height: number,
  maxEdge: number,
): { width: number; height: number } {
  const scale = Math.min(1, maxEdge / Math.max(width, height));

  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
  };
}

/** A preview ready to be put in an `<img>`. The URL is owned by the caller — see `release`. */
export interface Preview {
  /** `blob:` URL of the canvas re-encoding. Never of the received bytes. */
  url: string;
  width: number;
  height: number;
}

/**
 * Decodes a decrypted attachment and re-encodes what the decoder produced.
 *
 * Returns `null` — never throws — for everything that is not a still raster image this code can
 * hold: bytes that do not decode, an image over the pixel ceiling, a canvas the browser refuses
 * to give a 2D context for. The single return value keeps the caller's fallback to one branch,
 * and there is nothing to tell the three cases apart with that a user could act on differently.
 *
 * The canvas is created but **never inserted into the document**, and the bitmap is closed on
 * every path: the decoded pixels exist for the duration of this call and no longer. The only
 * thing that outlives it is the `blob:` URL, which the caller must `release`.
 */
export async function decodePreview(blob: Blob): Promise<Preview | null> {
  let bitmap: ImageBitmap;

  try {
    bitmap = await createImageBitmap(blob);
  } catch {
    // Not a raster image, or a corrupt one. Either way there is nothing safe to show.
    return null;
  }

  try {
    if (!withinPixelBudget(bitmap.width, bitmap.height)) return null;

    const size = fitWithin(bitmap.width, bitmap.height, MAX_PREVIEW_EDGE);
    const canvas = document.createElement("canvas");
    canvas.width = size.width;
    canvas.height = size.height;

    const context = canvas.getContext("2d");
    if (context === null) return null;

    context.drawImage(bitmap, 0, 0, size.width, size.height);

    // PNG rather than JPEG or WebP: it is lossless and keeps transparency, and a preview bounded
    // at 1280px is small enough that the size penalty does not matter. It never leaves memory.
    const encoded = await new Promise<Blob | null>((resolve) => {
      canvas.toBlob(resolve, "image/png");
    });
    if (encoded === null) return null;

    return { url: URL.createObjectURL(encoded), width: size.width, height: size.height };
  } finally {
    // Frees the decoded pixels without waiting for a collection that may never come while the
    // conversation stays open.
    bitmap.close();
  }
}

/** Releases a preview's URL. Not optional: an unrevoked `blob:` URL keeps its bytes alive. */
export function release(preview: Preview): void {
  URL.revokeObjectURL(preview.url);
}
