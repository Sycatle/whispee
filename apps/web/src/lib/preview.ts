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
 * # It was 25 megapixels, and that was too close to what people send
 *
 * The old value was chosen to cover "a full-resolution photo from any phone or consumer camera".
 * It did not: a 5016×5016 export is 25 160 256 pixels, 0.64% over, and it was refused — with the
 * wording reserved for bytes that are not an image at all. Somebody went looking for a fault in
 * their own file, which is the cost of a ceiling that sits where ordinary content lands.
 *
 * # Why moving it is cheap, and what actually bounds memory
 *
 * Not this number. Two other things do, and they are the reason this can be raised without buying
 * a proportional risk:
 *
 *   - What is **retained** is the canvas re-encoding, bounded by `MAX_PREVIEW_EDGE` — a few
 *     hundred kilobytes whatever the source was. The full bitmap is closed before this function
 *     returns, on every path.
 *   - What is **allocated** is the decode, and this check happens *after* it. That limitation is
 *     stated at the top of this file and it has not changed: no browser API reports an image's
 *     dimensions without decoding it. So the peak was never something this number prevented.
 *
 * What the ceiling does buy is refusing to *scale and re-encode* something absurd, and refusing it
 * before `drawImage` spends time on it. That is a real cost and worth bounding — but it is bounded
 * against decode bombs, not against photographs.
 *
 * 80 megapixels is chosen to sit clear of both. A 48-megapixel phone frame and a 61-megapixel
 * full-frame camera are both comfortably inside; a gigapixel panorama and a 30 000² zip bomb are
 * both outside, by an order of magnitude rather than by a percent.
 */
export const MAX_PREVIEW_PIXELS = 80_000_000;

/**
 * Longest edge of the preview actually kept, in CSS pixels.
 *
 * The bubble is at most 75% of a pane, so nothing wider than this is ever visible; 1280 leaves
 * enough for a high-density display without keeping a second full-size copy of every image in
 * memory. A preview never grows an image — a 200px icon stays 200px.
 */
export const MAX_PREVIEW_EDGE = 1280;

/**
 * Longest edge kept when the image is the whole screen rather than a line in a thread.
 *
 * # Why a second number, and not simply a bigger first one
 *
 * `MAX_PREVIEW_EDGE` is sized for the bubble, and at that size a zoom control would be a lie:
 * magnifying a 1280px re-encoding shows larger pixels and no more picture. Detail that was never
 * decoded cannot be revealed by scaling what was.
 *
 * So the viewer decodes again, at its own ceiling, and 4096 is chosen against what people
 * actually send: it is above the long edge of a 12-megapixel phone photo, which is the common
 * case, so for most images the second decode is the whole picture and the zoom shows real detail.
 *
 * # What it costs, and why the inline path does not simply use it
 *
 * Four bytes a pixel, so a 4096-wide bitmap is on the order of 60MB retained — per image. A
 * thread scrolling past thirty of those would hold what no tab should. The viewer is one image at
 * a time, opened deliberately and closed explicitly, and it releases on the way out; the inline
 * previews stay at the bubble's size, where they are cheap and there are many of them.
 *
 * `MAX_PREVIEW_PIXELS` does not move. It bounds the *decode*, which is the allocation this module
 * cannot avoid making before it can measure — the limitation stated at the top of this file — and
 * it is the same limit whichever size is asked for afterwards.
 */
export const MAX_VIEWER_EDGE = 4096;

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
  /** Size of the re-encoding — what an `<img>` will report as its natural size. */
  width: number;
  height: number;
  /**
   * Size of the image that was decoded, before it was fitted.
   *
   * Carried because it is the only place it is still known: the bitmap is closed before this
   * function returns, and the `<img>` downstream reports the re-encoding's size, not this one.
   * Anything that tells a reader "this image is N × M" has to use these, or it states the size of
   * our own thumbnail and calls it the file's.
   */
  source: { width: number; height: number };
}

/** Why a decode produced nothing. */
export type Refusal =
  /** The bytes are not a raster image this browser can decode, whatever they claim to be. */
  | { reason: "undecodable" }
  /** A real image, decoded, and past `MAX_PREVIEW_PIXELS`. Its size is reported so it can be said. */
  | { reason: "too-large"; width: number; height: number }
  /** The browser refused a 2D context, or refused to encode the canvas. Not about the file. */
  | { reason: "unavailable" };

/** Either the re-encoding, or why there is none. */
export type Decoded = { ok: true; preview: Preview } | ({ ok: false } & Refusal);

/**
 * Decodes a decrypted attachment and re-encodes what the decoder produced.
 *
 * Never throws. It used to return `null` for every failure, on the argument that there was
 * "nothing to tell the three cases apart with that a user could act on differently" — and that
 * argument was wrong in the one case that turned up in practice.
 *
 * A 5016×5016 export decoded perfectly and was refused for being 0.64% over the pixel ceiling,
 * and the caller, having only `null`, said the file did not decode as an image. It did. Somebody
 * went looking for a fault in their own file. The reason is reported now because saying the wrong
 * one is worse than saying nothing, and because these three genuinely differ: one is about the
 * bytes, one is about their size, and one is not about the file at all.
 *
 * The canvas is created but **never inserted into the document**, and the bitmap is closed on
 * every path: the decoded pixels exist for the duration of this call and no longer. The only
 * thing that outlives it is the `blob:` URL, which the caller must `release`.
 *
 * `maxEdge` changes the size of what is kept and nothing about what is refused: the decoder is
 * the same, the pixel ceiling is the same, and an image over it is dropped whichever size was
 * asked for. A caller wanting the full-screen size passes `MAX_VIEWER_EDGE` and owns the much
 * larger allocation that comes back.
 */
export async function decodePreview(
  blob: Blob,
  /** Longest edge of the re-encoding. `MAX_VIEWER_EDGE` for a full-screen look. */
  maxEdge: number = MAX_PREVIEW_EDGE,
): Promise<Decoded> {
  let bitmap: ImageBitmap;

  try {
    bitmap = await createImageBitmap(blob);
  } catch {
    // Not a raster image, or a corrupt one. Either way there is nothing safe to show.
    return { ok: false, reason: "undecodable" };
  }

  try {
    if (!withinPixelBudget(bitmap.width, bitmap.height)) {
      return { ok: false, reason: "too-large", width: bitmap.width, height: bitmap.height };
    }

    const size = fitWithin(bitmap.width, bitmap.height, maxEdge);
    const canvas = document.createElement("canvas");
    canvas.width = size.width;
    canvas.height = size.height;

    const context = canvas.getContext("2d");
    if (context === null) return { ok: false, reason: "unavailable" };

    context.drawImage(bitmap, 0, 0, size.width, size.height);

    // PNG rather than JPEG or WebP: it is lossless and keeps transparency, and a preview bounded
    // at 1280px is small enough that the size penalty does not matter. It never leaves memory.
    const encoded = await new Promise<Blob | null>((resolve) => {
      canvas.toBlob(resolve, "image/png");
    });
    if (encoded === null) return { ok: false, reason: "unavailable" };

    return {
      ok: true,
      preview: {
        url: URL.createObjectURL(encoded),
        width: size.width,
        height: size.height,
        source: { width: bitmap.width, height: bitmap.height },
      },
    };
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
