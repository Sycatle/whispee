import { MAX_PREVIEW_EDGE, MAX_PREVIEW_PIXELS, MAX_VIEWER_EDGE, fitWithin } from "./preview.ts";

/**
 * Rendering a PDF, under the rule the rest of the attachment path follows.
 *
 * # It conforms, and the mechanism is the same one `lib/preview.ts` describes
 *
 * pdf.js is a decoder in the exact sense that file means: it consumes bytes and produces, not a
 * document the sender wrote, but drawing instructions that it executes into **our** canvas. What
 * the reader sees is a raster this code painted, as with an image.
 *
 * A PDF carrying JavaScript, an `/OpenAction`, a `/Launch`, an embedded file or a `javascript:`
 * annotation does not survive the trip: none of that has a representation in a 2D context.
 *
 * # The nuance that separates it from an image, and it is worth stating
 *
 * The image decoder is the browser's, written in hardened C++ and living outside the JavaScript
 * sandbox. pdf.js is JavaScript running **on this origin** — the one holding the MLS state and
 * the identity key in IndexedDB. A code-execution flaw in it is not a remote memory corruption,
 * it is script on the page.
 *
 * Three things narrow that, and none of them is a proof:
 *
 *   - parsing happens in a dedicated `Worker`, which has no DOM;
 *   - `script-src 'self'` forbids `eval` and `new Function`, so any attempt to build code at
 *     run time fails loudly rather than quietly;
 *   - version 6 removed the `isEvalSupported` option entirely — earlier versions needed it in
 *     order to *stop* pdf.js building code at run time, and there is no longer a setting
 *     because there is no longer a path. Checked against the shipped types rather than
 *     assumed: the option was written here first and refused to compile.
 *
 * The same version dropped `disableAutoFetch`, `disableStream` and `disableRange`. Those were
 * about a document fetched over the network in pieces, and nothing here is fetched — the bytes
 * arrive decrypted, in memory, as an `ArrayBuffer`.
 *
 * # Nothing is fetched, and that took saying three times
 *
 * pdf.js reaches for a CDN by default — for character maps, for the standard fonts, for its wasm
 * decoders. `connect-src 'self'` would refuse those, and the failure is the worst kind: a CJK
 * document renders as blank pages rather than as an error. So every URL points into `public/`,
 * where `scripts/pdfjs-assets.mjs` put the files and recorded their digests.
 *
 * The worker is handed as a `workerPort` built from a same-origin `new URL(...,
 * import.meta.url)`. Setting `workerSrc` to a string would let pdf.js decide it is cross-origin
 * and wrap it in a `blob:` — which `worker-src 'self'` then refuses, again silently.
 *
 * # No text layer, no annotation layer, no link layer
 *
 * Those are DOM built from the file. A link layer in particular turns a `/URI` the sender chose
 * into a clickable target inside the application — the phishing primitive `lib/markdown.ts`
 * refuses to give markdown, arriving through a different door.
 *
 * The honest cost: **the PDF is not selectable and not searchable.** The download sits beside it,
 * as it does beside every preview.
 */

/**
 * Most pages rendered from one document.
 *
 * A page tree is a tree, so a small file can declare tens of thousands of pages. The count is
 * read before anything is drawn, which is what makes this a cheap refusal rather than a slow one.
 */
export const MAX_PDF_PAGES = 200;

/** Where the data files live. Written once here; `scripts/pdfjs-assets.mjs` puts them there. */
const ASSETS = "/pdfjs/";

/**
 * The scale to render a page at.
 *
 * A PDF declares its own size, and it may declare an absurd one: a `MediaBox` of two hundred
 * inches is legal, and `getViewport({ scale: 1 })` on it asks for a canvas of several gigabytes.
 *
 * This is the same fitting `lib/preview.ts` does for an image, with one difference worth noting
 * because that file regrets not having it: **the check precedes the allocation.** A page's
 * dimensions are known from its metadata, before anything is drawn, where an image's are known
 * only after it has been decoded.
 *
 * `zoom` multiplies the target edge rather than the result. Scaling a rendered canvas with a
 * transform magnifies pixels that were never drawn; asking pdf.js for a larger scale draws them.
 */
export function scaleFor(
  width: number,
  height: number,
  mode: "inline" | "full",
  zoom = 1,
): number {
  const edge = (mode === "full" ? MAX_VIEWER_EDGE : MAX_PREVIEW_EDGE) * zoom;
  const fitted = fitWithin(width, height, edge);

  // The pixel budget is the second ceiling and the one that binds on a wide, short page: an edge
  // of 4096 on a page eight times wider than it is tall is still well inside `MAX_VIEWER_EDGE`
  // and well past what should be held in memory.
  const budget = Math.sqrt(MAX_PREVIEW_PIXELS / (fitted.width * fitted.height));

  return (fitted.width / width) * Math.min(1, budget);
}

/** What a loaded document offers, without exposing pdf.js's own types to callers. */
export interface Document {
  readonly pages: number;
  /** Draws one page, 1-indexed, into a canvas the caller owns. */
  render(page: number, canvas: HTMLCanvasElement, mode: "inline" | "full", zoom: number): Promise<void>;
  /** Releases the worker and the parsed document. Not optional — both outlive the component. */
  destroy(): Promise<void>;
}

/**
 * Loads a PDF, or returns `null`.
 *
 * Never throws. A password-protected document, a truncated one and a file that is not a PDF at
 * all come back the same way, because the row has one answer for all three: the download link.
 *
 * The import is dynamic, and that is what keeps pdf.js out of the entry chunk — several hundred
 * kilobytes for a viewer most conversations never open.
 */
export async function open(bytes: ArrayBuffer): Promise<Document | null> {
  try {
    const pdfjs = await import("pdfjs-dist");

    // A port rather than a `workerSrc` string: see the note above on the `blob:` wrapper.
    pdfjs.GlobalWorkerOptions.workerPort = new Worker(
      new URL("pdfjs-dist/build/pdf.worker.mjs", import.meta.url),
      { type: "module" },
    );

    const task = pdfjs.getDocument({
      data: bytes,
      // Nothing reaches the network: the bytes are already here, and every asset is local.
      cMapUrl: `${ASSETS}cmaps/`,
      cMapPacked: true,
      standardFontDataUrl: `${ASSETS}standard_fonts/`,
      wasmUrl: `${ASSETS}wasm/`,
      // Does not ask the platform for its font list — one fewer fingerprinting channel and one
      // fewer code path.
      useSystemFonts: false,
      // The worker does not fetch anything itself. The assets are same-origin either way, so
      // this changes who asks rather than what is allowed — and keeping the requests on the
      // main thread keeps them inside the policy the page is subject to.
      useWorkerFetch: false,
      // A page that fails to draw one image still draws the rest of itself. A document a peer
      // sent is exactly the case where partial output beats an exception.
      stopAtErrors: false,
      // The ceiling `scaleFor` cannot reach: an image *inside* a page can declare a size the
      // page does not, and this refuses it before the decoder allocates for it.
      maxImageSize: MAX_PREVIEW_PIXELS,
    });

    // `destroy` lives on the loading task in this version rather than on the document, and it is
    // what releases the worker as well as the parsed file.
    const pdf = await task.promise;

    return {
      pages: Math.min(pdf.numPages, MAX_PDF_PAGES),

      async render(page, canvas, mode, zoom) {
        const loaded = await pdf.getPage(page);
        const base = loaded.getViewport({ scale: 1 });
        const viewport = loaded.getViewport({
          scale: scaleFor(base.width, base.height, mode, zoom),
        });

        canvas.width = Math.round(viewport.width);
        canvas.height = Math.round(viewport.height);

        const context = canvas.getContext("2d");
        if (context === null) return;

        await loaded.render({ canvas, canvasContext: context, viewport }).promise;
      },

      async destroy() {
        await task.destroy();
        pdfjs.GlobalWorkerOptions.workerPort?.terminate();
      },
    };
  } catch {
    return null;
  }
}
