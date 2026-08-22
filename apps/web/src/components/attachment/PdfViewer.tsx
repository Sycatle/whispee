import { useEffect, useRef, useState } from "react";

import { type Document, open } from "@/lib/pdf";
import type { ViewerProps } from "@/lib/viewer";
import { Button } from "@/ui/Button";

/**
 * An attached PDF, drawn.
 *
 * `lib/pdf.ts` carries the argument for why this conforms to the rule the attachment path
 * follows, and the nuance that separates it from an image. This file is the frame: one page on
 * screen, and a way to reach the others.
 *
 * # One canvas, one page
 *
 * Rendering every page into its own canvas is the obvious shape and the wrong one here: a
 * hundred-page document would hold a hundred rasters, and the ceiling on pages exists precisely
 * because a small file can declare a great many. One mounted canvas bounds what is held to a
 * single page, whatever the document claims to be.
 *
 * The cost is that reading it means paging rather than scrolling, which is worse for a long
 * document and is why the download stays where it is.
 */
export function PdfViewer({ blob, name, mode, onRefused }: ViewerProps) {
  const [document, setDocument] = useState<Document | null>(null);
  const [page, setPage] = useState(1);
  const canvas = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    let live = true;
    let opened: Document | null = null;

    void blob
      .arrayBuffer()
      .then(open)
      .then((loaded) => {
        if (!live) {
          void loaded?.destroy();
          return;
        }

        if (loaded === null) {
          // One sentence for every reason — encrypted, truncated, not a PDF at all — because the
          // reader has the same thing to do about each, and it is already on screen.
          onRefused("This file could not be read as a PDF. It can still be downloaded.");
          return;
        }

        opened = loaded;
        setDocument(loaded);
      });

    return () => {
      live = false;
      // The worker and the parsed document both outlive this component otherwise. `destroy` is
      // what releases them, and it is on the loading task rather than on the document — see
      // `lib/pdf.ts`.
      void opened?.destroy();
    };
    // `onRefused` is a callback prop rather than reactive state: depending on it would reopen the
    // document on every render of the parent.
  }, [blob]);

  // Redrawn when the page changes, and when the frame does: a page rendered at the thumbnail's
  // scale and then shown full screen would be a blurred enlargement of pixels that were never
  // drawn, which is the mistake `lib/preview.ts` documents for images.
  useEffect(() => {
    if (document === null || canvas.current === null) return;
    void document.render(page, canvas.current, mode, 1);
  }, [document, page, mode]);

  if (document === null) return null;

  return (
    <div className="flex flex-col items-center gap-tight">
      <canvas
        ref={canvas}
        // The name is the only description available: nothing here has read the document.
        aria-label={`Page ${page} of ${name}`}
        role="img"
        className="h-auto max-w-full rounded-control"
      />

      {document.pages > 1 && (
        <div className="flex items-center gap-snug text-caption">
          <Button
            variant="secondary"
            onClick={() => setPage((n) => Math.max(1, n - 1))}
            disabled={page === 1}
          >
            Previous
          </Button>
          {/* Announced, because the canvas beside it says nothing when the page changes: its
              `aria-label` updates, but a label change on an unfocused element is not spoken. */}
          <span aria-live="polite" className="text-(--color-ink-muted)">
            {page} / {document.pages}
          </span>
          <Button
            variant="secondary"
            onClick={() => setPage((n) => Math.min(document.pages, n + 1))}
            disabled={page === document.pages}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
