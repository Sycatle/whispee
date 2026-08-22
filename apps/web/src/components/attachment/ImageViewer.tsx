import { useEffect, useState } from "react";

import type { ViewerProps } from "@/lib/viewer";
import {
  MAX_VIEWER_EDGE,
  type Preview,
  decodePreview,
  mayAnimate,
  release,
} from "@/lib/preview";

/**
 * A received image, shown as pixels this code drew.
 *
 * # The rule, and where it is actually enforced
 *
 * Not here. `lib/preview.ts` holds it and argues it: the bytes go through `createImageBitmap`,
 * which is an image *decoder* — it either produces a raster or it rejects — and what reaches the
 * `<img>` below is a `<canvas>` re-encoding. An SVG cannot carry a `<script>` through that trip,
 * and an HTML file does not survive it at all.
 *
 * This component owns none of that. It owns the two things a decode cannot do for itself: asking
 * for the bytes only once somebody wants them, and releasing what it minted.
 *
 * # Split out of `Attachment.tsx`, unchanged
 *
 * The behaviour here is the behaviour that shipped; the move is what lets three more viewers
 * arrive without `Attachment.tsx` learning what any of them are. It knows `chooseViewer` said
 * "image" and nothing else — not `createImageBitmap`, not `blob:`, not the pixel ceiling.
 */
export function ImageViewer({ blob, name, mode, onRefused }: ViewerProps) {
  const [preview, setPreview] = useState<Preview | null>(null);

  // An unrevoked `blob:` URL keeps the decoded-derived pixels alive for the life of the document.
  // Scrolling a conversation unmounts these freely, so this cleanup is the only thing bounding
  // how much of it is held.
  useEffect(() => {
    if (preview === null) return;
    return () => release(preview);
  }, [preview]);

  useEffect(() => {
    let live = true;

    // The size asked for is the whole difference between the two modes. Decoding the bubble's
    // 1280px and then scaling it up would show larger pixels and no more picture — detail that
    // was never decoded cannot be revealed by magnifying what was.
    void decodePreview(blob, mode === "full" ? MAX_VIEWER_EDGE : undefined).then((decoded) => {
      // The component may have gone while the decode was in flight. Setting state on it would be
      // a warning; releasing a preview nobody will ever revoke would be a leak.
      if (!live) {
        if (decoded !== null) release(decoded);
        return;
      }

      if (decoded === null) {
        onRefused("This file does not decode as an image, whatever it says it is.");
        return;
      }

      setPreview(decoded);
    });

    return () => {
      live = false;
    };
    // `onRefused` is deliberately out of the dependency list: it is recreated on every render of
    // the parent, and depending on it would decode the same image again on every keystroke
    // anywhere in the thread. The linter does not ask for it — it is a callback prop, not
    // reactive state — so there is no suppression here to go stale.
    //
    // `mode` is in it, and has to be: opening the viewer on an image already shown inline is
    // exactly the moment the larger decode is wanted.
  }, [blob, mode]);

  if (preview === null) return null;

  return (
    <>
      <img
        src={preview.url}
        // Sender-controlled text, rendered as text by React. It is the only description of the
        // image available: nothing here has looked at what the picture contains.
        alt={name}
        width={preview.width}
        height={preview.height}
        // An `error` event on an image carries no reason, so this cannot be worded more precisely
        // than "not shown here". It fires when a policy refuses the `blob:` before the decode —
        // the failure mode `lib/csp.ts` documents having already had once, silently.
        onError={() => {
          setPreview(null);
          onRefused("The preview could not be shown here. The file itself is unaffected.");
        }}
        // `max-h-screen` and not `max-h-full` on the full path: the wrapper around this is what
        // the zoom transform is applied to, so a height bounded by the *parent* would fight the
        // scale instead of being magnified by it.
        className={
          mode === "full"
            ? "mx-auto h-auto max-h-screen max-w-full object-contain"
            : "h-auto max-w-full rounded-bubble"
        }
      />

      {/* A canvas holds one frame. Saying so is the difference between a limitation and a bug the
          user reports; the animation is one download away. */}
      {mayAnimate(blob.type) && (
        <p className="text-caption text-(--color-ink-muted)">
          First frame only — download the file for the rest.
        </p>
      )}
    </>
  );
}
