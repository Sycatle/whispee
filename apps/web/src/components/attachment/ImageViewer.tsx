import { useEffect, useState } from "react";

import type { ViewerProps } from "@/lib/viewer";
import {
  MAX_PREVIEW_PIXELS,
  MAX_VIEWER_EDGE,
  type Preview,
  type Refusal,
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
/**
 * What to tell somebody when there is no preview.
 *
 * The wording matters more than it looks. "This file does not decode as an image" is true of
 * exactly one of these, and it was being said for all three — including for a valid photograph
 * that was fractionally too large, which reads as the application calling somebody's own file
 * corrupt. Each sentence now says whose problem it is and whether anything can be done.
 */
function reasonFor(refusal: Refusal): string {
  switch (refusal.reason) {
    case "undecodable":
      return "This file does not decode as an image, whatever it says it is. It can only be downloaded.";
    case "too-large": {
      const megapixels = Math.round((refusal.width * refusal.height) / 1_000_000);
      const ceiling = Math.round(MAX_PREVIEW_PIXELS / 1_000_000);
      // The numbers are given because they are the only thing that makes this actionable: the
      // file is fine, it is simply past what a preview will hold, and its author can say by how
      // much rather than guessing.
      return `This image is ${refusal.width}×${refusal.height} — ${megapixels} megapixels, past the ${ceiling} a preview holds. Download it to see it in full.`;
    }
    case "unavailable":
      return "The preview could not be built here. The file itself is unaffected — download it to open it.";
  }
}

export function ImageViewer({ blob, name, mode, onRefused, onMeta }: ViewerProps) {
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
        if (decoded.ok) release(decoded.preview);
        return;
      }

      if (decoded.ok) {
        setPreview(decoded.preview);
        // The decoded size, not the re-encoded one. `preview.source` exists precisely because
        // this is the last point at which it is known.
        onMeta?.(decoded.preview.source);
        return;
      }

      // Each reason gets its own sentence, because the file is at fault in only one of them and
      // saying so when it is not sends somebody looking for a problem they do not have.
      onRefused(reasonFor(decoded));
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
        // Inline, an image is a thumbnail and not the picture. It used to take the full width of
        // the text column, which put a 533px square in the middle of a conversation and pushed
        // everything said around it off the screen — an attachment is one line of a thread, and
        // it should cost about what a few lines of text cost.
        //
        // Bounded on the *height* rather than the width, because the width is already bounded by
        // the column and the shape that actually breaks a thread is the tall one: a screenshot of
        // a phone is narrow and endless, and `max-w` does nothing to it. `w-auto` keeps the ratio.
        //
        // Full screen is the other half of the same decision. The thumbnail can be small because
        // one click makes it as large as the screen allows — see `AttachmentViewer`.
        //
        // `max-h-screen` and not `max-h-full` on that path: the wrapper around this is what the
        // zoom transform is applied to, so a height bounded by the *parent* would fight the scale
        // instead of being magnified by it.
        className={
          mode === "full"
            ? "mx-auto h-auto max-h-screen max-w-full object-contain"
            : "h-auto max-h-[14rem] w-auto max-w-full rounded-bubble object-contain"
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
