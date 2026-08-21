import { useEffect, useState } from "react";

import type { AttachmentRef } from "@/lib/attachments";
import { type Preview, decodePreview, looksLikeImage, mayAnimate, release } from "@/lib/preview";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/**
 * A received attachment.
 *
 * # The received bytes are never rendered
 *
 * The MIME type comes from the sender: it is a hint, not a proof. Handing a file declared
 * `image/png` that turns out to be SVG or HTML to the browser as a document would run script on
 * this origin — that is, within reach of the keys in IndexedDB. A hostile peer, or one
 * compromised account, is enough.
 *
 * That rule has not moved. What is shown for an image is not the file: it is a `<canvas>`
 * re-encoding of what an image decoder produced from it, built in `lib/preview.ts`. Bytes that
 * are not a raster image do not decode, and the ones that do come back as pixels rather than as
 * a document. The `<img>` below therefore points at a `blob:` URL this code minted from its own
 * canvas, never at the attachment.
 *
 * # Nothing happens until the user asks
 *
 * There is no eager preview: the bytes do not exist until `onOpen` decrypts them, so opening a
 * conversation decodes nothing. A file that does not decode falls back to the download link,
 * which is also always present next to a preview — a preview is a look at the file, not the
 * file.
 *
 * The name comes from the sender too. It is shown as text, never interpreted as a path.
 */
export function Attachment({
  attachment,
  onOpen,
}: {
  attachment: AttachmentRef;
  onOpen: () => Promise<Blob>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  // Set when a decode was attempted and refused. It hides the button rather than letting the
  // user click it again for the same answer.
  const [undecodable, setUndecodable] = useState(false);

  // An unrevoked `blob:` URL keeps the decrypted-derived pixels alive for the life of the
  // document. Scrolling a conversation unmounts these freely, so the cleanup is the only thing
  // bounding how much of it is held.
  useEffect(() => {
    if (preview === null) return;
    return () => release(preview);
  }, [preview]);

  // Attempting a decode on every PDF that goes past would cost a decode to learn nothing. This
  // reads the sender's hint, and that is safe here: it decides how much work to do, not what to
  // trust. A lie in either direction costs a wasted decode or a missing preview.
  const offerPreview = looksLikeImage(attachment.mime) && preview === null && !undecodable;

  // Failure is not benign at this layer: the AEAD rejects a substituted or altered blob, so a
  // decryption error means the ciphertext is not the one a group member produced.
  const report = (e: unknown, fallback: string) => {
    setError(
      e instanceof Error && e.name === "OperationError"
        ? "Unreadable file: it was modified or replaced after it was sent."
        : fallback,
    );
  };

  const download = async () => {
    setBusy(true);
    setError(null);
    try {
      const blob = await onOpen();

      // Decryption succeeded, so the AEAD validated integrity: these bytes are the ones a group
      // member encrypted, unaltered in transit.
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = attachment.name;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      report(e, "Download failed.");
    } finally {
      setBusy(false);
    }
  };

  const show = async () => {
    setBusy(true);
    setError(null);
    try {
      // The decrypted blob is deliberately not kept in state. Showing the image and saving it
      // are two actions; making the second cheaper by holding the plaintext would keep every
      // opened attachment in memory for the life of the view.
      const decoded = await decodePreview(await onOpen());

      if (decoded === null) setUndecodable(true);
      else setPreview(decoded);
    } catch (e) {
      report(e, "Could not open the file.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-1">
      {preview !== null && (
        <img
          src={preview.url}
          // Sender-controlled text, rendered as text by React. It is the only description of the
          // image available: nothing here has looked at what the picture contains.
          alt={attachment.name}
          width={preview.width}
          height={preview.height}
          className="h-auto max-w-full rounded-bubble"
        />
      )}

      <button
        type="button"
        onClick={download}
        disabled={busy}
        className="flex items-center gap-2 text-left underline disabled:opacity-60"
      >
        <span aria-hidden>📎</span>
        <span className="break-all">{attachment.name}</span>
      </button>

      {offerPreview && (
        <button
          type="button"
          onClick={show}
          disabled={busy}
          className="text-xs underline opacity-70 disabled:opacity-60"
        >
          Show image
        </button>
      )}

      <p className="text-xs opacity-70">
        {formatSize(attachment.size)}
        {busy && " — decrypting…"}
      </p>

      {/* A canvas holds one frame. Saying so is the difference between a limitation and a bug
          the user reports; the animation is one download away. */}
      {preview !== null && mayAnimate(attachment.mime) && (
        <p className="text-xs opacity-70">First frame only — download the file for the rest.</p>
      )}

      {undecodable && (
        <p className="text-xs opacity-70">
          This file does not decode as an image, whatever it says it is. It can only be
          downloaded.
        </p>
      )}

      {error && (
        <p role="alert" className="text-xs text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}
