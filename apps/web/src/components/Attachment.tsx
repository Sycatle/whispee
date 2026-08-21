import { useEffect, useState } from "react";

import type { AttachmentRef } from "@/lib/attachments";
import { type Preview, decodePreview, looksLikeImage, mayAnimate, release } from "@/lib/preview";
import { Icon } from "@/ui/Icon";
import { Spinner } from "@/ui/Spinner";

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
  // Set when the browser was handed a preview and refused to paint it. See the note on the
  // `<img>` below for the one cause known today. What it does not tell us is *which* cause: an
  // `error` event on an image carries no reason, so this cannot be worded more precisely than
  // "not shown here".
  const [previewRefused, setPreviewRefused] = useState(false);

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
  const offerPreview =
    looksLikeImage(attachment.mime) && preview === null && !undecodable && !previewRefused;

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
    <div className="space-y-tight">
      {preview !== null && (
        <img
          src={preview.url}
          // Sender-controlled text, rendered as text by React. It is the only description of the
          // image available: nothing here has looked at what the picture contains.
          alt={attachment.name}
          width={preview.width}
          height={preview.height}
          // The desktop shell serves this page under a CSP whose `img-src` lists `'self' data:
          // asset: http://asset.localhost` and not `blob:` — see `apps/desktop/tauri.conf.json`.
          // Every preview here is a `blob:` URL minted from our own canvas, so on that target the
          // image is blocked before it is ever decoded. Dropping back to the download row is not
          // a fix for that; widening a security policy is its own decision, made in its own
          // commit. What this handler buys is that the failure is visible and the file is still
          // reachable, instead of an empty frame the user cannot tell from a slow load.
          onError={() => {
            setPreview(null);
            setPreviewRefused(true);
          }}
          className="h-auto max-w-full rounded-bubble"
        />
      )}

      <button
        type="button"
        onClick={download}
        disabled={busy}
        aria-busy={busy}
        className="flex items-center gap-snug text-left underline disabled:opacity-60"
      >
        {/* The paperclip was a literal 📎, drawn by whatever emoji font the platform ships: blue
            on Windows, flat grey on Linux, and a tofu box in a container with no emoji font at
            all. The Lucide glyph is `currentColor` and the same shape everywhere.

            The spinner takes the icon's slot rather than sitting beside it. Both are 16 px, so
            the label does not move when the download starts — and the busy mark lands on the
            control that is actually working. */}
        {busy ? <Spinner /> : <Icon name="attach" />}
        <span className="break-all">{attachment.name}</span>
      </button>

      {offerPreview && (
        <button
          type="button"
          onClick={show}
          disabled={busy}
          className="text-caption text-(--color-ink-muted) underline disabled:opacity-60"
        >
          Show image
        </button>
      )}

      <p className="text-caption text-(--color-ink-muted)">
        {formatSize(attachment.size)}
        {busy && " — decrypting…"}
      </p>

      {/* A canvas holds one frame. Saying so is the difference between a limitation and a bug
          the user reports; the animation is one download away. */}
      {preview !== null && mayAnimate(attachment.mime) && (
        <p className="text-caption text-(--color-ink-muted)">
          First frame only — download the file for the rest.
        </p>
      )}

      {undecodable && (
        <p className="text-caption text-(--color-ink-muted)">
          This file does not decode as an image, whatever it says it is. It can only be
          downloaded.
        </p>
      )}

      {previewRefused && (
        <p className="text-caption text-(--color-ink-muted)">
          The preview could not be shown here. The file itself is unaffected — download it to
          open it.
        </p>
      )}

      {error && (
        <p role="alert" className="text-caption text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}
