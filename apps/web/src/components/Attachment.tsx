import { useEffect, useState } from "react";

import { ImageViewer } from "@/components/attachment/ImageViewer";
import type { AttachmentRef } from "@/lib/attachments";
import { type ViewerKind, type ViewerProps, chooseViewer } from "@/lib/viewer";
import { Icon } from "@/ui/Icon";
import { Spinner } from "@/ui/Spinner";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/**
 * The viewers that exist, by the kind that asks for them.
 *
 * Partial on purpose, and it is what makes this file additive rather than a switch that grows a
 * branch per batch. `chooseViewer` names the decoder a file *deserves* whether or not it has been
 * written yet; a kind with no entry here falls back to the download row, which is exactly what
 * every viewer's own refusal falls back to. Audio, text and PDF land here one commit at a time,
 * and nothing else in this file changes when they do.
 */
const VIEWERS: Partial<Record<ViewerKind, (props: ViewerProps) => React.ReactNode>> = {
  image: ImageViewer,
};

/**
 * A received attachment: its name, its size, a way to save it, and a way to look at it.
 *
 * # The received bytes are never rendered
 *
 * The MIME type comes from the sender: it is a hint, not a proof. Handing a file declared
 * `image/png` that turns out to be SVG or HTML to the browser as a document would run script on
 * this origin — that is, within reach of the keys in IndexedDB. A hostile peer, or one compromised
 * account, is enough.
 *
 * That rule has not moved; what has moved is where it is kept. This component no longer knows how
 * any file is decoded. It asks `lib/viewer.ts` which decoder a file deserves, hands the bytes to
 * whichever one exists, and shows the download row when none does or when one refuses. Every
 * refusal has the same landing place, and the download link sits beside a viewer rather than being
 * replaced by it — a preview is a look at the file, not the file.
 *
 * # Nothing happens until the user asks
 *
 * The bytes do not exist until `onOpen` decrypts them, so opening a conversation decodes nothing.
 *
 * # What holding the plaintext costs, per viewer
 *
 * This file used to say the decrypted blob was deliberately not kept in state, and that was true
 * while an image was the only case: it is re-encoded and the original is dropped. It stops being
 * true as the other viewers arrive — audio plays progressively and PDF pages are rendered on
 * demand, so both need the plaintext for as long as they are on screen. Hence `close`: shutting a
 * viewer drops the blob rather than merely hiding it, and that is the only thing bounding how much
 * decrypted material an open conversation holds.
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
  const [opened, setOpened] = useState<Blob | null>(null);
  // Set when a viewer was handed bytes and gave them back. It carries the wording the viewer chose
  // and hides the button rather than letting the user click it again for the same answer.
  const [refused, setRefused] = useState<string | null>(null);

  const kind = chooseViewer(attachment.mime, attachment.name);
  const Viewer = kind === null ? undefined : VIEWERS[kind];
  const offer = Viewer !== undefined && opened === null && refused === null;

  // Closing is not optional for audio and PDF: the blob is the decrypted file, and an unmounted
  // viewer that left it in state here would keep it for the life of the thread.
  useEffect(() => () => setOpened(null), []);

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
      setOpened(await onOpen());
    } catch (e) {
      report(e, "Could not open the file.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-tight">
      {Viewer !== undefined && opened !== null && (
        <Viewer
          blob={opened}
          name={attachment.name}
          mode="inline"
          onRefused={(message) => {
            setOpened(null);
            setRefused(message);
          }}
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

      {offer && (
        <button
          type="button"
          onClick={show}
          disabled={busy}
          className="text-caption text-(--color-ink-muted) underline disabled:opacity-60"
        >
          {kind === "image" ? "Show image" : "Show contents"}
        </button>
      )}

      <p className="text-caption text-(--color-ink-muted)">
        {formatSize(attachment.size)}
        {busy && " — decrypting…"}
      </p>

      {refused !== null && <p className="text-caption text-(--color-ink-muted)">{refused}</p>}

      {error && (
        <p role="alert" className="text-caption text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}
