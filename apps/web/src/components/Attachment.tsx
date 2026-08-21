import { useState } from "react";
import type { AttachmentRef } from "@/lib/attachments";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/**
 * A received attachment.
 *
 * The file is **downloaded, never rendered inline**. The MIME type comes from the sender: it is
 * a hint, not a proof. Displaying a file declared `image/png` that turns out to be SVG or HTML
 * would run script on this origin — that is, within reach of the keys in IndexedDB. A hostile
 * peer, or one compromised account, is enough.
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
      // A failure here is not benign: the AEAD rejects a substituted or altered blob.
      setError(
        e instanceof Error && e.name === "OperationError"
          ? "Unreadable file: it was modified or replaced after it was sent."
          : "Download failed.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-1">
      <button
        type="button"
        onClick={download}
        disabled={busy}
        className="flex items-center gap-2 text-left underline disabled:opacity-60"
      >
        <span aria-hidden>📎</span>
        <span className="break-all">{attachment.name}</span>
      </button>
      <p className="text-xs opacity-70">
        {formatSize(attachment.size)}
        {busy && " — decrypting…"}
      </p>
      {error && (
        <p role="alert" className="text-xs text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}
