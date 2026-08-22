import { useEffect, useState } from "react";

import { AttachmentViewer } from "@/components/attachment/AttachmentViewer";
import { AudioViewer } from "@/components/attachment/AudioViewer";
import { ImageViewer } from "@/components/attachment/ImageViewer";
import { TextViewer } from "@/components/attachment/TextViewer";
import type { AttachmentRef } from "@/lib/attachments";
import { type ViewerKind, type ViewerProps, chooseViewer } from "@/lib/viewer";
import { cn } from "@/ui/cn";
import { ContextMenu } from "@/ui/ContextMenu";
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
/**
 * Kinds a bigger frame does something for.
 *
 * A picture and a document gain from the room — detail that a thumbnail cannot hold, a page that
 * wants a page's width. A text file gains a little and is included for it. Sound gains nothing:
 * the player is the same player, and offering to enlarge it promises a difference that does not
 * arrive.
 */
const ENLARGEABLE: ReadonlySet<ViewerKind> = new Set<ViewerKind>(["image", "text", "pdf"]);

const VIEWERS: Partial<Record<ViewerKind, (props: ViewerProps) => React.ReactNode>> = {
  image: ImageViewer,
  text: TextViewer,
  audio: AudioViewer,
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
  align = "start",
}: {
  attachment: AttachmentRef;
  onOpen: () => Promise<Blob>;
  /**
   * Which edge the rows hang from.
   *
   * A prop and not a selector reaching in from `Messages.tsx`. That is how it was done first —
   * `[&_button.flex]:justify-end` on the row — and it worked for exactly one of the four things
   * in here: `text-right` is inherited and reaches text nodes, but the file name and the preview
   * are a flex button and an image, and both stayed against the left edge of a right-aligned
   * message. A component that has to be styled from outside by guessing at its markup is a
   * component that is styled wrongly the first time its markup changes.
   */
  align?: "start" | "end";
}) {
  const [busy, setBusy] = useState(false);
  // Whether the open blob is filling the screen or sitting under the message. One flag and not a
  // second copy of the bytes: the sheet shows the same `opened`, at a different size.
  const [full, setFull] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<Blob | null>(null);
  // Set when a viewer was handed bytes and gave them back. It carries the wording the viewer chose
  // and hides the button rather than letting the user click it again for the same answer.
  const [refused, setRefused] = useState<string | null>(null);

  const kind = chooseViewer(attachment.mime, attachment.name);
  // True once something is actually on screen for this file. Not `opened !== null` alone: a
  // viewer that refused sets `refused` and unmounts, and the name has to come back with it.
  const shown = opened !== null && refused === null;
  const Viewer = kind === null ? undefined : VIEWERS[kind];
  const offer = Viewer !== undefined && opened === null && refused === null;

  // Closing is not optional for audio and PDF: the blob is the decrypted file, and an unmounted
  // viewer that left it in state here would keep it for the life of the thread.
  useEffect(() => () => setOpened(null), []);

  // A refusal drops the bytes and closes the sheet with them. Leaving the sheet up over a viewer
  // that just said it could not read the file would be a frame around nothing.
  const refuse = (message: string) => {
    setOpened(null);
    setFull(false);
    setRefused(message);
  };

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

  const body = (
    // A flex column rather than `space-y-*`, because the rows have to be aligned as well as
    // spaced, and `items-*` is what says which edge they hang from.
    <div className={cn("flex flex-col gap-tight", align === "end" ? "items-end" : "items-start")}>
      {Viewer !== undefined && opened !== null && (
        <>
          {/* A picture is its own affordance: clicking it opens it, and an "Enlarge" link beside
              it would only say what the click already says. It still has to be a real `<button>`
              — a target only a pointer can reach is not a control.

              Only a picture, though. Wrapping every viewer this way would put a media player's
              own controls inside a button, where the outer click swallows play and seek, and
              nested interactive elements are invalid besides. The kinds that carry their own
              controls get an explicit trigger instead, below. */}
          {kind === "image" ? (
            <button
              type="button"
              onClick={() => setFull(true)}
              className="block cursor-zoom-in rounded-bubble focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent)"
              aria-label={`Open ${attachment.name} full screen`}
            >
              <Viewer blob={opened} name={attachment.name} mode="inline" onRefused={refuse} />
            </button>
          ) : (
            <>
              <Viewer blob={opened} name={attachment.name} mode="inline" onRefused={refuse} />
              {/* Not offered for sound. A screen's worth of a media player is a media player with
                  more space around it: there is nothing a bigger frame reveals, and a control
                  that opens onto no difference is a control that teaches people to distrust the
                  others. `ENLARGEABLE` is the list of kinds where the frame changes what can be
                  read — the same distinction `AttachmentViewer` draws for the zoom. */}
              {ENLARGEABLE.has(kind!) && (
                <button
                  type="button"
                  onClick={() => setFull(true)}
                  className="text-caption text-(--color-ink-muted) underline"
                >
                  Open full screen
                </button>
              )}
            </>
          )}

          {full && kind !== null && (
            <AttachmentViewer
              blob={opened}
              name={attachment.name}
              kind={kind}
              onRefused={refuse}
              onClose={() => setFull(false)}
              onSave={() => void download()}
            >
              {/* The sheet is handed the component rather than the kind: this file is the only
                  one that maps one to the other, and `AttachmentViewer` stays a frame that can
                  hold whatever the next batch adds. */}
              {(props) => <Viewer {...props} />}
            </AttachmentViewer>
          )}
        </>
      )}

      {/* Under a preview, the row is the picture and nothing else.

          The name, the size and the download all used to sit beneath it, and together they said
          more about the file than the file said about itself — a thread of photographs read as a
          list of file names with pictures attached. None of the three is information somebody
          scanning a conversation is looking for.

          They are not gone, they have moved to where they are the subject rather than the
          furniture: the context menu on this row, and the viewer, which has both the room to
          state them and a reason to. `lib/preview.ts` requires that the real bytes stay
          reachable beside every preview — a preview is a look at the file, not the file — and the
          viewer is where "beside" now is.

          The menu is deliberately not the only route. `ui/ContextMenu.tsx` says why: a menu that
          is the sole way to reach something is hidden behind a gesture that does not exist on
          touch and is invisible to a screen reader. Clicking the picture opens the viewer, and
          the viewer carries a real button. */}
      {!shown && (
        <>
          <button
            type="button"
            onClick={download}
            disabled={busy}
            aria-busy={busy}
            className={cn(
              "flex items-center gap-snug underline disabled:opacity-60",
              align === "end" ? "text-right" : "text-left",
            )}
          >
            {/* The paperclip was a literal 📎, drawn by whatever emoji font the platform ships:
                blue on Windows, flat grey on Linux, and a tofu box in a container with no emoji
                font at all. The Lucide glyph is `currentColor` and the same shape everywhere.

                The spinner takes the icon's slot rather than sitting beside it. Both are 16 px,
                so the label does not move when the download starts — and the busy mark lands on
                the control that is actually working. */}
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
        </>
      )}

      {refused !== null && <p className="text-caption text-(--color-ink-muted)">{refused}</p>}

      {error && (
        <p role="alert" className="text-caption text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );

  /**
   * The file's own actions, on the file.
   *
   * Nested inside the row's menu, which is the pattern `Messages.tsx` already uses for the author
   * card: Radix hands the event to the innermost trigger, so right-clicking a picture asks about
   * the picture and right-clicking the sentence beside it asks about the message.
   *
   * Everything here is reachable without it — clicking the thumbnail opens the viewer, and the
   * viewer carries both actions as buttons. That is the rule `ui/ContextMenu.tsx` states: this is
   * a shortcut to what is already there, never the only way to it.
   */
  return (
    <ContextMenu trigger={body}>
      <ContextMenu.Item
        icon="search"
        // Only where there is something to enlarge. An entry that opens an empty frame is worse
        // than an entry that is not there.
        disabled={Viewer === undefined || busy}
        onSelect={() => {
          if (opened !== null) setFull(true);
          else void show().then(() => setFull(true));
        }}
      >
        Open larger
      </ContextMenu.Item>

      <ContextMenu.Item icon="attach" disabled={busy} onSelect={() => void download()}>
        {/* "Original size" because the viewer shows a re-encoding: one frame of an animation, no
            colour profile, no metadata. The distinction is the whole reason both entries exist. */}
        Save to device — original size
      </ContextMenu.Item>
    </ContextMenu>
  );
}
