import { useEffect, useRef, useState } from "react";

import type { ViewerProps } from "@/lib/viewer";

/**
 * An attached sound, played.
 *
 * # This is the one place received bytes reach a decoder without being re-emitted
 *
 * Every other viewer keeps the rule `lib/preview.ts` states. An image is decoded by
 * `createImageBitmap` and what reaches the `<img>` is a canvas re-encoding — pixels this code
 * drew, never the file. Text is decoded to a `string`, which is not a document at all. A PDF is
 * painted into a canvas.
 *
 * Audio is not. The `<audio>` element below is handed a `blob:` URL of the **decrypted file as it
 * arrived**, and the platform's media decoder reads the sender's bytes. That is a break in the
 * rule, it is the only one in this codebase, and it is written here rather than discovered later.
 *
 * # The conforming version exists and is unaffordable
 *
 * `decodeAudioData` is the exact counterpart of `createImageBitmap`: a decoder that either
 * rejects or returns samples, which could be re-encoded to WAV so that only our own bytes are
 * ever served. The circuit is real. It is simply not payable here.
 *
 * It requires the whole file at once and returns uncompressed float32 PCM — about 176 kB per
 * second of stereo. The 25 MiB an attachment may reach is, in MP3, on the order of twenty-five
 * minutes: roughly **250 MB of PCM** held for the length of the listening, plus a re-encoded WAV
 * of comparable size. The tab dies before the conversion ends. The trick that renders an image
 * thumbnail in 40 ms is, for audio, a factor of ten in memory over content ten times as long.
 *
 * # Pre-flighting through `decodeAudioData` anyway would be theatre
 *
 * It is the obvious compromise and it protects nothing: it would push the same bytes through the
 * *same* system decoder, one more time. If the flaw is in the MP4 parser, `decodeAudioData`
 * reaches it too — earlier, and with nobody watching. The gesture looks like `createImageBitmap`
 * without having the property that makes `createImageBitmap` worth anything, which is the
 * re-emission behind it.
 *
 * What it would have bought — a duration and a clean rejection before the element is mounted —
 * arrives free with `loadedmetadata`, which decodes no more than a header.
 *
 * # What the break does not cost
 *
 * An `<audio>` element does not navigate. Bytes that are not a media stream raise an `error`
 * event; they never become a document, so nothing on this path turns into script on the origin
 * holding the MLS state and the identity key. That is the property `img-src blob:` relies on too,
 * and `media-src blob:` is no wider: a `blob:` is not a network origin, nothing outside this
 * document can mint one, and the server cannot inject one.
 *
 * # What it does cost
 *
 * A decoding surface. Media demuxers and decoders — MP4, Matroska, MP3, AAC, Vorbis, Opus, FLAC —
 * are a larger and historically more accident-prone body of code than image decoders, and here
 * they are handed a file a peer chose. On the desktop shell it is worse and should be said:
 * WebKitGTK delegates playback to GStreamer, so to a set of plugins installed on the user's
 * machine that no code in this repository selects or bounds.
 *
 * The position taken is that this decoder is the one the user invokes anyway by opening the
 * downloaded file in whatever player they have — the preview does not create the risk, it brings
 * it forward by one click. That is a defensible position. It is not a proof.
 *
 * # The declared type decides nothing here, unlike everywhere else
 *
 * `chooseViewer` reads it to decide whether to offer this at all. Past that it is inert: the
 * browser sniffs the bytes to pick a demuxer and ignores what the `Blob` claims. A lie costs a
 * button that appears where it should not, or one that fails to appear.
 */

/** A duration a person can read. `1:04`, and `1:02:03` only when there is an hour to show. */
function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "";

  const whole = Math.floor(seconds);
  const parts = [Math.floor(whole / 3600), Math.floor((whole % 3600) / 60), whole % 60];

  return (parts[0] === 0 ? parts.slice(1) : parts)
    .map((part, index) => (index === 0 ? String(part) : String(part).padStart(2, "0")))
    .join(":");
}

export function AudioViewer({ blob, name, onRefused }: ViewerProps) {
  const [url, setUrl] = useState<string | null>(null);
  const [duration, setDuration] = useState<number | null>(null);
  const element = useRef<HTMLAudioElement>(null);

  useEffect(() => {
    const minted = URL.createObjectURL(blob);
    setUrl(minted);

    return () => {
      // The order matters and is the counterpart of `bitmap.close()` in `lib/preview.ts`. A media
      // element holding a revoked source can keep the engine's buffer alive, so it is stopped and
      // detached from its source *before* the URL goes — otherwise the decrypted bytes outlive
      // the component that decrypted them.
      const audio = element.current;
      if (audio) {
        audio.pause();
        audio.removeAttribute("src");
        audio.load();
      }
      URL.revokeObjectURL(minted);
    };
  }, [blob]);

  if (url === null) return null;

  /* A width in `rem`, not `w-full`, and the difference is the whole reason this player was
     usable in a mockup and 24 pixels wide in the thread.
  
     `Messages.tsx` lays an author's turns out in a column with `items-end` or `items-start`,
     so that the lane hugs the side the sender is on. Both are `align-items` values other than
     `stretch`, which means every child of that column is sized to its **content** rather than
     to the column. A percentage width inside it is therefore circular — it resolves against a
     parent whose width is resolving against it — and the browser settles on the intrinsic
     minimum. For a `<canvas>` or an `<img>` that minimum is the real thing and everything
     looks fine, which is why this survived review; for `<audio>` it is the width of nothing,
     and the control collapsed to a sliver with no play button in it.
  
     `min()` rather than a bare `22rem` so a narrow window still gets a player that fits the
     lane instead of one that overflows it.
   */

  return (
    <div className="flex w-[min(22rem,100%)] flex-col gap-tight">
      {/* `jsx-a11y/media-has-caption` asks for a `<track>`, and it is right to ask.
 
          There is none to give. A caption track is authored alongside the media, and this file
          arrived encrypted from somebody else with nothing beside it — the protocol carries a
          name, a size and a key, and no place to put a transcript even if one existed. Generating
          one would mean speech recognition, which means either shipping a model or sending a
          decrypted voice message to a service, and the second is the thing this application is
          built to make impossible.
 
          So the limitation is real and stands: **a voice message is not accessible to somebody
          who cannot hear it**, and nothing here fixes that. What can be done is done — the file
          name is announced, the duration is text, and the download offers the bytes to whatever
          tool the reader already trusts. The rule is suppressed on this line rather than in the
          configuration, so the next media element has to make its own argument. */}
      {/* eslint-disable-next-line jsx-a11y/media-has-caption -- argued directly above */}
      <audio
        ref={element}
        src={url}
        controls
        // A second deliberate gesture after the one that decrypted the file: even now, no byte
        // reaches the decoder until play is pressed.
        preload="none"
        // Never `autoPlay`, and never `loop`. A voice message that starts by itself in a public
        // place is an operational security problem rather than an ergonomic one.
        aria-label={`Audio: ${name}`}
        onLoadedMetadata={(event) => setDuration(event.currentTarget.duration)}
        // An `error` on a media element carries no usable reason, so this cannot be worded more
        // precisely than it is.
        onError={() => onRefused("This file could not be played here. Download it to open it.")}
        // The platform's own controls rather than buttons of our own: they come with the
        // keyboard, the screen reader, the system shortcuts and the output device picker, none of
        // which would be rebuilt as well here.
        // `w-full` is meaningful again here: the wrapper above now has a definite width for it
        // to be a percentage of.
        className="w-full max-w-full"
      />

      {/* Spoken, because a screen reader does not read a media element's timeline reliably —
          and because the duration is the one thing somebody deciding whether to listen wants. */}
      {duration !== null && formatDuration(duration) !== "" && (
        <span className="text-caption text-(--color-ink-muted)">{formatDuration(duration)}</span>
      )}
    </div>
  );
}
