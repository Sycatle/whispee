import { useEffect, useState } from "react";

import { Button } from "@/ui/Button";
import { Spinner } from "@/ui/Spinner";
import {
  type LinkPreview,
  fetchPreview,
  fetchPreviewImage,
  previewAvailable,
} from "@/lib/link-preview";
import { type Preview, decodePreview } from "@/lib/preview";

/**
 * What a site says about a link, once somebody has asked for it.
 *
 * # The label is the feature
 *
 * The button says **Contact this site**, not *Preview*, and that is not a wording preference. A
 * preview generated here is a request to a server the sender chose: whoever sends
 * `https://their-server/{uuid}` and watches it arrive learns that the recipient opened the
 * conversation, when, and from which address. In an application where everything else is
 * encrypted end to end, that is the most profitable side channel available — so the control has
 * to describe the action rather than the result. Somebody who would not press *contact this site*
 * would press *preview*, and they would be pressing the same thing.
 *
 * Signal answers this better: the **sender** builds the preview and ships it inside the encrypted
 * message, so the recipient contacts nobody. That needs a field on the wire, which is a protocol
 * change; this is what can be built without one, and the difference is worth knowing.
 *
 * # Never automatic, never remembered
 *
 * Nothing here runs on mount. There is no cache — not in this component, not in
 * `lib/link-preview.ts` — because a cache turns one press into a record, and a memoised result
 * would silently re-arm the request on the next render. Closing the card and opening it again is
 * a second, deliberate contact, and it should be.
 *
 * The card cannot appear where nobody pressed anything: `RichText` takes it as an opt-in prop, so
 * the rail, the quotes and the notifications *cannot* render one. That is structure rather than
 * a comment asking people not to.
 *
 * # The image is a second press, and it is not rendered
 *
 * The text card is shown without downloading a picture. When one is asked for, the bytes come
 * back from a server nobody vetted — **exactly the situation of an attachment** — so they go
 * through `decodePreview`, which decodes them and re-emits a PNG of ours. Not one new line of
 * decoding lives here. That reuse is the demonstration that `lib/preview.ts` was put in the right
 * place: the second source of hostile images inherits the first one's defence unchanged.
 */
export function LinkCard({ url }: { url: string }) {
  const [state, setState] = useState<"idle" | "loading" | "shown">("idle");
  const [preview, setPreview] = useState<LinkPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Not offered at all where there is no native process to make the request. See `lib/platform.ts`
  // on why the native code is in the web bundle and dead there.
  if (!previewAvailable()) return null;

  if (state === "idle") {
    return (
      <div className="my-tight">
        <Button
          size="sm"
          variant="quiet"
          onClick={() => {
            setState("loading");
            setError(null);
            fetchPreview(url).then(
              (fetched) => {
                setPreview(fetched);
                setState("shown");
              },
              (reason: unknown) => {
                setError(reason instanceof Error ? reason.message : "This site could not be contacted.");
                setState("idle");
              },
            );
          }}
        >
          Contact this site
        </Button>

        {/* The sentence the native side produced, shown as written. Those sentences name what was
            refused and never quote the URL back: a hostile title echoed into the thread is how a
            crafted string becomes something somebody trusts. */}
        {error !== null && (
          <p className="mt-tight text-caption text-(--color-warn)">{error}</p>
        )}
      </div>
    );
  }

  if (state === "loading" || preview === null) {
    return (
      <div className="my-tight flex items-center gap-tight text-caption text-(--color-ink-muted)">
        <Spinner size="sm" />
        <span>Contacting the site…</span>
      </div>
    );
  }

  return (
    <div className="my-tight max-w-full overflow-hidden rounded-control border border-(--color-border-subtle) bg-(--color-surface-sunken) text-left">
      <div className="flex flex-col gap-tight p-gutter">
        {/* The host first and always, in its own line. The title is written by the site and the
            host is not — so what the reader checks comes before what the site chose to say. */}
        <span className="text-caption text-(--color-ink-muted)">{preview.host}</span>

        {preview.title !== null && (
          <span className="text-body font-medium text-(--color-ink)">{preview.title}</span>
        )}
        {preview.description !== null && (
          <span className="text-caption text-(--color-ink-muted)">{preview.description}</span>
        )}

        {preview.image !== null && <CardImage url={preview.image} />}
      </div>
    </div>
  );
}

/**
 * A picture from the site, decoded and re-emitted before it is shown.
 *
 * A second press rather than part of the first: a site that answers with metadata and then stalls
 * on an image leaves a card that works rather than nothing, and somebody who wants the text is
 * not made to fetch a megabyte for it.
 */
function CardImage({ url }: { url: string }) {
  const [asked, setAsked] = useState(false);
  const [image, setImage] = useState<Preview | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!asked) return;

    let live = true;
    let minted: Preview | null = null;

    void fetchPreviewImage(url)
      .then((blob) => decodePreview(blob))
      .then((decoded) => {
        if (!live) return;
        if (!decoded.ok) {
          setFailed(true);
          return;
        }
        minted = decoded.preview;
        setImage(decoded.preview);
      })
      .catch(() => {
        if (live) setFailed(true);
      });

    // The re-encoding is a `blob:` URL held by this component and nobody else, so it is revoked
    // here — the same discipline every viewer in `components/attachment` keeps.
    return () => {
      live = false;
      if (minted !== null) URL.revokeObjectURL(minted.url);
    };
  }, [asked, url]);

  if (failed) {
    return (
      <span className="text-caption text-(--color-ink-muted)">
        This site&rsquo;s picture could not be shown.
      </span>
    );
  }

  if (image !== null) {
    return (
      <img
        src={image.url}
        // Empty, and that is the accurate answer rather than a shrug.
        //
        // There is no description to give: nothing on this side has looked at the picture, and
        // the site's own words for it are the title and description already in this card, above.
        // An `alt` naming the host would repeat the line above it, and one describing the content
        // would be a claim this component has no basis for. A decorative image whose information
        // is already in the text takes an empty `alt` — that is what it is for.
        alt=""
        width={image.width}
        height={image.height}
        className="h-auto w-full rounded-control"
      />
    );
  }

  return (
    <Button size="sm" variant="quiet" busy={asked} onClick={() => setAsked(true)}>
      Load this site&rsquo;s picture
    </Button>
  );
}
