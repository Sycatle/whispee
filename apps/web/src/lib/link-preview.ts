/**
 * Asking the native process what a link says about itself.
 *
 * # This module cannot make the request, and that is the point
 *
 * A `fetch` from this page fails on nearly every site for want of `Access-Control-Allow-Origin`,
 * and widening `connect-src` to `https:` to fix it would hand back the exfiltration channel the
 * CSP exists to close — in exchange for a feature that still would not work. So the request is
 * made by `apps/desktop/src/link.rs`, which has neither CORS nor a CSP, and which is also the
 * only place where the address connected to can be decided by us rather than by a resolver.
 *
 * Everything that decides *what may be contacted* lives there and is tested there. This file is a
 * caller: it knows whether the command exists, converts what comes back, and never retries.
 *
 * # The three rules, and where they are actually enforced
 *
 * A preview generated at the recipient leaks their IP by construction: whoever sends
 * `https://their-server/{uuid}` and watches the request arrive learns that the target opened the
 * conversation, when, and from where. So: never automatic, never remembered, never from a
 * notification or the rail.
 *
 * **Nothing here caches**, which is the second rule, and the absence is deliberate: a cache turns
 * one press into a record, and a memoised preview would silently re-arm on the next render. The
 * first and third are enforced by the interface rather than here — `RichText` takes the card as
 * an opt-in prop, so a call site that does not pass it *cannot* produce one. That is a stronger
 * guarantee than a comment asking people not to.
 *
 * # Why there is a disarm and not a capability query
 *
 * Tauri exposes no list of registered commands, so the only probe is the call itself. A desktop
 * binary older than these two commands rejects with "not found"; without remembering that, every
 * message with a link would pay another rejected round trip. Same shape as `lib/biometrics.ts`,
 * for the same reason.
 */

import { invoke } from "@tauri-apps/api/core";

import { fromBase64 } from "./keys.ts";
import { isTauri } from "./platform.ts";

/** What the native side sends back. Mirrors `LinkPreview` in `apps/desktop/src/link.rs`. */
export interface LinkPreview {
  /** The URL that finally answered, after redirects — not the one that was asked for. */
  url: string;
  /** Its host, to be shown beside the title. */
  host: string;
  title: string | null;
  description: string | null;
  /** A URL, never bytes: fetching it is a second, separate press. */
  image: string | null;
}

/**
 * Set once, when the native side says it does not know these commands.
 *
 * Module state rather than React state on purpose: the answer is a property of the binary the
 * page is running inside, not of any component, and it cannot change without a restart.
 */
let missing = false;

/**
 * Whether asking is worth attempting at all.
 *
 * False on the web, where there is no native process, and false on a desktop build that predates
 * these commands.
 */
export function previewAvailable(): boolean {
  return isTauri() && !missing;
}

/**
 * Whether a rejection means "this binary has no such command" rather than "the request failed".
 *
 * Tauri words this itself and the wording has moved between versions, so the test is on the two
 * parts that have not: the phrase names the command and says it was not found. A false negative
 * costs one wasted call per link; a false positive would disable the feature for the session over
 * a transient failure, which is why this does not simply treat every rejection as absence.
 */
export function looksMissing(reason: unknown): boolean {
  const text = String(
    reason instanceof Error ? reason.message : typeof reason === "string" ? reason : "",
  ).toLowerCase();

  return text.includes("not found") && text.includes("command");
}

/**
 * What a site says about one of its own pages.
 *
 * Rejects with the sentence the native side produced. Those sentences name what was refused and
 * never quote the URL back — a hostile title echoed into the thread is how a crafted string
 * becomes a sentence somebody trusts.
 */
export async function fetchPreview(url: string): Promise<LinkPreview> {
  if (!previewAvailable()) {
    throw new Error("Previews are only available in the desktop application.");
  }

  try {
    return await invoke<LinkPreview>("link_preview", { url });
  } catch (reason) {
    if (looksMissing(reason)) {
      missing = true;
      throw new Error("This version of the desktop application cannot contact sites.", {
        cause: reason,
      });
    }
    // Tauri rejects with a string, which is the sentence `link.rs` produced: it is shown as
    // written. Anything else is a failure of the bridge rather than of the site, and gets a
    // sentence of ours — with the original attached, because a message a reader can act on and a
    // reason a developer can debug are not the same string.
    throw new Error(typeof reason === "string" ? reason : "This site could not be contacted.", {
      cause: reason,
    });
  }
}

/**
 * The bytes of a preview image, as a `Blob`.
 *
 * **The caller must not render these bytes.** A server nobody vetted chose them, which is exactly
 * the situation of an attachment — so they go through `decodePreview` in `lib/preview.ts`, which
 * decodes them and re-emits a PNG of ours. `LinkCard` does that and holds the only call site.
 *
 * The MIME type is deliberately empty rather than guessed: nothing here has looked at the bytes,
 * and a `Blob` labelled `image/png` that is not one is a claim this module has no basis for.
 */
export async function fetchPreviewImage(url: string): Promise<Blob> {
  if (!previewAvailable()) {
    throw new Error("Previews are only available in the desktop application.");
  }

  const encoded = await invoke<string>("link_image", { url });
  return new Blob([fromBase64(encoded)]);
}
