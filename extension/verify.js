/**
 * The comparison itself, with nothing browser-specific in it.
 *
 * # Why this is a separate file
 *
 * So it can be tested. The rest of the extension is service-worker plumbing that only runs inside
 * Chrome, and an extension whose only proof is "it looked right when I clicked it" is exactly the
 * kind of verification this project spends its time refusing elsewhere. Everything here takes its
 * inputs as arguments — no `chrome`, no `fetch` at module scope — so `verify.test.js` can drive it
 * under `node --test`.
 *
 * # What it is comparing
 *
 * A manifest published by GitHub Actions, in `sha256sum` format, against the bytes a browser was
 * served. Whichever way those bytes are obtained, this file does not care: it takes a function.
 */

/**
 * Parses a `sha256sum` manifest into a map of path to expected digest.
 *
 * The format is two spaces between digest and path, which is `sha256sum`'s own output and what
 * `scripts/release-web.sh` emits. Lines that do not look like that are ignored rather than
 * refused: a future manifest may carry a header, and refusing a whole verification over a line
 * nobody reads would be the wrong failure.
 */
export function parseManifest(text) {
  const entries = new Map();

  for (const line of text.split("\n")) {
    const match = /^([0-9a-f]{64})\s\s(.+)$/.exec(line.trim());
    if (match) entries.set(match[2], match[1]);
  }

  return entries;
}

/** Hex of the SHA-256 of some bytes, the same digest `sha256sum` prints. */
export async function digest(bytes, subtle) {
  const hash = await subtle.digest("SHA-256", bytes);

  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Turns a resource URL into the path a manifest would list it under.
 *
 * `null` when the resource does not belong to this origin — a font from a CDN, an analytics
 * script, anything the deployment did not build. Those are **not** ignorable: a page is not
 * verified if part of what it runs came from somewhere the manifest never described, so the
 * caller reports them rather than skipping them. See `UNLISTED` below.
 */
export function pathOf(url, origin) {
  if (!url.startsWith(`${origin}/`)) return null;

  const path = url.slice(origin.length + 1);

  // The query string is not part of what was hashed, and a cache-buster would otherwise make
  // every resource unverifiable.
  return path.split(/[?#]/)[0];
}

export const MATCHED = "matched";
export const ALTERED = "altered";
/** Served from this origin, at a path the manifest does not describe. */
export const UNLISTED = "unlisted";
/** Loaded from somewhere else entirely. */
export const FOREIGN = "foreign";

/**
 * Compares what a page loaded against what a manifest says it should be.
 *
 * `fetchBytes` is injected: in the extension it re-requests through the browser cache, in the test
 * it hands back whatever the test decided. That indirection is not neutral and the caller must
 * understand it — see `background.js` on why re-fetching is a compromise rather than a solution.
 *
 * **Fails closed.** Anything that is not a confirmed match counts against the verdict: a resource
 * that could not be fetched, one at an unlisted path, one from another origin. A verifier that
 * answers "fine" when it does not know is worse than no verifier, because somebody relies on it.
 */
export async function verifyResources({ urls, origin, manifest, fetchBytes, subtle }) {
  const findings = [];

  for (const url of urls) {
    const path = pathOf(url, origin);

    if (path === null) {
      findings.push({ url, state: FOREIGN });
      continue;
    }

    const expected = manifest.get(path);
    if (expected === undefined) {
      findings.push({ url, path, state: UNLISTED });
      continue;
    }

    let actual;
    try {
      actual = await digest(await fetchBytes(url), subtle);
    } catch {
      // Unreachable is not innocent here: the page ran this resource, so something served it.
      findings.push({ url, path, state: ALTERED });
      continue;
    }

    findings.push({ url, path, state: actual === expected ? MATCHED : ALTERED, actual, expected });
  }

  return findings;
}

/**
 * The one-word answer, and it is only `ok` when every single resource matched.
 *
 * There is no partial pass. A page whose main bundle matches and whose one injected script does
 * not is not "mostly verified" — it is a page running code nobody published.
 */
export function verdict(findings) {
  if (findings.length === 0) return "unknown";

  return findings.every((finding) => finding.state === MATCHED) ? "ok" : "failed";
}
