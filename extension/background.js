/**
 * The service worker: fetch the manifest, hash what the page loaded, colour the icon.
 *
 * # The verdict is here and never in the page
 *
 * That is the whole reason an extension exists rather than a banner. Everything a page displays is
 * under the control of the server that served it, so a "verified" badge drawn by the application
 * would be erased — or forged — by exactly the server it is supposed to catch. The toolbar icon is
 * outside that server's reach, and it is the only place this answer can be believed.
 *
 * # Where the manifest comes from, and why it matters more than how it is compared
 *
 * From GitHub's API, never from the site being inspected. A server that hands over both the code
 * and the list of hashes for that code has certified itself, which is the defect this whole
 * mechanism exists to remove — the same one `docs/THREAT-MODEL.md` records about the transparency
 * log being signed by the server it watches.
 *
 * # The compromise this cannot avoid, stated plainly
 *
 * The extension cannot read the bytes the page actually received. Chrome gives no API for it
 * outside the debugger protocol. So it **re-requests** each resource with `cache: "force-cache"`,
 * which normally returns the copy the page itself used.
 *
 * Normally. A server that answers differently to a second request defeats this, and nothing here
 * detects that. It is the same compromise Code Verify makes, it is real, and it is why the banner
 * in the application does not go away. What this raises is the cost of an attack from "serve
 * anything" to "serve one thing consistently and hope nobody compares" — worth having, and not the
 * same as impossible.
 */
import { parseManifest, verifyResources, verdict } from "./verify.js";

const REPOSITORY = "Sycatle/whispee";

/** The colours. Red is failure; grey is "not answered", which is not the same as pass. */
const BADGE = {
  ok: { text: "ok", colour: "#1a7f37" },
  failed: { text: "!", colour: "#cf222e" },
  unknown: { text: "?", colour: "#6e7781" },
};

async function latestManifest() {
  const release = await fetch(`https://api.github.com/repos/${REPOSITORY}/releases/latest`, {
    headers: { accept: "application/vnd.github+json" },
  });
  if (!release.ok) throw new Error(`no published release (${release.status})`);

  const body = await release.json();
  const asset = body.assets?.find((candidate) => candidate.name === "WEB-SHA256SUMS");
  if (!asset) throw new Error("the latest release publishes no manifest");

  const manifest = await fetch(asset.browser_download_url);
  if (!manifest.ok) throw new Error(`manifest unreachable (${manifest.status})`);

  return { tag: body.tag_name, entries: parseManifest(await manifest.text()) };
}

/**
 * What the page loaded, asked of the page itself.
 *
 * `performance.getEntriesByType("resource")` is the browser's own record of every request the
 * document made, which is better than parsing the HTML for `<script>` tags: it catches what was
 * imported dynamically too. `document.location.href` is added because the document is not a
 * resource entry and is the one file everything else is named from.
 */
async function loadedBy(tabId) {
  const [result] = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => [
      document.location.href.split(/[?#]/)[0],
      ...performance
        .getEntriesByType("resource")
        .filter((entry) => entry.initiatorType !== "beacon")
        .map((entry) => entry.name),
    ],
  });

  return [...new Set(result.result)];
}

async function check(tabId, origin) {
  const { tag, entries } = await latestManifest();

  const findings = await verifyResources({
    urls: await loadedBy(tabId),
    origin,
    manifest: entries,
    // See the note at the top on what this does and does not establish.
    fetchBytes: async (url) => {
      const response = await fetch(url, { cache: "force-cache" });
      if (!response.ok) throw new Error(`${response.status}`);
      return await response.arrayBuffer();
    },
    subtle: crypto.subtle,
  });

  return { tag, findings, answer: verdict(findings) };
}

async function paint(tabId, answer) {
  const badge = BADGE[answer] ?? BADGE.unknown;

  await chrome.action.setBadgeText({ tabId, text: badge.text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.colour });
}

chrome.runtime.onMessage.addListener((message, _sender, respond) => {
  if (message?.kind !== "check") return false;

  (async () => {
    try {
      const result = await check(message.tabId, message.origin);
      // Kept so the popup can show the detail without running the whole check again.
      await chrome.storage.session.set({ [`tab:${message.tabId}`]: result });
      await paint(message.tabId, result.answer);
      respond(result);
    } catch (error) {
      await paint(message.tabId, "unknown");
      respond({ answer: "unknown", error: String(error?.message ?? error) });
    }
  })();

  // Keeps the message channel open for the async reply above.
  return true;
});

// A navigation invalidates whatever the last answer was. Clearing rather than re-checking: a
// stale "ok" left on the icon after the page changed would be the worst thing this could display.
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") void paint(tabId, "unknown");
});
