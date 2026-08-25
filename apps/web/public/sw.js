/**
 * The service worker: a wake-up point for Web Push, and a cache with a boundary.
 *
 * # Why this file was allowed to exist, and what changed since
 *
 * `src/lib/notifications.ts` refused a service worker in as many words: "one would be a cache of
 * the application shell served by the same server the desktop build exists to stop trusting". A
 * worker that caches the shell keeps a copy of the application alive across visits, so a server
 * that served a hostile bundle once keeps its victim even after it is fixed. That is a real and
 * serious thing to refuse, and it was refused correctly.
 *
 * This file then existed for a while caching **nothing** — no `fetch` handler, no `Cache` — because
 * the Push API has no other delivery point: a push message wakes the *worker*, not the page.
 *
 * It caches now, and the refusal above is answered rather than forgotten:
 *
 *  1. **`index.html` is never served from the cache while there is a network.** It is the entry
 *     point and the thing that names every other file, so it is fetched first, every time, and the
 *     cached copy is a fallback for being offline. A corrected deployment therefore takes effect on
 *     the next load, exactly as it did before this file cached anything.
 *
 *  2. **What is cached first is addressed by its content.** Vite fingerprints everything under
 *     `/assets/`, and it is `index.html` that names which fingerprints to load. A hostile asset
 *     kept in this cache is never asked for again once a corrected `index.html` names different
 *     files. The cache-first rule prolongs nothing; it only avoids re-downloading bytes whose name
 *     already asserts what they are.
 *
 *  3. **There is now a check that did not exist then.** `scripts/release-web.sh` publishes a
 *     manifest of hashes and `.github/workflows/release.yml` attests it, so what a deployment
 *     serves can be compared against what a commit produced — this file included, since it is
 *     served from `public/` like everything else. `scripts/verify-web.sh` is the other end.
 *
 * # What it still costs, stated rather than buried
 *
 * **Offline, the application starts from the last `index.html` this browser received** — which
 * could be one served during an attack. It is bounded: the moment there is a network, it is
 * replaced. And it is not a new exposure, because that `index.html` had already been executed when
 * it arrived. What the cache adds is that it can be executed once more, with no network, before
 * the correction can reach it.
 *
 * **Executable bytes that are not content-addressed are not cached first.**
 * `crypto_wasm_bg.wasm` and `pdfjs/wasm/*` keep the same filename across releases, so a cached
 * copy would be asked for again by name after a fix. They are fetched from the network and only
 * fall back to the cache, like `index.html` and for the same reason.
 *
 * # Why the notification text is a constant
 *
 * The worker cannot decrypt. The MLS keys live in a WASM module inside the page, in memory the
 * worker has no access to, and moving them here would mean handing the decryption keys to a
 * context that outlives every tab. So the notification says that something arrived, and nothing
 * about what: the same answer iOS forces on every messenger, arrived at here on purpose rather
 * than by constraint.
 *
 * That is also the third of the three limits in `migrations/0011_push.sql`: the wake-up carries no
 * text, no sender and no group id. There is nothing here to display even if this file wanted to.
 */

// Kept in step with `NOTICE_TITLE` and `NOTICE_BODY_ONE` in `src/lib/notifications.ts`. Duplicated
// rather than imported: a service worker is its own module graph, served as a plain file so that
// what is deployed is what can be read, and a build step to share two strings would cost more
// clarity than it saves. `push.test.ts` pins them against their source.
const TITLE = "Whispee";
const BODY = "New message";

/**
 * The cache's name, and the only thing that empties it wholesale.
 *
 * Bumped by hand. This file is served verbatim from `public/` and is not processed by Vite, so
 * nothing can inject a build hash into it, and a hand-bumped constant is the only form that stays
 * byte-identical for everybody who builds this commit — which the published manifest requires.
 *
 * Forgetting to bump it is survivable, which is the point of `CACHE_LIMIT` below: deployments
 * accumulate their fingerprinted assets in one generation, and the limit is what keeps that
 * bounded without depending on anybody's memory.
 */
const GENERATION = "whispee-1";

/**
 * How many entries one generation may hold.
 *
 * A full load asks for roughly thirty files, so this is about a dozen deployments' worth of
 * fingerprinted assets. The oldest goes when a new one arrives — `caches` keeps insertion order,
 * so "oldest" is the first key and needs no bookkeeping of its own.
 */
const CACHE_LIMIT = 400;

/**
 * What to do with a request, and nothing else. Pure, so it can be tested for what it decides
 * rather than for what it downloads — see `push.test.ts`, which runs this file in a sandbox.
 *
 *  - `"immutable"` — answer from the cache if it is there, otherwise fetch and keep it. Only for
 *    paths whose bytes cannot change under the same name, or whose contents are not code.
 *  - `"entry"` — like `"fresh"`, and additionally revalidated against the server rather than
 *    answered out of the browser's own HTTP cache. See `fresh`.
 *  - `"fresh"` — fetch, keep a copy, and fall back to that copy only when the network fails.
 *  - `"pass"` — do not touch it. The request goes out as if this file did not exist.
 */
function strategyFor(request) {
  // A POST is not a thing to replay from a cache, and every write in this application is one.
  if (request.method !== "GET") return "pass";

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return "pass";

  // The delivery service. Signed requests and sealed envelopes: nothing here belongs in a store
  // that outlives the tab, and a stale answer would be worse than no answer.
  if (url.pathname === "/v1" || url.pathname.startsWith("/v1/")) return "pass";

  // The entry point, in both spellings and in its navigation form. Never cache-first: see the
  // header.
  if (request.mode === "navigate") return "entry";
  if (url.pathname === "/" || url.pathname === "/index.html") return "entry";

  // Fingerprinted by Vite. The name is derived from the bytes, so the bytes cannot change under
  // it — and `index.html`, which is always fetched, is what says which names to ask for.
  if (url.pathname.startsWith("/assets/")) return "immutable";

  // Not fingerprinted, and cached first anyway because neither is code: the emoji files are JSON
  // handed to `JSON.parse`, and the fonts are glyph tables handed to a shaper. A stale one draws
  // the wrong picture; it does not run. Together they are nine megabytes that were fetched again
  // on every single visit.
  if (url.pathname.startsWith("/emoji/") && url.pathname.endsWith(".json")) return "immutable";
  if (url.pathname.startsWith("/fonts/")) return "immutable";

  // Everything else, `crypto_wasm_bg.wasm` and `pdfjs/` included. Both are executable and both
  // keep their filename across releases, which is exactly the pair of properties that would let a
  // cached copy outlive its correction.
  return "fresh";
}

/** Adds to the cache and drops the oldest entries once there are too many. */
async function keep(request, response) {
  const cache = await caches.open(GENERATION);
  await cache.put(request, response);

  const keys = await cache.keys();
  // `keys()` answers in insertion order, so the front of the list is the oldest.
  for (const stale of keys.slice(0, Math.max(0, keys.length - CACHE_LIMIT))) {
    await cache.delete(stale);
  }
}

async function immutable(request) {
  const hit = await caches.match(request, { cacheName: GENERATION });
  if (hit) return hit;

  const response = await fetch(request);
  // Only a complete, successful answer. Caching a 404 or a range response would serve it back
  // for as long as the generation lives.
  if (response.ok && response.status === 200) await keep(request, response.clone());

  return response;
}

async function fresh(request, entry = false) {
  try {
    // **The entry point is revalidated, and that is not the same as fetching it.**
    //
    // `fetch` consults the browser's own HTTP cache first, so a deployment that serves
    // `index.html` without `Cache-Control: no-cache` gets a stale entry point out of it — and the
    // whole argument in this file's header, that a correction takes effect on the next load, would
    // then rest on somebody's reverse-proxy configuration. `deploy/Caddyfile` sets that header and
    // says why; this line is what makes the property hold for a deployment that does not.
    //
    // `no-cache` and not `no-store`: a conditional request still answers 304 from the cache, so
    // the cost is a round trip, not the file.
    //
    // Constructing a `Request` from a navigation one downgrades its mode to `same-origin`, which
    // the specification does deliberately and which costs nothing here — what is wanted is the
    // bytes, and `respondWith` accepts any response for a navigation.
    const response = await fetch(entry ? new Request(request, { cache: "no-cache" }) : request);
    if (response.ok && response.status === 200) await keep(request, response.clone());

    return response;
  } catch (offline) {
    const hit = await caches.match(request, { cacheName: GENERATION });
    if (hit) return hit;

    // A navigation with nothing cached for this exact URL still has somewhere to go: this is a
    // single-page application, so every route is `index.html`. Without this, a reload of
    // `/#/settings` offline would fail where the same visit to `/` would not.
    if (request.mode === "navigate") {
      const shell = await caches.match("/index.html", { cacheName: GENERATION });
      if (shell) return shell;
    }

    throw offline;
  }
}

self.addEventListener("install", () => {
  // **No `skipWaiting`, and no precache.**
  //
  // A worker that takes over a page already loaded can answer that page's later requests — a lazy
  // chunk, a font — out of a generation it did not start with. The default lifecycle, where the
  // new worker waits for every tab to go, is the one that keeps a session on one version of the
  // application.
  //
  // Nothing is fetched here either: a precache list is a second manifest of filenames to keep in
  // step with the build, and everything worth caching is asked for by the page a moment later
  // anyway.
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      // Older generations, and any cache some earlier version of this file opened.
      const names = await caches.keys();
      await Promise.all(names.filter((name) => name !== GENERATION).map((name) => caches.delete(name)));

      // Claim the pages that loaded before this worker existed — the first visit, where the page
      // was fetched from the network and nothing was controlling it. Without this, the first
      // visit populates no cache at all and the offline start only works from the second.
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const strategy = strategyFor(event.request);
  // Not calling `respondWith` at all is what "pass" means: the request goes to the network as if
  // no worker were installed. Calling it with `fetch(event.request)` would look the same and is
  // not — it would route the request through this worker's lifetime and stall it on termination.
  if (strategy === "pass") return;

  if (strategy === "immutable") return event.respondWith(immutable(event.request));

  event.respondWith(fresh(event.request, strategy === "entry"));
});

self.addEventListener("push", (event) => {
  // `waitUntil` or the worker may be killed before the notification is shown. Browsers also
  // require that a push handler show *something*: staying silent gets the subscription revoked
  // after a few offences, and on some browsers displays a "this site was updated in the
  // background" notice instead — worse than ours, and not ours to write.
  event.waitUntil(
    self.registration.showNotification(TITLE, {
      body: BODY,
      // The collapse key. Ten messages while the phone is in a pocket are one notification, not
      // ten — the page does the same with `tag: conversation`, except this side does not know
      // which conversation, so everything collapses into one.
      tag: "whispee-wake",
      // No `renotify`: the point of collapsing is not to buzz again for each one.
      silent: false,
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  // Focus a tab that is already open before opening another. Somebody who clicks a notification
  // wants the conversation they were already in, not a second copy of the application signing in
  // from scratch.
  event.waitUntil(
    (async () => {
      const clients = await self.clients.matchAll({
        type: "window",
        includeUncontrolled: true,
      });

      for (const client of clients) {
        if ("focus" in client) return client.focus();
      }

      // No deep link, and it is not an oversight: the wake-up does not say which conversation,
      // so the honest destination is the application's front door.
      return self.clients.openWindow("/");
    })(),
  );
});
