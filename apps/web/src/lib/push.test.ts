/**
 * What can be tested about Web Push without a browser.
 *
 * `node --test` has no `navigator`, no service worker and no `PushManager`, so the subscription
 * path itself is exercised by hand in a real browser — the procedure is in `docs/DEPLOY.md`, and
 * it is what separates this feature from a hope. What is here is the part that is pure and that
 * fails silently in production if it is wrong: the key decoding, the capability check, and the
 * two strings the service worker cannot import.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { test } from "node:test";

import { NOTICE_BODY_ONE, NOTICE_TITLE } from "./notifications.ts";
import { PROVIDER, decodeApplicationServerKey, pushSupported } from "./push.ts";

/**
 * The provider name is a wire value shared with the server.
 *
 * `push::WEB_PUSH` is the other half. They are two constants in two languages and nothing but this
 * assertion connects them: a rename on one side alone produces a subscription the emitter skips —
 * silently, because skipping an unknown provider is exactly what it is meant to do for a token
 * whose provider has not landed yet.
 */
test("the provider name matches the one the server files subscriptions under", () => {
  const source = readFileSync(new URL("../../../../crates/server/src/push.rs", import.meta.url), "utf8");

  assert.match(
    source,
    new RegExp(`pub const WEB_PUSH: &str = "${PROVIDER}";`),
    "the client and the server disagree on the provider name",
  );
});

/**
 * The worker's copy is duplicated rather than imported, and this is what keeps the copy honest.
 *
 * A service worker is its own module graph, served as a plain file so what is deployed is what can
 * be read. That costs two literals. Left unchecked they drift, and the drift is invisible: the
 * notification simply starts saying something the rest of the application does not.
 */
test("the service worker shows the same words the application does", () => {
  const worker = readFileSync(new URL("../../public/sw.js", import.meta.url), "utf8");

  assert.match(worker, new RegExp(`const TITLE = "${NOTICE_TITLE}";`));
  assert.match(worker, new RegExp(`const BODY = "${NOTICE_BODY_ONE}";`));
});

/**
 * The worker, run in a sandbox with the globals a service worker has and nothing else.
 *
 * It is a plain script, not a module — served verbatim so that what is deployed is what can be
 * read — which is exactly what makes this possible: its top-level function declarations become
 * properties of the sandbox, so `strategyFor` can be called and the listeners it registers can be
 * fired. That is worth more than matching its text with a regular expression, because what has to
 * hold is what it *decides*, not how it is spelled.
 */
function sandbox(overrides: Record<string, unknown> = {}) {
  const listeners: Record<string, (event: unknown) => void> = {};
  const self = {
    location: { origin: "https://whispee.example" },
    addEventListener: (name: string, handler: (event: unknown) => void) => {
      listeners[name] = handler;
    },
    registration: { showNotification: () => Promise.resolve() },
    clients: { claim: () => Promise.resolve(), matchAll: () => Promise.resolve([]) },
  };

  const context = createContext({ self, URL, Promise, Math, ...overrides });
  runInContext(readFileSync(new URL("../../public/sw.js", import.meta.url), "utf8"), context);

  return { context: context as Record<string, unknown>, listeners };
}

function asked(url: string, mode = "no-cors", method = "GET") {
  return { url, mode, method };
}

/**
 * **The property that answers the refusal this worker was written against.**
 *
 * `notifications.ts` refused a service worker because one would cache the application shell served
 * by the server the desktop build exists to stop trusting. The worker caches now, and what makes
 * that acceptable is this line: the entry point is fetched, never answered from the cache while
 * there is a network. A corrected deployment therefore takes effect on the next load.
 *
 * `/v1` is the other absence that has to hold: signed requests and sealed envelopes do not belong
 * in a store that outlives the tab.
 */
test("the entry point is never answered from the cache, and /v1 is never touched", () => {
  const { context } = sandbox();
  const strategyFor = context.strategyFor as (request: unknown) => string;

  assert.equal(strategyFor(asked("https://whispee.example/", "navigate")), "entry");
  assert.equal(strategyFor(asked("https://whispee.example/index.html")), "entry");
  assert.equal(strategyFor(asked("https://whispee.example/#/settings", "navigate")), "entry");

  assert.equal(strategyFor(asked("https://whispee.example/v1/messages")), "pass");
  assert.equal(strategyFor(asked("https://whispee.example/v1/gateway")), "pass");
});

/**
 * Cache-first is for bytes whose name asserts what they are, and for bytes that are not code.
 *
 * The two exclusions carry the argument: `crypto_wasm_bg.wasm` and `pdfjs/wasm/*` are executable
 * **and** keep their filename across releases, which is the pair of properties that would let a
 * cached copy outlive its correction.
 */
test("only content-addressed files and non-code are answered from the cache first", () => {
  const { context } = sandbox();
  const strategyFor = context.strategyFor as (request: unknown) => string;

  assert.equal(strategyFor(asked("https://whispee.example/assets/index-abc123.js")), "immutable");
  assert.equal(strategyFor(asked("https://whispee.example/emoji/base.json")), "immutable");
  assert.equal(strategyFor(asked("https://whispee.example/fonts/inter.woff2")), "immutable");

  assert.equal(strategyFor(asked("https://whispee.example/crypto_wasm_bg.wasm")), "fresh");
  assert.equal(strategyFor(asked("https://whispee.example/pdfjs/wasm/jbig2.wasm")), "fresh");
});

/** Nothing this worker does applies to a write, or to another origin. */
test("a write and another origin pass straight through", () => {
  const { context } = sandbox();
  const strategyFor = context.strategyFor as (request: unknown) => string;

  assert.equal(strategyFor(asked("https://whispee.example/assets/x.js", "no-cors", "POST")), "pass");
  assert.equal(strategyFor(asked("https://elsewhere.example/assets/x.js")), "pass");
});

/**
 * The decision above, carried out: with a network, the cached entry point is not what comes back.
 *
 * A stub `caches` that would answer and a `fetch` that does — if the order were the other way
 * round, the stale copy would win and the whole argument in the worker's header would be false.
 */
test("with a network, a cached entry point is not what is served", async () => {
  const served: string[] = [];
  const { context } = sandbox({
    fetch: () => {
      served.push("network");
      return Promise.resolve({ ok: true, status: 200, clone: () => ({}) });
    },
    caches: {
      open: () =>
        Promise.resolve({ put: () => Promise.resolve(), keys: () => Promise.resolve([]) }),
      match: () => {
        served.push("cache");
        return Promise.resolve({ ok: true, status: 200 });
      },
    },
  });

  await (context.fresh as (request: unknown) => Promise<unknown>)(asked("https://whispee.example/"));

  assert.deepEqual(served, ["network"], "the cache was consulted before the network");
});

/**
 * **The property must not rest on the deployment's headers.**
 *
 * `fetch` consults the browser's own HTTP cache first, so a reverse proxy that serves
 * `index.html` without `Cache-Control: no-cache` would hand back a stale entry point and the
 * argument in the worker's header would be false for that deployment. `deploy/Caddyfile` sets the
 * header; the worker asks for a revalidation anyway.
 */
test("the entry point is revalidated rather than read out of the HTTP cache", async () => {
  const asked_for: unknown[] = [];
  const { context } = sandbox({
    // A plain factory, not a class with parameter properties: `node --test` strips types, it does
    // not transform, and `constructor(readonly x)` is a transform. `lib/push.ts` is written the
    // way it is for the same reason.
    Request: function (input: unknown, init: { cache?: string }) {
      return { input, init };
    },
    fetch: (request: { init?: { cache?: string } }) => {
      asked_for.push(request.init?.cache ?? "default");
      return Promise.resolve({ ok: true, status: 200, clone: () => ({}) });
    },
    caches: {
      open: () =>
        Promise.resolve({ put: () => Promise.resolve(), keys: () => Promise.resolve([]) }),
      match: () => Promise.resolve(undefined),
    },
  });

  const fresh = context.fresh as (request: unknown, entry?: boolean) => Promise<unknown>;
  await fresh(asked("https://whispee.example/"), true);
  await fresh(asked("https://whispee.example/crypto_wasm_bg.wasm"));

  assert.deepEqual(asked_for, ["no-cache", "default"]);
});

/** And without one, it is — which is the whole reason any of this is here. */
test("with no network, the cached entry point is what is served", async () => {
  const { context } = sandbox({
    fetch: () => Promise.reject(new Error("offline")),
    caches: {
      open: () =>
        Promise.resolve({ put: () => Promise.resolve(), keys: () => Promise.resolve([]) }),
      match: () => Promise.resolve({ ok: true, status: 200, cached: true }),
    },
  });

  const response = await (
    context.fresh as (request: unknown) => Promise<{ cached?: boolean }>
  )(asked("https://whispee.example/"));

  assert.equal(response.cached, true);
});

test("a base64url key decodes to the sixty-five bytes of an uncompressed point", () => {
  // A real P-256 public key as the server advertises it: 0x04 then two 32-byte coordinates.
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  for (let index = 1; index < raw.length; index += 1) raw[index] = index;

  const base64url = Buffer.from(raw)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  assert.deepEqual([...decodeApplicationServerKey(base64url)], [...raw]);
});

/**
 * The padding is restored before decoding, and that is the whole reason this function exists
 * rather than a bare `atob`.
 *
 * base64url as this protocol writes it is unpadded, `atob` demands padding, and the failure is an
 * `InvalidCharacterError` raised inside the browser that names neither the value nor the caller.
 */
test("an unpadded key is decoded rather than refused", () => {
  // Three bytes encode to four characters with no padding; two bytes need one `=`, one needs two.
  assert.deepEqual([...decodeApplicationServerKey("AQID")], [1, 2, 3]);
  assert.deepEqual([...decodeApplicationServerKey("AQI")], [1, 2]);
  assert.deepEqual([...decodeApplicationServerKey("AQ")], [1]);
});

/** The two characters base64url replaces are the ones a raw key is most likely to contain. */
test("the url alphabet is translated back", () => {
  assert.deepEqual([...decodeApplicationServerKey("-_8")], [251, 255]);
});

/**
 * Under `node --test` there is no `navigator` and no `PushManager`, so the capability check must
 * answer no rather than throw.
 *
 * That is not a concession to the harness: it is the same answer a browser without push gives,
 * and the screen hides the control on it. A `ReferenceError` here would take the settings screen
 * down on exactly those browsers.
 */
test("push reports itself unsupported where the browser offers nothing", () => {
  assert.equal(pushSupported(), false);
});
