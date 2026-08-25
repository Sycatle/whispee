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
 * **The property that matters about the worker**, and it is an absence.
 *
 * `notifications.ts` refused a service worker because one would cache the application shell served
 * by the server the desktop build exists to stop trusting. This worker is allowed to exist because
 * it caches nothing. That is not a promise in a comment: a `fetch` handler or a `caches` call is
 * what would turn it into the thing that was refused, so their absence is asserted.
 */
test("the service worker intercepts nothing and caches nothing", () => {
  const worker = readFileSync(new URL("../../public/sw.js", import.meta.url), "utf8");
  const code = worker.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

  assert.doesNotMatch(code, /addEventListener\(\s*["']fetch["']/, "it would serve a stale bundle");
  assert.doesNotMatch(code, /caches\b/, "it would keep a copy of the application");
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
