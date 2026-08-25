import assert from "node:assert/strict";
import { test } from "node:test";

import { contactable, looksMissing, previewAvailable } from "./link-preview.ts";

/**
 * What is not covered here, and cannot be: whether a site is safe to contact. That decision is
 * `apps/desktop/src/link.rs` and is tested there, in the process that opens the connection —
 * testing it again from this side would only pin the shape of an argument, not the defence.
 *
 * What these pin is the part this file can get wrong on its own: deciding that a desktop binary
 * lacks the commands, which disables the feature for the rest of the session.
 */

/**
 * The false positive is the expensive one.
 *
 * A rejection misread as absence turns one failed request into a feature that stays off until the
 * application restarts, over a site that happened to be down. A rejection missed in the other
 * direction costs one wasted call per link — which is why this is not "every rejection means
 * absent".
 */
test("only a missing command disarms, not a failed request", () => {
  assert.equal(looksMissing(new Error("Command link_preview not found")), true);
  assert.equal(looksMissing("command not found"), true);
  assert.equal(looksMissing("Command NOT FOUND"), true);

  for (const transient of [
    "This site did not answer.",
    "This site took too long to answer.",
    "This link points back at this machine or its local network.",
    "not found",
    "404 not found",
    "",
  ]) {
    assert.equal(looksMissing(transient), false, transient);
  }
});

/** Anything that is not a string or an `Error` must not be coerced into a match by accident. */
test("an unrecognisable rejection is not absence", () => {
  for (const odd of [null, undefined, 0, {}, [], { message: "command not found" }]) {
    assert.equal(looksMissing(odd), false);
  }
});

/**
 * On the web there is no native process, so the button must never be offered. This is the check
 * that keeps the dead native code in the shared bundle dead — see `lib/platform.ts` on why there
 * is one bundle rather than two.
 */
test("nothing is available outside the desktop application", () => {
  assert.equal("__TAURI_INTERNALS__" in globalThis, false);
  assert.equal(previewAvailable(), false);
});

/**
 * The gap this closes: `LinkText` refuses to make a deceptive URL clickable, and offering to
 * contact the same URL would hand back what was withheld. The crafted ones are precisely the ones
 * somebody wants fetched.
 */
test("a deceptive link is never offered for contact", () => {
  assert.equal(contactable("https://google.com@evil.tld/"), false);
  assert.equal(contactable("https://user:pw@evil.tld/"), false);
  assert.equal(contactable("https://xn--80ak6aa92e.com/"), false);
});

/** The native side refuses everything but `https`, so a button on the rest cannot work. */
test("only https is offered", () => {
  assert.equal(contactable("http://example.com/"), false);
  assert.equal(contactable("javascript:alert(1)"), false);
  assert.equal(contactable("data:text/html,x"), false);
  assert.equal(contactable("not a url"), false);
});

test("an ordinary link is offered", () => {
  assert.equal(contactable("https://example.com/"), true);
  assert.equal(contactable("https://en.wikipedia.org/wiki/A_(b)"), true);
  // `www.` is completed to https by `classify`, so it qualifies.
  assert.equal(contactable("www.example.com"), true);
});
