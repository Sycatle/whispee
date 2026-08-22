import assert from "node:assert/strict";
import { test } from "node:test";

import { looksMissing, previewAvailable } from "./link-preview.ts";

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
