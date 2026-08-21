import assert from "node:assert/strict";
import { test } from "node:test";

import { MAX_BYTES, MAX_CODE_POINTS, sanitize, validate } from "./display-name.ts";

/** The character that reverses everything rendered after it, and the reason this module exists. */
const RIGHT_TO_LEFT_OVERRIDE = "\u202E";

/** The rest of the family. An isolate left behind reorders exactly as an override does. */
const BIDI_CONTROLS = ["\u200E", "\u200F", "\u202A", "\u202D", "\u2066", "\u2069", "\uFEFF"];

test("a right to left override is removed from a display name", () => {
  const cleaned = sanitize(`Charlie${RIGHT_TO_LEFT_OVERRIDE}`);

  assert.equal(cleaned, "Charlie");
  assert.ok(!cleaned.includes(RIGHT_TO_LEFT_OVERRIDE));
});

/**
 * The whole family, not only the one the previous test names: a stripper that handles the
 * override and leaves the isolates behind teaches false comfort about the ones it missed.
 */
test("every bidi control is removed, not only the override", () => {
  for (const control of BIDI_CONTROLS) {
    assert.equal(sanitize(`a${control}b`), "ab");
  }
});

/** A name is one line. A name that is two breaks out of the row it is drawn in. */
test("a newline cannot smuggle a second line into a display name", () => {
  assert.equal(sanitize("Charlie\nthe second"), "Charlie the second");
  assert.equal(sanitize("Charlie\u0000"), "Charlie");
});

test("a display name that is only whitespace is treated as absent", () => {
  assert.equal(sanitize("   \t  "), "");
  assert.equal(validate(sanitize("   \t  ")), "empty");
});

/** Padding a name with spaces is how the handle gets pushed off the end of a fixed width row. */
test("internal runs of whitespace collapse to a single space", () => {
  assert.equal(sanitize("  Charlie    the     third  "), "Charlie the third");
});

test("a display name is normalised so that two spellings of one name measure the same", () => {
  const combining = sanitize("Andre\u0301");
  const precomposed = sanitize("Andr\u00E9");

  assert.equal(combining, precomposed);
  assert.equal([...combining].length, 5);
});

/**
 * Truncating would change somebody's name without telling them, and the half kept would be the
 * half that fits rather than the half they meant.
 */
test("a display name longer than the cap is refused rather than truncated", () => {
  const long = "a".repeat(MAX_CODE_POINTS + 1);

  assert.equal(validate(long), "too-long");
  assert.equal(sanitize(long), long);
});

test("a display name of exactly the cap is accepted", () => {
  assert.equal(validate("a".repeat(MAX_CODE_POINTS)), null);
});

/**
 * The two ceilings bound different things, and this is the case that proves neither implies the
 * other: seventeen emoji sit inside the code point budget and well past the wire format's.
 */
test("the byte ceiling is reached before the code point ceiling with emoji", () => {
  const emoji = "\u{1F642}".repeat(17);

  assert.ok([...emoji].length <= MAX_CODE_POINTS);
  assert.ok(new TextEncoder().encode(emoji).length > MAX_BYTES);
  assert.equal(validate(emoji), "too-long");
});

test("an empty display name is refused rather than stored", () => {
  assert.equal(validate(""), "empty");
});

/** Sanitising twice must change nothing, or the wire copy and the local one would drift apart. */
test("sanitising an already sanitised display name is a no-op", () => {
  const once = sanitize("  Charlie\u200E   Brown  ");

  assert.equal(sanitize(once), once);
});
