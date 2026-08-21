import assert from "node:assert/strict";
import { test } from "node:test";

import { formatShortcut, matches, parseCombo, type Chord } from "./shortcuts.ts";

/** A key press with nothing held. Each test turns on only what it is about. */
const press = (key: string, held: Partial<Chord> = {}): Chord => ({
  key,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  ...held,
});

test("a combo is a set of modifiers and exactly one key", () => {
  assert.deepEqual(parseCombo("mod+k"), {
    mod: true,
    ctrl: false,
    alt: false,
    shift: false,
    key: "k",
  });
  assert.deepEqual(parseCombo("MOD+Shift+ALT+I"), {
    mod: true,
    ctrl: false,
    alt: true,
    shift: true,
    key: "i",
  });
});

/** The three shortcuts the shell wires. `,` is the one a naive tokeniser mangles. */
test("the shell's own combos parse", () => {
  assert.equal(parseCombo("mod+k").key, "k");
  assert.equal(parseCombo("mod+,").key, ",");
  assert.equal(parseCombo("mod+i").key, "i");
});

test("cmd, command and meta are spellings of mod, not a fourth modifier", () => {
  for (const spelling of ["cmd+k", "command+k", "meta+k"]) {
    assert.deepEqual(parseCombo(spelling), parseCombo("mod+k"), spelling);
  }
});

/** `mod` is Ctrl on Linux, but a combo that says `ctrl` says it on every platform. */
test("a literal ctrl is not mod", () => {
  assert.deepEqual(parseCombo("ctrl+k"), {
    mod: false,
    ctrl: true,
    alt: false,
    shift: false,
    key: "k",
  });
});

test("a key written as a word becomes the value the event reports", () => {
  assert.equal(parseCombo("mod+space").key, " ");
  assert.equal(parseCombo("esc").key, "escape");
  assert.equal(parseCombo("mod+return").key, "enter");
});

test("whitespace around a token is not part of it", () => {
  assert.deepEqual(parseCombo(" mod + k "), parseCombo("mod+k"));
});

/**
 * Combos are literals written by a programmer. A malformed one has to fail loudly, because the
 * alternative is a shortcut that is bound and never fires — invisible until someone reports it.
 */
test("a combo with no key, or with two, is a programming error", () => {
  assert.throws(() => parseCombo("mod+shift"), /names no key/);
  assert.throws(() => parseCombo(""), /names no key/);
  assert.throws(() => parseCombo("mod+k+j"), /names more than one key/);
});

test("mod is drawn as ⌘ on Apple and spelled Ctrl elsewhere", () => {
  assert.equal(formatShortcut("mod+k", true), "⌘K");
  assert.equal(formatShortcut("mod+k", false), "Ctrl+K");
});

/** Apple's own menus order the glyphs ⌃⌥⇧⌘, with no separator. Disagreeing reads as a bug. */
test("Apple stacks glyphs in the system's order", () => {
  assert.equal(formatShortcut("mod+shift+alt+ctrl+i", true), "⌃⌥⇧⌘I");
  assert.equal(formatShortcut("mod+shift+alt+ctrl+i", false), "Ctrl+Alt+Shift+I");
});

/** On a PC keyboard `mod` *is* Ctrl, so a combo asking for both must not say Ctrl twice. */
test("mod and a literal ctrl collapse to one Ctrl off Apple", () => {
  assert.equal(formatShortcut("mod+ctrl+k", false), "Ctrl+K");
  assert.equal(formatShortcut("mod+ctrl+k", true), "⌃⌘K");
});

test("punctuation is shown as typed, and named keys as their glyph", () => {
  assert.equal(formatShortcut("mod+,", true), "⌘,");
  assert.equal(formatShortcut("mod+,", false), "Ctrl+,");
  assert.equal(formatShortcut("mod+enter", true), "⌘↵");
  assert.equal(formatShortcut("mod+space", false), "Ctrl+Space");
  assert.equal(formatShortcut("escape", false), "Esc");
});

test("mod matches the command key on Apple and the control key elsewhere", () => {
  const combo = parseCombo("mod+k");

  assert.ok(matches(combo, press("k", { metaKey: true }), true));
  assert.equal(matches(combo, press("k", { ctrlKey: true }), true), false);

  assert.ok(matches(combo, press("k", { ctrlKey: true }), false));
  assert.equal(matches(combo, press("k", { metaKey: true }), false), false);
});

/**
 * The case that makes the comparison exhaustive rather than a subset check: without it, `mod+k`
 * would also fire on ⌘⇧K and ⌘⌥K, taking chords that belong to the browser or to a shortcut we
 * have not written yet.
 */
test("an unrequested modifier is a mismatch", () => {
  const combo = parseCombo("mod+k");

  assert.equal(matches(combo, press("k", { metaKey: true, shiftKey: true }), true), false);
  assert.equal(matches(combo, press("k", { metaKey: true, altKey: true }), true), false);
  assert.equal(matches(combo, press("k", { ctrlKey: true, metaKey: true }), false), false);
});

/** Holding shift reports the upper-case letter; the combo is written lower-case either way. */
test("the key comparison ignores the case the event reports", () => {
  assert.ok(matches(parseCombo("mod+shift+k"), press("K", { metaKey: true, shiftKey: true }), true));
});

test("a bare key matches only with nothing held", () => {
  const combo = parseCombo("escape");

  assert.ok(matches(combo, press("Escape"), true));
  assert.equal(matches(combo, press("Escape", { shiftKey: true }), true), false);
});
