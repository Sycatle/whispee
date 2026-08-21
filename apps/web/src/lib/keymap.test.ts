import assert from "node:assert/strict";
import { test } from "node:test";

import { KEYMAP, bindingOf, grouped } from "./keymap.ts";
import { matches, parseCombo } from "./shortcuts.ts";

test("every combo in the keymap parses", () => {
  // `parseCombo` throws on a malformed combo, and a shortcut nobody has typed lately would
  // otherwise throw on the render that first mounts it.
  for (const binding of KEYMAP) assert.doesNotThrow(() => parseCombo(binding.combo));
});

test("no two bindings claim the same chord", () => {
  // The mechanism does not arbitrate: two handlers on one chord both run, in mount order, and
  // nothing says so. This is the check that keeps that from being possible by accident.
  const combos = KEYMAP.map((binding) => binding.combo);
  assert.equal(new Set(combos).size, combos.length);
});

test("no two bindings share an id", () => {
  const ids = KEYMAP.map((binding) => binding.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every binding is described", () => {
  // The label is what the help screen shows. An empty one produces a row with a chord and no
  // explanation, which is worse than not listing it.
  for (const binding of KEYMAP) assert.ok(binding.label.length > 0, binding.id);
});

test("bindingOf finds every id in the map, and refuses one that is not", () => {
  for (const binding of KEYMAP) assert.equal(bindingOf(binding.id).combo, binding.combo);
  // @ts-expect-error — the union forbids this at compile time; the throw is the runtime backstop
  // for the case where the union and the map have drifted apart.
  assert.throws(() => bindingOf("nothing.here"));
});

test("every combo actually fires on the key press it describes", () => {
  // The end-to-end claim of the whole registry: what is listed is what answers. `?` is the one
  // that failed before the matcher stopped comparing shift on punctuation, and it failed
  // silently — listed, formatted, and dead.
  for (const binding of KEYMAP) {
    const combo = parseCombo(binding.combo);
    const chord = {
      key: combo.key,
      metaKey: false,
      ctrlKey: combo.mod || combo.ctrl,
      altKey: combo.alt,
      // As a keyboard reports it: punctuation typically arrives shifted.
      shiftKey: /[a-z0-9]/.test(combo.key) ? combo.shift : true,
    };

    assert.ok(matches(combo, chord, false), `${binding.id} (${binding.combo}) never fires`);
  }
});

test("grouping lists only the bindings asked for, and drops empty headings", () => {
  const only = grouped(["help.shortcuts"]);

  assert.deepEqual(
    only.map(([group]) => group),
    ["Help"],
  );
  assert.deepEqual(
    only[0][1].map((binding) => binding.id),
    ["help.shortcuts"],
  );
  assert.deepEqual(grouped([]), []);
});
