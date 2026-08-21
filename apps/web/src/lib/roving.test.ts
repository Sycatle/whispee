import assert from "node:assert/strict";
import { test } from "node:test";

import { move } from "./roving.ts";

const ROWS = ["a", "b", "c"];

test("the arrows step along the ring", () => {
  assert.equal(move(ROWS, "a", "ArrowDown"), "b");
  assert.equal(move(ROWS, "b", "ArrowUp"), "a");
});

test("without a wrap, the ends of the ring report no move", () => {
  assert.equal(move(ROWS, "c", "ArrowDown"), null);
  assert.equal(move(ROWS, "a", "ArrowUp"), null);
});

test("with a wrap, the ends meet", () => {
  assert.equal(move(ROWS, "c", "ArrowDown", { wrap: true }), "a");
  assert.equal(move(ROWS, "a", "ArrowUp", { wrap: true }), "c");
});

test("a ring of one reports no move even when it wraps", () => {
  // Arithmetically the next item is itself. Reporting it would have the caller swallow a
  // keystroke that moved nothing.
  assert.equal(move(["only"], "only", "ArrowDown", { wrap: true }), null);
  assert.equal(move(["only"], "only", "ArrowUp", { wrap: true }), null);
});

test("with no position yet, the ring is entered from the end the key came from", () => {
  assert.equal(move(ROWS, null, "ArrowDown"), "a");
  assert.equal(move(ROWS, null, "ArrowUp"), "c");
});

test("an anchor the list no longer holds is treated as no position", () => {
  // The filter in the rail rewrites the list on every keystroke, so the anchor routinely names a
  // row that has just been excluded. Down should reach the first of what is left rather than
  // report nothing and feel broken.
  assert.equal(move(ROWS, "gone", "ArrowDown"), "a");
  assert.equal(move(ROWS, "gone", "ArrowUp"), "c");
});

test("Home and End reach the ends from anywhere, and report nothing once there", () => {
  assert.equal(move(ROWS, "b", "Home"), "a");
  assert.equal(move(ROWS, "b", "End"), "c");
  assert.equal(move(ROWS, "a", "Home"), null);
  assert.equal(move(ROWS, "c", "End"), null);
});

test("Home and End work from no position at all", () => {
  assert.equal(move(ROWS, null, "Home"), "a");
  assert.equal(move(ROWS, null, "End"), "c");
});

test("a horizontal ring answers Left and Right, and leaves Up and Down alone", () => {
  const ring = { orientation: "horizontal" } as const;
  assert.equal(move(ROWS, "a", "ArrowRight", ring), "b");
  assert.equal(move(ROWS, "b", "ArrowLeft", ring), "a");
  // What makes a horizontal ring nestable inside a vertical one: the other pair falls through to
  // whatever contains it.
  assert.equal(move(ROWS, "a", "ArrowDown", ring), null);
  assert.equal(move(ROWS, "b", "ArrowUp", ring), null);
});

test("a vertical ring leaves Left and Right alone", () => {
  assert.equal(move(ROWS, "a", "ArrowRight"), null);
  assert.equal(move(ROWS, "b", "ArrowLeft"), null);
});

test("an empty list reports no move for any key", () => {
  for (const key of ["ArrowDown", "ArrowUp", "Home", "End"]) {
    assert.equal(move([], null, key), null);
    assert.equal(move([], "a", key, { wrap: true }), null);
  }
});

test("a key the ring knows nothing about reports no move", () => {
  // The caller uses this to decide whether to call `preventDefault`, so PageDown must fall
  // through to the browser and keep scrolling the list.
  for (const key of ["PageDown", "Tab", "Enter", " ", "a"]) {
    assert.equal(move(ROWS, "b", key), null);
  }
});
