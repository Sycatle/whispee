import assert from "node:assert/strict";
import { test } from "node:test";

import { GRID_SIZE, identicon, MARK_COUNT, MARK_LEVELS, marks } from "./proofstrip.ts";

/** Two fingerprints in the shape `accountFingerprint` produces: hex, grouped in blocks. */
const ALICE = "a1b2 c3d4 e5f6 0718 293a 4b5c 6d7e 8f90";
const BOB = "a1b2 c3d4 e5f6 0718 293a 4b5c 6d7e 8f91";

test("the same fingerprint always produces the same marks", () => {
  assert.deepEqual(marks(ALICE), marks(ALICE));
});

test("two distinct fingerprints produce distinct patterns", () => {
  // The two differ by a single hex digit, which is the case that matters: a substitution must
  // not look like a typo.
  assert.notDeepEqual(marks(ALICE), marks(BOB));
});

test("a strip has exactly the number of marks it was asked for", () => {
  assert.equal(marks(ALICE).length, MARK_COUNT);
  assert.equal(marks(ALICE, 24).length, 24);
  assert.equal(marks(ALICE, 0).length, 0);
});

test("every mark is one of the three defined levels", () => {
  for (const level of marks(ALICE, 512)) {
    assert.ok(Number.isInteger(level), `${level} is not an integer level`);
    assert.ok(level >= 0 && level < MARK_LEVELS, `${level} is outside the defined levels`);
  }
});

test("a fingerprint shorter than expected still produces a full strip", () => {
  // A truncated fingerprint must not produce a truncated strip: a short strip would read as a
  // different, quieter state instead of as the same ornament.
  assert.equal(marks("").length, MARK_COUNT);
  assert.equal(marks("a").length, MARK_COUNT);
});

test("the same seed always produces the same avatar", () => {
  assert.deepEqual(identicon(ALICE), identicon(ALICE));
  assert.notDeepEqual(identicon(ALICE).cells, identicon(BOB).cells);
});

test("an avatar grid is symmetric so a glance reads it as one shape", () => {
  const { cells, hue } = identicon(ALICE);
  assert.equal(cells.length, GRID_SIZE * GRID_SIZE);
  assert.ok(hue >= 0 && hue < 360, `hue ${hue} is not a degree`);
  for (let row = 0; row < GRID_SIZE; row += 1) {
    for (let column = 0; column < GRID_SIZE; column += 1) {
      assert.equal(
        cells[row * GRID_SIZE + column],
        cells[row * GRID_SIZE + (GRID_SIZE - 1 - column)],
        `row ${row} is not mirrored at column ${column}`,
      );
    }
  }
});

test("an avatar is never blank, because a blank one is the placeholder", () => {
  for (let index = 0; index < 2048; index += 1) {
    assert.ok(identicon(`seed-${index}`).cells.some(Boolean), `seed-${index} drew nothing`);
  }
});
