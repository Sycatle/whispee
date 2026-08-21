/**
 * Padding is reversible or it is worthless: a mistake here makes messages unreadable, not just
 * less private.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { pad, unpad } from "./padding.ts";

test("any content survives a round trip", () => {
  for (const length of [0, 1, 2, 255, 256, 257, 511, 512, 513, 1024, 5000]) {
    const body = new Uint8Array(length).map((_, i) => (i * 7) % 256);
    assert.deepEqual(unpad(pad(body)), body, `length ${length}`);
  }
});

/** The whole point of the scheme: ordinary typed messages become indistinguishable. */
test("short messages all have the same size", () => {
  const sizes = new Set(
    ["ok", "yes", "I'll call you back in ten minutes", "a".repeat(200)].map(
      (text) => pad(new TextEncoder().encode(text)).length,
    ),
  );
  assert.equal(sizes.size, 1);
  assert.equal([...sizes][0], 256);
});

/** The waste stays bounded: that is what makes the doubling acceptable. */
test("padding never doubles the size", () => {
  for (let length = 256; length < 20000; length += 37) {
    assert.ok(pad(new Uint8Array(length)).length < length * 2 + 256);
  }
});

/**
 * Content ending in zeros is the case the marker exists for: without it, those zeros would be
 * taken for padding and the message would be truncated.
 */
test("content ending in zeros is returned intact", () => {
  const body = new Uint8Array([1, 2, 3, 0, 0, 0]);
  assert.deepEqual(unpad(pad(body)), body);
});

test("malformed padding is rejected rather than guessed", () => {
  assert.throws(() => unpad(new Uint8Array(256)));
  assert.throws(() => unpad(new Uint8Array([1, 2, 3])));
});
