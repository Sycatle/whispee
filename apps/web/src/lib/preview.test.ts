/**
 * What can be checked without a browser, and what cannot.
 *
 * The security property of `preview.ts` is that the received bytes go through an image decoder
 * and never reach the document — and that property lives entirely in `decodePreview`, which
 * needs `createImageBitmap`, a `<canvas>` and `URL.createObjectURL`. `node --test` has none of
 * the three, so **the decoder round trip is not covered here** and is verified by hand: an SVG
 * renamed to `.png` must produce a download link, not a rendered drawing.
 *
 * What is covered is every decision made around that call — the ceilings, the scaling, and the
 * reading of a sender-controlled MIME string — which is where an off-by-one silently turns a
 * bound into no bound at all.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MAX_PREVIEW_EDGE,
  MAX_PREVIEW_PIXELS,
  fitWithin,
  looksLikeImage,
  mayAnimate,
  withinPixelBudget,
} from "./preview.ts";

/** The type is attacker-controlled text, so the parsing has to survive whatever it says. */
test("the declared type is read defensively", () => {
  assert.ok(looksLikeImage("image/png"));
  assert.ok(looksLikeImage("IMAGE/PNG"));
  assert.ok(looksLikeImage(" image/jpeg ; charset=binary"));

  assert.ok(!looksLikeImage("text/html"));
  assert.ok(!looksLikeImage("application/octet-stream"));
  assert.ok(!looksLikeImage(""));
  // The prefix must be the whole type, not a substring: this is a real MIME type and it is not
  // an image.
  assert.ok(!looksLikeImage("application/vnd.image/png"));
});

/**
 * `image/svg+xml` is the case the whole module is built around. It passes this gate on purpose —
 * the gate is about cost, not safety — and is stopped by the decoder, which cannot rasterise it
 * into a preview that carries script.
 */
test("SVG is not filtered out here, because this is not the filter", () => {
  assert.ok(looksLikeImage("image/svg+xml"));
});

test("formats that can animate are flagged so the caption can say so", () => {
  assert.ok(mayAnimate("image/gif"));
  assert.ok(mayAnimate("image/webp"));
  assert.ok(mayAnimate("image/APNG"));
  assert.ok(!mayAnimate("image/png"));
  assert.ok(!mayAnimate("image/jpeg"));
});

test("the pixel ceiling is inclusive and rejects degenerate sizes", () => {
  assert.ok(withinPixelBudget(5000, 5000));
  assert.ok(withinPixelBudget(MAX_PREVIEW_PIXELS, 1));
  assert.ok(!withinPixelBudget(MAX_PREVIEW_PIXELS + 1, 1));

  // A decode bomb is a small file describing an enormous raster; the ceiling is the only thing
  // between it and a hundred megabytes retained per message.
  assert.ok(!withinPixelBudget(60000, 60000));

  assert.ok(!withinPixelBudget(0, 100));
  assert.ok(!withinPixelBudget(100, 0));
});

test("an image smaller than the ceiling is drawn at its own size", () => {
  assert.deepEqual(fitWithin(320, 240, MAX_PREVIEW_EDGE), { width: 320, height: 240 });
});

test("a large image is scaled down keeping its aspect ratio", () => {
  const fitted = fitWithin(4000, 3000, MAX_PREVIEW_EDGE);
  assert.equal(fitted.width, MAX_PREVIEW_EDGE);
  assert.equal(fitted.height, Math.round((MAX_PREVIEW_EDGE * 3) / 4));
});

test("the constrained edge is the long one, whichever it is", () => {
  assert.equal(fitWithin(3000, 4000, 1000).height, 1000);
  assert.equal(fitWithin(4000, 3000, 1000).width, 1000);
});

/** A canvas of zero width throws, so a sliver must round up rather than to nothing. */
test("an extreme aspect ratio still produces a drawable canvas", () => {
  const fitted = fitWithin(10000, 1, 1000);
  assert.equal(fitted.width, 1000);
  assert.equal(fitted.height, 1);
});
