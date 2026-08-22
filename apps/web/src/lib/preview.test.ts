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
  MAX_VIEWER_EDGE,
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

/**
 * The two ceilings answer different questions and the difference is the whole reason the viewer
 * decodes a second time: `MAX_PREVIEW_PIXELS` bounds what may be decoded at all, `MAX_*_EDGE`
 * bounds what is kept afterwards. Reading one as the other is how a zoom control ends up
 * magnifying a thumbnail.
 */
test("the viewer's edge is larger than the bubble's, and the pixel ceiling is neither", () => {
  assert.ok(
    MAX_VIEWER_EDGE > MAX_PREVIEW_EDGE,
    "a viewer that keeps no more than the bubble does has nothing to zoom into",
  );
  // Above the long edge of a 12-megapixel phone photo (4000px), which is the case that has to
  // come back whole for the zoom to show real detail rather than interpolation.
  assert.ok(MAX_VIEWER_EDGE >= 4000);
});

/**
 * `fitWithin` is what both ceilings are applied through, so the property that matters is that it
 * never grows an image — a 200px icon opened full screen must stay 200px rather than being blown
 * up into a blur.
 */
test("the viewer's ceiling still never enlarges an image", () => {
  assert.deepEqual(fitWithin(200, 150, MAX_VIEWER_EDGE), { width: 200, height: 150 });
  assert.deepEqual(fitWithin(4000, 3000, MAX_VIEWER_EDGE), { width: 4000, height: 3000 });
});

test("an image past the viewer's ceiling is scaled to it, keeping its shape", () => {
  const wide = fitWithin(8192, 2048, MAX_VIEWER_EDGE);
  assert.equal(wide.width, MAX_VIEWER_EDGE);
  assert.equal(wide.height, MAX_VIEWER_EDGE / 4);

  const tall = fitWithin(2048, 8192, MAX_VIEWER_EDGE);
  assert.equal(tall.height, MAX_VIEWER_EDGE);
  assert.equal(tall.width, MAX_VIEWER_EDGE / 4);
});

/**
 * The ceilings compose in the order that matters: an image can be under the viewer's edge and
 * still over the pixel budget — 6000×5000 is 4800px on its long edge but 30 megapixels — and the
 * budget is what decides, at either size.
 */
test("the pixel budget is not weakened by asking for the larger edge", () => {
  assert.ok(!withinPixelBudget(6000, 5000));
  assert.ok(fitWithin(6000, 5000, MAX_VIEWER_EDGE).width <= MAX_VIEWER_EDGE);
  assert.ok(6000 * 5000 > MAX_PREVIEW_PIXELS);
});
