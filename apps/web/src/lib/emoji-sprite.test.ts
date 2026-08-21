import assert from "node:assert/strict";
import { test } from "node:test";

import { load, shardOf } from "./emoji-sprite.ts";

test("a sequence with no skin tone is in the base sheet", () => {
  assert.equal(shardOf("😀"), "base");
  assert.equal(shardOf("👨‍💻"), "base");
  assert.equal(shardOf("🇫🇷"), "base");
});

test("a single modifier names its own sheet", () => {
  assert.equal(shardOf("👍🏻"), "tone-1");
  assert.equal(shardOf("👍🏽"), "tone-3");
  assert.equal(shardOf("👍🏿"), "tone-5");
});

test("the same modifier twice is still one tone, not a mixture", () => {
  // A couple where both people share a tone carries the modifier twice. Counting occurrences
  // rather than distinct values would file it under `mixed`, where the generator — which uses
  // this very function — would not have put it. The emoji would be unreachable at runtime and
  // the build would report nothing wrong.
  assert.equal(shardOf("👩🏻‍❤️‍👨🏻"), "tone-1");
  assert.equal(shardOf("👩🏻‍❤️‍👨🏿"), "mixed");
});

/**
 * Just enough document for `inject` to run under the Node test runner.
 *
 * Not a DOM library: what is being tested is the memoisation, and the only reason this exists at
 * all is that a sheet landing now writes straight into the document rather than being kept as
 * strings. Stubbing the four calls it makes is cheaper and more honest than pretending the load
 * path has no side effect.
 */
function stubDocument(): () => void {
  const node = () => ({ setAttribute() {}, append() {}, innerHTML: "" });
  const previous = Reflect.get(globalThis, "document") as unknown;

  Reflect.set(globalThis, "document", {
    createElementNS: node,
    body: { prepend() {} },
  });

  return () => Reflect.set(globalThis, "document", previous);
}

test("a sheet is fetched once, however many callers ask for it", async () => {
  let calls = 0;
  const original = globalThis.fetch;
  const restore = stubDocument();
  globalThis.fetch = (async () => {
    calls += 1;
    return new Response(JSON.stringify({ "1f44d-1f3fd": "<path/>" }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;

  try {
    // Two bubbles mounting in one frame is the ordinary case, not the pathological one. Without
    // memoisation on the promise they would each fetch and each parse the same megabytes.
    await Promise.all([load("tone-3"), load("tone-3")]);
    await load("tone-3");
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = original;
    restore();
  }
});
