import assert from "node:assert/strict";
import { test } from "node:test";

import { decode, encode, isControl } from "./content.ts";

test("a receipt round-trips", () => {
  const decoded = decode(encode({ kind: "receipt", state: "read", seq: 4200 }));
  assert.deepEqual(decoded, { body: { kind: "receipt", state: "read", seq: 4200 } });
});

test("the two receipt states stay distinct", () => {
  const delivered = decode(encode({ kind: "receipt", state: "delivered", seq: 1 }));
  const read = decode(encode({ kind: "receipt", state: "read", seq: 1 }));
  assert.notDeepEqual(delivered, read);
});

test("a reaction and a reply are not confused despite their shared shape", () => {
  const reaction = decode(encode({ kind: "reaction", target: 12, emoji: "👍" }));
  const reply = decode(encode({ kind: "reply", target: 12, text: "👍" }));

  assert.deepEqual(reaction, { body: { kind: "reaction", target: 12, emoji: "👍" } });
  assert.deepEqual(reply, { body: { kind: "reply", target: 12, text: "👍" } });
});

test("an empty emoji encodes the removal of a reaction", () => {
  assert.deepEqual(decode(encode({ kind: "reaction", target: 3, emoji: "" })), {
    body: { kind: "reaction", target: 3, emoji: "" },
  });
});

/**
 * **The test that prevents the infinite loop.** A receipt is itself an envelope: unless it is
 * recognized as protocol traffic, each side acknowledges the other's acknowledgement and the
 * conversation never stops.
 */
test("a receipt is protocol traffic, a reaction is not", () => {
  assert.equal(isControl({ kind: "receipt", state: "read", seq: 1 }), true);
  assert.equal(isControl({ kind: "reaction", target: 1, emoji: "🙂" }), false);
  assert.equal(isControl({ kind: "reply", target: 1, text: "yes" }), false);
  assert.equal(isControl({ kind: "text", text: "hello" }), false);
});

test("a truncated receipt is rejected rather than interpreted", () => {
  const complete = encode({ kind: "receipt", state: "read", seq: 9 });
  assert.throws(() => decode(complete.subarray(0, complete.length - 1)));
});

test("a truncated message reference is rejected", () => {
  assert.throws(() => decode(new Uint8Array([5, 0, 0, 0])));
});

test("a stamped message carries its time back", () => {
  const decoded = decode(encode({ kind: "text", text: "hello" }, 1_700_000_000_123));

  assert.deepEqual(decoded, {
    body: { kind: "text", text: "hello" },
    sentAt: 1_700_000_000_123,
  });
});

/** Every displayable form goes through the same wrapper, so none of them can be forgotten. */
test("the stamp composes with each displayable form", () => {
  for (const body of [
    { kind: "text", text: "hi" },
    { kind: "reaction", target: 1, emoji: "🙂" },
    { kind: "reply", target: 1, text: "yes" },
  ] as const) {
    assert.deepEqual(decode(encode(body, 42)), { body, sentAt: 42 });
  }
});

/**
 * Control traffic is not displayed, so eight bytes of date buy nothing — and a receipt that
 * looked like a dated message would be one more thing `isControl` has to un-say.
 */
test("control traffic is never stamped, even when a time is offered", () => {
  const stamped = encode({ kind: "receipt", state: "read", seq: 1 }, 42);
  const plain = encode({ kind: "receipt", state: "read", seq: 1 });

  assert.deepEqual(stamped, plain);
  assert.equal(decode(stamped).sentAt, undefined);
});

/** A message written before stamping existed still reads, without inventing a date for it. */
test("an unstamped message decodes with no time rather than a guessed one", () => {
  assert.deepEqual(decode(encode({ kind: "text", text: "old" })), {
    body: { kind: "text", text: "old" },
  });
});

test("a truncated stamp is rejected rather than read as a shorter number", () => {
  const stamped = encode({ kind: "text", text: "x" }, 1);
  assert.throws(() => decode(stamped.subarray(0, 6)));
});

/**
 * Unwrapping is deliberately one level deep. Recursion would let a member nest a few thousand
 * wrappers and spend our stack on it; here the second wrapper is simply an unknown inner type.
 */
test("a wrapper nested inside a wrapper is refused", () => {
  const once = encode({ kind: "text", text: "x" }, 1);
  const twice = new Uint8Array(9 + once.length);
  twice.set(once.subarray(0, 9), 0);
  twice.set(once, 9);

  assert.throws(() => decode(twice));
});
