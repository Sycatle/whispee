import assert from "node:assert/strict";
import { test } from "node:test";

import { decode, encode, isControl } from "./content.ts";

test("a receipt round-trips", () => {
  const decoded = decode(encode({ kind: "receipt", state: "read", seq: 4200 }));
  assert.deepEqual(decoded, { kind: "receipt", state: "read", seq: 4200 });
});

test("the two receipt states stay distinct", () => {
  const delivered = decode(encode({ kind: "receipt", state: "delivered", seq: 1 }));
  const read = decode(encode({ kind: "receipt", state: "read", seq: 1 }));
  assert.notDeepEqual(delivered, read);
});

test("a reaction and a reply are not confused despite their shared shape", () => {
  const reaction = decode(encode({ kind: "reaction", target: 12, emoji: "👍" }));
  const reply = decode(encode({ kind: "reply", target: 12, text: "👍" }));

  assert.deepEqual(reaction, { kind: "reaction", target: 12, emoji: "👍" });
  assert.deepEqual(reply, { kind: "reply", target: 12, text: "👍" });
});

test("an empty emoji encodes the removal of a reaction", () => {
  assert.deepEqual(decode(encode({ kind: "reaction", target: 3, emoji: "" })), {
    kind: "reaction",
    target: 3,
    emoji: "",
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
