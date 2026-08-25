import assert from "node:assert/strict";
import { test } from "node:test";

import { expiryOf, isExpired, prune } from "./expiry.ts";
import type { Message } from "./session-types.ts";

const HOUR = 3600;

test("the deadline runs from when the sender says they wrote it", () => {
  assert.equal(expiryOf(1_000_000, 1_000_500, HOUR), 1_000_000 + HOUR * 1000);
});

test("a sender cannot buy time by post-dating their own message", () => {
  // sentAt an hour in the future, seen now: the clamp takes the moment it was seen.
  const seen = 1_000_000;
  assert.equal(expiryOf(seen + HOUR * 1000, seen, HOUR), seen + HOUR * 1000);
});

test("a sender may shorten their own message, which was never forbidden", () => {
  const seen = 1_000_000;
  const sent = seen - HOUR * 1000;
  assert.equal(expiryOf(sent, seen, HOUR), sent + HOUR * 1000);
});

test("no lifetime means no deadline", () => {
  assert.equal(expiryOf(1_000_000, 1_000_000, 0), undefined);
});

test("control traffic carries no sentAt and never expires", () => {
  // Nothing to count from. Receipts, gossip, posting keys and profiles are never stamped — see
  // `content.isControl` — so they have no deadline. The notices *are* stamped and do expire,
  // which is the intended answer and not an oversight: a thread whose messages are gone does not
  // read better for keeping the line that announced they would be.
  assert.equal(expiryOf(undefined, 1_000_000, HOUR), undefined);
});

test("pruning drops what is past and keeps the rest, in order", () => {
  const now = 2_000_000;
  const messages = [
    { seq: 1, sender: "bob", mine: false, content: { kind: "text", text: "old" }, expiresAt: now - 1 },
    { seq: 2, sender: "bob", mine: false, content: { kind: "text", text: "kept" }, expiresAt: now + 1 },
    { seq: 3, sender: "bob", mine: false, content: { kind: "text", text: "no deadline" } },
  ] as Message[];

  assert.deepEqual(prune(messages, now).map((m) => m.seq), [2, 3]);
});

test("a message already past its deadline when it arrives is expired on arrival", () => {
  const now = 2_000_000;
  const message = { seq: 1, sender: "bob", mine: false, content: { kind: "text", text: "late" }, expiresAt: now - 1 } as Message;

  assert.equal(isExpired(message, now), true);
});
