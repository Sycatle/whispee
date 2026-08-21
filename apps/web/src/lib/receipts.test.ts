import assert from "node:assert/strict";
import { test } from "node:test";

import { pending, record, statusOf, type ReceiptBook } from "./receipts.ts";

test("a receipt that moves backwards does not overwrite a further cursor", () => {
  const book: ReceiptBook = new Map();
  record(book, "bob", "read", 10);
  record(book, "bob", "read", 4);
  assert.equal(book.get("bob")?.read, 10);
});

test("reading implies having received", () => {
  const book: ReceiptBook = new Map();
  record(book, "bob", "read", 7);
  assert.deepEqual(book.get("bob"), { delivered: 7, read: 7 });
});

/**
 * **The test that keeps the conversation from never stopping.** Once the receipt for a cursor
 * has been sent, there must be nothing left to send for that same cursor.
 */
test("nothing is left to send once the account has already acknowledged that number", () => {
  const book: ReceiptBook = new Map();

  assert.equal(pending(book, "alice", "read", 5), 5);
  record(book, "alice", "read", 5);
  assert.equal(pending(book, "alice", "read", 5), undefined);
  assert.equal(pending(book, "alice", "read", 6), 6);
});

test("an account's second device does not send a receipt the first one already sent", () => {
  const book: ReceiptBook = new Map();

  // The first device sends; the receipt reaches every member, the second device included.
  record(book, "alice", "delivered", 12);

  assert.equal(pending(book, "alice", "delivered", 12), undefined);
});

test("a message is only read once every correspondent has read it", () => {
  const book: ReceiptBook = new Map();
  record(book, "bob", "read", 3);
  record(book, "carol", "delivered", 3);

  assert.equal(statusOf(book, ["bob", "carol"], 3, true), "delivered");

  record(book, "carol", "read", 3);
  assert.equal(statusOf(book, ["bob", "carol"], 3, true), "read");
});

/** Reciprocity: turning off your read receipts also stops you from seeing other people's. */
test("without read receipts, the status stops at delivered", () => {
  const book: ReceiptBook = new Map();
  record(book, "bob", "read", 3);

  assert.equal(statusOf(book, ["bob"], 3, false), "delivered");
});

test("a message nobody has picked up yet stays at sent", () => {
  assert.equal(statusOf(new Map(), ["bob"], 1, true), "sent");
});

/**
 * **The test that keeps the conversation from never stopping.**
 *
 * A receipt is itself an envelope. If the cursor being acknowledged advances over receipts, every
 * receipt gives birth to another. This test freezes the rule: only a cursor that moves on real
 * messages may be announced.
 *
 * The case was observed in production before the fix — ten envelopes in forty seconds, for two
 * people who were saying nothing.
 */
test("a frozen cursor produces no further receipt, even after several rounds", () => {
  const book: ReceiptBook = new Map();
  const contentCursor = 3;

  let sends = 0;
  for (let round = 0; round < 10; round += 1) {
    const due = pending(book, "alice", "delivered", contentCursor);
    if (due === undefined) continue;
    record(book, "alice", "delivered", due);
    sends += 1;
  }

  assert.equal(sends, 1, "one receipt per message received, not one per poll round");
});
