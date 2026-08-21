/**
 * What a conversation view says about itself.
 *
 * These rules used to be instance methods on a class that cannot be instantiated without WASM and
 * IndexedDB, so none of them had ever been checked by anything but the running application. Each
 * test below states the rule its subject exists to enforce, rather than the shape of its output.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import type { ResolvedAccount } from "./account.ts";
import {
  deliveryStatus,
  lastActivityIn,
  matchingConversation,
  successorOf,
  unreadIn,
} from "./conversation-view.ts";
import { record } from "./receipts.ts";
import { freshSignalState, type ConversationView, type Message } from "./session-types.ts";

function view(over: Partial<ConversationView> = {}): ConversationView {
  return {
    groupId: new Uint8Array([1]),
    key: "aa",
    messages: [],
    peers: [],
    accounts: [],
    epoch: 0n,
    cursor: 0,
    mine: new Set<number>(),
    ...freshSignalState(),
    ...over,
  };
}

function said(seq: number, sender: string, over: Partial<Message> = {}): Message {
  return { seq, sender, mine: false, content: { kind: "text", text: "x" }, ...over };
}

function peers(...names: string[]) {
  return names.map((name) => ({ name })) as ConversationView["peers"];
}

function account(handle: string, fingerprint: string) {
  return { handle, fingerprint } as ResolvedAccount;
}

test("a conversation is found whatever order its members were typed in", () => {
  const group = view({ key: "g", peers: peers("alice", "bob", "carol") });

  assert.equal(matchingConversation([group], ["carol", "bob"], "alice"), group);
  assert.equal(matchingConversation([group], ["bob", "carol"], "alice"), group);
});

test("a peer's several devices count once", () => {
  // An account with three devices appears three times in the MLS tree. Comparing lists rather than
  // sets would make it match nothing and open a second conversation with the same person.
  const duo = view({ peers: peers("alice", "bob", "bob", "bob") });

  assert.equal(matchingConversation([duo], ["bob"], "alice"), duo);
});

test("a strict subset is not a match", () => {
  const group = view({ peers: peers("alice", "bob", "carol") });

  assert.equal(matchingConversation([group], ["bob"], "alice"), undefined);
});

test("the admin hands over to a moderator when one is left", () => {
  const group = view({ peers: peers("alice", "bob", "carol") });
  const roles = { admin: "alice", moderators: ["carol"] };

  assert.equal(successorOf(group, roles, "alice"), "carol");
});

test("with no moderator left, the oldest member in tree order inherits", () => {
  const group = view({ peers: peers("alice", "bob", "carol") });

  assert.equal(successorOf(group, { admin: "alice", moderators: [] }, "alice"), "bob");
});

test("an admin alone in the group has nobody to hand over to", () => {
  const alone = view({ peers: peers("alice") });

  assert.equal(successorOf(alone, { admin: "alice", moderators: [] }, "alice"), null);
});

test("only what arrived after the read cursor is unread", () => {
  const thread = view({
    readCursor: 2,
    messages: [said(1, "bob"), said(2, "bob"), said(3, "bob"), said(4, "bob")],
  });

  assert.equal(unreadIn(thread), 2);
});

test("nobody is behind on what they wrote themselves", () => {
  const thread = view({
    readCursor: 0,
    messages: [said(1, "alice", { mine: true }), said(2, "bob")],
  });

  assert.equal(unreadIn(thread), 1);
});

test("a thread with no stamps sinks rather than floating", () => {
  // `0`, not `Date.now()`. An old conversation nobody has written in must not sort above a live
  // one on a value invented for it at render time.
  assert.equal(lastActivityIn(view({ messages: [said(1, "bob")] })), 0);
});

test("a message still queued counts as activity", () => {
  const thread = view({
    messages: [said(1, "bob", { sentAt: 100 })],
    outbox: [{ localId: "x", text: "later", sentAt: 500, state: "sending" }],
  });

  assert.equal(lastActivityIn(thread), 500);
});

test("the latest stamp wins, whichever side it came from", () => {
  const thread = view({
    messages: [said(1, "bob", { sentAt: 900 }), said(2, "bob", { sentAt: 300 })],
    outbox: [{ localId: "x", text: "later", sentAt: 500, state: "sending" }],
  });

  assert.equal(lastActivityIn(thread), 900);
});

test("a message is only read once every recipient has read it", () => {
  const receipts = new Map();
  record(receipts, "bob", "read", 5);
  record(receipts, "carol", "delivered", 5);

  const group = view({
    receipts,
    accounts: [account("alice", "A"), account("bob", "B"), account("carol", "C")],
  });

  assert.equal(deliveryStatus(group, 5, "alice", true), "delivered");

  record(receipts, "carol", "read", 5);
  assert.equal(deliveryStatus(group, 5, "alice", true), "read");
});

test("with read receipts off, nothing is ever reported as read", () => {
  // Off means off in both directions. Showing somebody else's read receipts while withholding our
  // own would be the one arrangement the setting must not produce.
  const receipts = new Map();
  record(receipts, "bob", "read", 5);

  const duo = view({ receipts, accounts: [account("alice", "A"), account("bob", "B")] });

  assert.equal(deliveryStatus(duo, 5, "alice", true), "read");
  assert.notEqual(deliveryStatus(duo, 5, "alice", false), "read");
});
