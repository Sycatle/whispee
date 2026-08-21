import assert from "node:assert/strict";
import { test } from "node:test";

import { type RosterConversation, roster } from "./roster.ts";

/** A conversation whose members have been resolved by a poll. */
function resolved(...handles: string[]): RosterConversation {
  return { accounts: handles.map((handle) => ({ handle })), peers: [] };
}

/** A conversation restored from disk: the tree is known, the accounts are not yet. */
function restored(...names: string[]): RosterConversation {
  return { accounts: [], peers: names.map((name) => ({ name })) };
}

test("somebody with a one-to-one conversation is a row above, not a contact", () => {
  const contacts = roster({ conversations: [resolved("bob")], verified: [], self: "alice" });
  assert.deepEqual(contacts, []);
});

test("a group member with no thread of their own is a contact", () => {
  const contacts = roster({
    conversations: [resolved("bob", "carol")],
    verified: [],
    self: "alice",
  });
  assert.deepEqual(contacts, ["bob", "carol"]);
});

test("only the person we have a thread with drops out of the group they share with us", () => {
  const contacts = roster({
    conversations: [resolved("bob", "carol"), resolved("bob")],
    verified: [],
    self: "alice",
  });
  assert.deepEqual(contacts, ["carol"]);
});

test("a verified handle is a contact even with nothing shared", () => {
  const contacts = roster({ conversations: [], verified: ["dave"], self: "alice" });
  assert.deepEqual(contacts, ["dave"]);
});

test("verifying somebody we already talk to does not list them twice", () => {
  const contacts = roster({
    conversations: [resolved("bob")],
    verified: ["bob"],
    self: "alice",
  });
  assert.deepEqual(contacts, []);
});

test("we are never our own contact, from either source", () => {
  const contacts = roster({
    conversations: [restored("alice", "bob", "carol")],
    verified: ["alice"],
    self: "alice",
  });
  assert.deepEqual(contacts, ["bob", "carol"]);
});

test("a restored two-person thread counts as one-to-one although the tree lists us in it", () => {
  // The regression this guards: `peers` includes ourselves and `accounts` does not, so counting
  // members before removing ourselves would read this as a group and list Bob as a contact
  // right under his own conversation.
  const contacts = roster({ conversations: [restored("alice", "bob")], verified: [], self: "alice" });
  assert.deepEqual(contacts, []);
});

test("contacts come back sorted, whatever order the conversations arrived in", () => {
  const contacts = roster({
    conversations: [resolved("zoe", "bob"), resolved("mallory", "bob")],
    verified: [],
    self: "alice",
  });
  assert.deepEqual(contacts, ["bob", "mallory", "zoe"]);
});
