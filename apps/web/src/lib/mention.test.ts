import assert from "node:assert/strict";
import { test } from "node:test";

import { addressedIn, addresses, completions, resolve, runs, typed } from "./mention.ts";
import type { NameSources } from "./naming.ts";

const MEMBERS = ["alice", "bob", "carol_w", "dave"];

const SOURCES: NameSources = {
  petnames: { dave: "The Boss" },
  profiles: {
    alice: { name: "Alice Smith" },
    bob: { name: "Bobby" },
    carol_w: { name: "Alice Smith" },
  },
};

test("an at sign opening a token starts a mention", () => {
  assert.deepEqual(typed("@al", 3), { from: 0, to: 3, query: "al" });
  assert.deepEqual(typed("hey @al", 7), { from: 4, to: 7, query: "al" });
  assert.deepEqual(typed("(@al", 4), { from: 1, to: 4, query: "al" });
});

test("a bare at sign opens the menu", () => {
  // Unlike a shortcode, which needs two characters: this candidate set is a handful of people,
  // and listing them answers "who is in this room".
  assert.deepEqual(typed("@", 1), { from: 0, to: 1, query: "" });
});

test("an at sign inside a word does not", () => {
  // The case this rule exists for: an email address must not put a menu over the composer.
  assert.equal(typed("sam@example.com", 15), null);
  assert.equal(typed("sam@ex", 6), null);
  assert.equal(typed("@@", 2), null);
});

test("the query stops at whitespace", () => {
  // A query allowed to swallow a space would turn the rest of the sentence into a search term
  // and the menu would never close.
  assert.equal(typed("@alice and", 10), null);
});

test("an exact handle outranks everything", () => {
  assert.deepEqual(completions(MEMBERS, SOURCES, "bob"), ["bob"]);
});

test("handles rank ahead of names, and names ahead of anything else", () => {
  // `alice` matches by handle; `carol_w` only by its asserted name.
  assert.deepEqual(completions(MEMBERS, SOURCES, "ali"), ["alice", "carol_w"]);
});

test("a petname is searchable, because it is what the reader sees", () => {
  assert.deepEqual(completions(MEMBERS, SOURCES, "boss"), ["dave"]);
});

test("a bare query offers everybody, sorted", () => {
  assert.deepEqual(completions(MEMBERS, SOURCES, ""), ["alice", "bob", "carol_w", "dave"]);
});

test("a pasted handle keeps its sigil without breaking the match", () => {
  assert.deepEqual(completions(MEMBERS, SOURCES, "@bob"), ["bob"]);
});

test("a mention is split out of the prose around it", () => {
  assert.deepEqual(runs("hi @alice, look", MEMBERS), [
    { text: "hi " },
    { handle: "alice" },
    { text: ", look" },
  ]);
});

test("a handle that names nobody here stays prose", () => {
  // The rule that keeps one conversation's rendering independent of every other one.
  assert.deepEqual(runs("hi @mallory", MEMBERS), [{ text: "hi @mallory" }]);
});

test("the token is maximal and never backtracked", () => {
  // `alice` is a member and `alicesmith` is not. Drawing `@alice` here and leaving `smith` after
  // it would attribute the sentence to somebody the writer did not address.
  assert.deepEqual(runs("@alicesmith", MEMBERS), [{ text: "@alicesmith" }]);
});

test("an email address is not a mention even when the domain is a member", () => {
  assert.deepEqual(runs("write to sam@alice", MEMBERS), [{ text: "write to sam@alice" }]);
});

test("two mentions in a row keep the space between them", () => {
  assert.deepEqual(runs("@alice @bob", MEMBERS), [
    { handle: "alice" },
    { text: " " },
    { handle: "bob" },
  ]);
});

test("addressing is decided by the same rules that render", () => {
  assert.equal(addresses("hi @alice", "alice", MEMBERS), true);
  assert.equal(addresses("hi @alice", "bob", MEMBERS), false);
  // Not a mention, so not an address: a notification fired here would point at nothing.
  assert.equal(addresses("sam@alice", "alice", MEMBERS), false);
  assert.equal(addresses("@alicesmith", "alice", MEMBERS), false);
});

test("scanning twice gives the same answer", () => {
  // The scanner is a module-level regex with `lastIndex`, which is state. Reset on entry, so a
  // second call cannot start halfway through the string.
  const once = runs("hi @alice", MEMBERS);
  assert.deepEqual(runs("hi @alice", MEMBERS), once);
});

test("a mention newer than the cursor is an address", () => {
  const thread = [
    { seq: 1, mine: true, content: { kind: "text", text: "morning" } },
    { seq: 2, mine: false, content: { kind: "text", text: "hey @alice" } },
  ];
  assert.equal(addressedIn(thread, 1, "alice", MEMBERS), "mention");
  // Anything at or below the cursor has already been accounted for.
  assert.equal(addressedIn(thread, 2, "alice", MEMBERS), null);
});

test("a reply to one of ours is an address", () => {
  const thread = [
    { seq: 1, mine: true, content: { kind: "text", text: "morning" } },
    { seq: 2, mine: false, content: { kind: "reply", text: "sure", target: 1 } },
  ];
  assert.equal(addressedIn(thread, 1, "alice", MEMBERS), "reply");
});

test("a reply to somebody else is not", () => {
  const thread = [
    { seq: 1, mine: false, content: { kind: "text", text: "morning" } },
    { seq: 2, mine: false, content: { kind: "reply", text: "sure", target: 1 } },
  ];
  assert.equal(addressedIn(thread, 1, "alice", MEMBERS), null);
});

test("a mention outranks a reply in the same batch", () => {
  const thread = [
    { seq: 1, mine: true, content: { kind: "text", text: "morning" } },
    { seq: 2, mine: false, content: { kind: "reply", text: "sure", target: 1 } },
    { seq: 3, mine: false, content: { kind: "text", text: "@alice look" } },
  ];
  assert.equal(addressedIn(thread, 1, "alice", MEMBERS), "mention");
});

test("our own messages never address us", () => {
  const thread = [
    { seq: 1, mine: true, content: { kind: "text", text: "note to @alice" } },
    { seq: 2, mine: true, content: { kind: "reply", text: "and", target: 1 } },
  ];
  assert.equal(addressedIn(thread, 0, "alice", MEMBERS), null);
});

const DIRECTORY = new Map([
  ["alice", "a".repeat(32)],
  ["bob", "b".repeat(32)],
]);

test("a typed handle leaves as the account it names", () => {
  assert.equal(resolve("hi @alice", DIRECTORY), `hi @${"a".repeat(32)}`);
});

test("a handle nobody in the room answers to is left alone", () => {
  // The same rule `runs` applies: it addresses somebody who will never read it, and inventing an
  // id for them would be worse than leaving prose.
  assert.equal(resolve("hi @mallory", DIRECTORY), "hi @mallory");
});

test("resolving touches nothing when there is nothing to resolve", () => {
  const plain = "no mentions here, and an @ sign";
  assert.equal(resolve(plain, DIRECTORY), plain);
});

test("an email address survives resolution intact", () => {
  assert.equal(resolve("write to sam@alice about it", DIRECTORY), "write to sam@alice about it");
});

test("several mentions and the prose between them all survive", () => {
  assert.equal(
    resolve("@alice and @bob, look", DIRECTORY),
    `@${"a".repeat(32)} and @${"b".repeat(32)}, look`,
  );
});

test("an id typed by hand is already resolved and stays put", () => {
  const already = `hi @${"a".repeat(32)}`;
  assert.equal(resolve(already, DIRECTORY), already);
});

test("what resolution produces is what rendering reads back", () => {
  // The round trip is the property that matters: a mention the sender wrote and the recipient
  // cannot find highlighted is worse than no mention at all.
  const accounts = [...DIRECTORY.values()];
  const wire = resolve("hi @alice", DIRECTORY);
  assert.deepEqual(runs(wire, accounts), [{ text: "hi " }, { handle: "a".repeat(32) }]);
  assert.equal(addresses(wire, "a".repeat(32), accounts), true);
});

/**
 * The defect fenced blocks introduced, and the reason `resolve` splices rather than joins.
 *
 * `resolve` runs on the way **out** — on the message that is actually sent. A handle rewritten
 * inside a code sample leaves thirty-two hexadecimal characters in the middle of somebody's
 * snippet, on the wire, with nothing to recover it from. That is a different order of mistake
 * from rendering it wrongly.
 */
test("a handle inside a fenced block is left exactly as it was written", () => {
  const directory = new Map([["alice", "a1b2c3"]]);
  const text = "ask @alice about this:\n```py\n@alice\ndef f(): pass\n```\nand that is all";

  const out = resolve(text, directory);

  assert.ok(out.includes("ask @a1b2c3 about this"), "prose was not resolved");
  assert.ok(out.includes("```py\n@alice\ndef f(): pass\n```"), "the block was rewritten");
  assert.equal(out.split("a1b2c3").length - 1, 1, "the id reached the code sample");
});

test("a handle inside inline code is left alone too", () => {
  const directory = new Map([["alice", "a1b2c3"]]);
  assert.equal(resolve("see `@alice` here", directory), "see `@alice` here");
  assert.equal(resolve("see @alice here", directory), "see @a1b2c3 here");
});

/**
 * Byte-for-byte identity outside prose is the property the splice buys, and the way to check it
 * is a text the scanner has no business changing at all.
 */
test("text with nothing to resolve comes back unchanged", () => {
  const directory = new Map([["alice", "a1b2c3"]]);
  for (const text of [
    "```\njust code\n```",
    "no mentions at all",
    "```\n@nobody\n```",
    "trailing newline\n",
    "```unclosed\n@alice",
  ]) {
    assert.equal(resolve(text, directory), text, `changed ${JSON.stringify(text)}`);
  }
});

/**
 * The mirror-image bug: a notification raised for a handle that is only visible inside a code
 * sample, naming somebody the message does not address.
 */
test("a handle only present in code does not address anybody", () => {
  const among = ["alice"];
  assert.ok(!addresses("```\n@alice\n```", "alice", among));
  assert.ok(!addresses("run `@alice` to see", "alice", among));
  assert.ok(addresses("hey @alice", "alice", among));
  // Both at once: the prose one counts, the code one does not, and the answer is still yes.
  assert.ok(addresses("hey @alice, run `@alice`", "alice", among));
});
