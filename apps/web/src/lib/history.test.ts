import assert from "node:assert/strict";
import { test } from "node:test";

import { RECENT_PER_CONVERSATION, decodeHistory, encodeHistory } from "./history.ts";
import type { Message } from "./session.ts";

const text = (seq: number, extra: Partial<Message> = {}): Message => ({
  seq,
  sender: "bob",
  mine: false,
  content: { kind: "text", text: `message ${seq}` },
  ...extra,
});

const roundTrip = (conversations: Map<string, Message[]>) =>
  decodeHistory(encodeHistory(conversations));

test("a conversation reads back with its messages", () => {
  const original = new Map([["0a0b", [text(1), text(2)]]]);

  assert.deepEqual(roundTrip(original).get("0a0b"), [text(1), text(2)]);
});

/** The stamp rides inside the encoded body, so it must survive without a field of its own. */
test("the time a message was written survives the round trip", () => {
  const stamped = text(1, { sentAt: 1_700_000_000_000 });

  assert.equal(roundTrip(new Map([["0a0b", [stamped]]])).get("0a0b")?.[0].sentAt, 1_700_000_000_000);
});

test("an unstamped message comes back without a time rather than with a guessed one", () => {
  const restored = roundTrip(new Map([["0a0b", [text(1)]]])).get("0a0b");

  assert.ok(restored);
  assert.ok(!("sentAt" in restored[0]));
});

test("our own messages stay ours", () => {
  const mine = text(1, { mine: true, sender: "alice-laptop" });

  assert.deepEqual(roundTrip(new Map([["0a0b", [mine]]])).get("0a0b"), [mine]);
});

/**
 * The cap is the whole reason this is a window and not a log: `persist` re-serialises everything
 * on every write, so an unbounded thread would make each send cost the entire history.
 */
test("only the tail of a long conversation is kept", () => {
  const long = Array.from({ length: RECENT_PER_CONVERSATION + 50 }, (_, i) => text(i));

  const restored = roundTrip(new Map([["0a0b", long]]));

  assert.equal(restored.get("0a0b")?.length, RECENT_PER_CONVERSATION);
  // The tail, not the head: what is dropped is the part the vault can fetch back.
  assert.equal(restored.get("0a0b")?.[0].seq, 50);
});

test("messages are written in sequence order whatever order they arrived in", () => {
  const shuffled = [text(3), text(1), text(2)];

  assert.deepEqual(
    roundTrip(new Map([["0a0b", shuffled]])).get("0a0b")?.map((m) => m.seq),
    [1, 2, 3],
  );
});

test("an empty conversation writes no entry at all", () => {
  assert.equal(roundTrip(new Map([["0a0b", []]])).size, 0);
});

test("conversations stay separate", () => {
  const restored = roundTrip(
    new Map([
      ["0a0b", [text(1)]],
      ["0c0d", [text(9)]],
    ]),
  );

  assert.equal(restored.get("0a0b")?.[0].seq, 1);
  assert.equal(restored.get("0c0d")?.[0].seq, 9);
});

/**
 * A cache is redundant by construction: the conversation is still on the server and `hydrate`
 * fetches it. Refusing to start because the cache is corrupt would turn a cosmetic loss into a
 * device that cannot open.
 */
test("an unreadable cache yields nothing rather than throwing", () => {
  assert.equal(decodeHistory(new TextEncoder().encode("not json at all")).size, 0);
  assert.equal(decodeHistory(new Uint8Array()).size, 0);
});

test("a cache from another version is ignored rather than misread", () => {
  const future = new TextEncoder().encode(JSON.stringify({ v: 2, conversations: { a: [] } }));

  assert.equal(decodeHistory(future).size, 0);
});

/** One bad entry loses one message, not the conversation around it. */
test("an entry that no longer decodes is dropped on its own", () => {
  const encoded = encodeHistory(new Map([["0a0b", [text(1), text(2)]]]));
  const payload = JSON.parse(new TextDecoder().decode(encoded));
  // Type byte 200 is not a content type, so `content.decode` refuses it.
  payload.conversations["0a0b"][0].body = [200, 1, 2];

  const restored = decodeHistory(new TextEncoder().encode(JSON.stringify(payload)));

  assert.deepEqual(restored.get("0a0b")?.map((m) => m.seq), [2]);
});
