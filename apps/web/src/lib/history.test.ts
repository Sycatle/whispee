import assert from "node:assert/strict";
import { test } from "node:test";

import { type Cached, RECENT_PER_CONVERSATION, decodeHistory, encodeHistory } from "./history.ts";
import type { Message, Pending } from "./session.ts";

const text = (seq: number, extra: Partial<Message> = {}): Message => ({
  seq,
  sender: "bob",
  mine: false,
  content: { kind: "text", text: `message ${seq}` },
  ...extra,
});

const thread = (messages: Message[], outbox: Pending[] = []): Cached => ({ messages, outbox });

const roundTrip = (conversations: Map<string, Cached>) =>
  decodeHistory(encodeHistory(conversations));

test("a conversation reads back with its messages", () => {
  const original = new Map([["0a0b", thread([text(1), text(2)])]]);

  assert.deepEqual(roundTrip(original).get("0a0b")?.messages, [text(1), text(2)]);
});

/** The stamp rides inside the encoded body, so it must survive without a field of its own. */
test("the time a message was written survives the round trip", () => {
  const stamped = text(1, { sentAt: 1_700_000_000_000 });

  assert.equal(roundTrip(new Map([["0a0b", thread([stamped])]])).get("0a0b")?.messages[0].sentAt, 1_700_000_000_000);
});

test("an unstamped message comes back without a time rather than with a guessed one", () => {
  const restored = roundTrip(new Map([["0a0b", thread([text(1)])]])).get("0a0b")?.messages;

  assert.ok(restored);
  assert.ok(!("sentAt" in restored[0]));
});

test("our own messages stay ours", () => {
  const mine = text(1, { mine: true, sender: "alice-laptop" });

  assert.deepEqual(roundTrip(new Map([["0a0b", thread([mine])]])).get("0a0b")?.messages, [mine]);
});

/**
 * The cap is the whole reason this is a window and not a log: `persist` re-serialises everything
 * on every write, so an unbounded thread would make each send cost the entire history.
 */
test("only the tail of a long conversation is kept", () => {
  const long = Array.from({ length: RECENT_PER_CONVERSATION + 50 }, (_, i) => text(i));

  const restored = roundTrip(new Map([["0a0b", thread(long)]]));

  assert.equal(restored.get("0a0b")?.messages.length, RECENT_PER_CONVERSATION);
  // The tail, not the head: what is dropped is the part the vault can fetch back.
  assert.equal(restored.get("0a0b")?.messages[0].seq, 50);
});

test("messages are written in sequence order whatever order they arrived in", () => {
  const shuffled = [text(3), text(1), text(2)];

  assert.deepEqual(
    roundTrip(new Map([["0a0b", thread(shuffled)]])).get("0a0b")?.messages.map((m) => m.seq),
    [1, 2, 3],
  );
});

test("an empty conversation writes no entry at all", () => {
  assert.equal(roundTrip(new Map([["0a0b", thread([])]])).size, 0);
});

test("conversations stay separate", () => {
  const restored = roundTrip(
    new Map([
      ["0a0b", thread([text(1)])],
      ["0c0d", thread([text(9)])],
    ]),
  );

  assert.equal(restored.get("0a0b")?.messages[0].seq, 1);
  assert.equal(restored.get("0c0d")?.messages[0].seq, 9);
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
  const encoded = encodeHistory(new Map([["0a0b", thread([text(1), text(2)])]]));
  const payload = JSON.parse(new TextDecoder().decode(encoded));
  // Type byte 200 is not a content type, so `content.decode` refuses it.
  payload.conversations["0a0b"][0].body = [200, 1, 2];

  const restored = decodeHistory(new TextEncoder().encode(JSON.stringify(payload)));

  assert.deepEqual(restored.get("0a0b")?.messages.map((m) => m.seq), [2]);
});

const queued = (localId: string, state: Pending["state"] = "failed"): Pending => ({
  localId,
  text: "not sent yet",
  sentAt: 1_700_000_000_000,
  state,
});

/** The one thing on this screen a user would be angry to lose. */
test("a queued message survives a reload", () => {
  const restored = roundTrip(new Map([["0a0b", thread([], [queued("a")])]]));

  assert.equal(restored.get("0a0b")?.outbox.length, 1);
  assert.equal(restored.get("0a0b")?.outbox[0].text, "not sent yet");
  assert.equal(restored.get("0a0b")?.outbox[0].sentAt, 1_700_000_000_000);
});

/**
 * A request in flight when the tab closed may or may not have arrived. Saying it did not and
 * letting the user decide beats retrying silently and posting it twice.
 */
test("a message still in flight comes back as failed, not as sending", () => {
  const restored = roundTrip(new Map([["0a0b", thread([], [queued("a", "sending")])]]));

  assert.equal(restored.get("0a0b")?.outbox[0].state, "failed");
});

/** Not a cache: nothing else holds these, so the cap that applies to the thread must not. */
test("the outbox is not trimmed the way the thread is", () => {
  const many = Array.from({ length: RECENT_PER_CONVERSATION + 20 }, (_, i) => queued(`q${i}`));

  assert.equal(
    roundTrip(new Map([["0a0b", thread([], many)]])).get("0a0b")?.outbox.length,
    many.length,
  );
});

test("a conversation with nothing but a queued message is still restored", () => {
  assert.ok(roundTrip(new Map([["0a0b", thread([], [queued("a")])]])).has("0a0b"));
});

test("a malformed queue entry is dropped without taking the others", () => {
  const encoded = encodeHistory(new Map([["0a0b", thread([], [queued("a"), queued("b")])]]));
  const payload = JSON.parse(new TextDecoder().decode(encoded));
  delete payload.outbox["0a0b"][0].text;

  const restored = decodeHistory(new TextEncoder().encode(JSON.stringify(payload)));

  assert.deepEqual(restored.get("0a0b")?.outbox.map((q) => q.localId), ["b"]);
});
