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

test("a display name round-trips with the moment it was set", () => {
  const at = Date.now() - 1000;
  const decoded = decode(encode({ kind: "profile", name: "Charlie", at }));

  assert.deepEqual(decoded, { body: { kind: "profile", name: "Charlie", at } });
});

/**
 * The name is control traffic, which is what buys it the three things it needs at once: no bubble
 * in the thread, nothing archived to the vault, and no movement of the receipt cursor. The stamp
 * it gives up in exchange is the reason it carries its own eight bytes.
 */
test("a display name is protocol traffic and is never wrapped in a stamp", () => {
  assert.equal(isControl({ kind: "profile", name: "Charlie", at: 1 }), true);
  assert.deepEqual(
    encode({ kind: "profile", name: "Charlie", at: 1 }, 999),
    encode({ kind: "profile", name: "Charlie", at: 1 }),
  );
});

/**
 * The self-declared clock is worth exactly what the stamp of a text message is worth: nothing. A
 * member who dates their rename far ahead would win last-writer-wins against every update they
 * ever make afterwards, and their name would be frozen with nothing on screen to say why.
 */
test("a profile timestamp in the future is clamped to the receiving clock", () => {
  const before = Date.now();
  const decoded = decode(encode({ kind: "profile", name: "Charlie", at: 4_102_444_800_000 }));
  const after = Date.now();

  assert.equal(decoded.body.kind, "profile");
  if (decoded.body.kind !== "profile") return;
  assert.ok(decoded.body.at >= before);
  assert.ok(decoded.body.at <= after);
});

/** Ordinary skew between two consumer devices is not an attack, and must not cost a rename. */
test("a profile timestamp a little ahead of us is believed", () => {
  const at = Date.now() + 60_000;
  const decoded = decode(encode({ kind: "profile", name: "Charlie", at }));

  assert.deepEqual(decoded.body, { kind: "profile", name: "Charlie", at });
});

test("a display name over sixty-four bytes is refused rather than sent", () => {
  assert.throws(() => encode({ kind: "profile", name: "\u{1F642}".repeat(17), at: 1 }));
});

test("a truncated profile timestamp is rejected rather than interpreted", () => {
  const complete = encode({ kind: "profile", name: "Charlie", at: 1 });
  assert.throws(() => decode(complete.subarray(0, 5)));
});

/** A name arriving over the wire is bounded on the way in too: the sender is not to be trusted. */
test("a profile carrying an oversized name is rejected on decode", () => {
  const oversized = new Uint8Array(1 + 8 + 65);
  oversized[0] = 8;
  oversized.fill(0x61, 9);

  assert.throws(() => decode(oversized));
});

test("a membership notice round-trips, for each event", () => {
  for (const event of ["joined", "removed", "left"] as const) {
    const decoded = decode(encode({ kind: "membership", event, handle: "charlie8295" }));
    assert.deepEqual(decoded, { body: { kind: "membership", event, handle: "charlie8295" } });
  }
});

test("a membership notice is not control, so it is shown, archived and counted", () => {
  // The whole point is that it appears in the thread. Were it control it would be silently
  // dropped from the display, from the vault, and from the unread count — three failures with
  // one cause and no error anywhere.
  assert.equal(isControl({ kind: "membership", event: "joined", handle: "charlie8295" }), false);
});

test("a membership notice keeps its timestamp", () => {
  // Being non-control is what earns the stamp: the line sits in the thread among messages, and
  // one line without an hour in a column of them is the odd one out.
  const at = new Date("2024-03-04T12:00:00Z").getTime();
  const decoded = decode(encode({ kind: "membership", event: "left", handle: "dana4417" }, at));

  assert.equal(decoded.sentAt, at);
  assert.deepEqual(decoded.body, { kind: "membership", event: "left", handle: "dana4417" });
});

test("an unknown membership event is refused rather than drawn with a blank verb", () => {
  // A newer client saying something this one cannot render. The alternative to throwing is a
  // sentence with a hole in it, which reads as a bug in the conversation rather than in the app.
  const forged = new Uint8Array([10, 99, ...new TextEncoder().encode("charlie8295")]);
  assert.throws(() => decode(forged), /unknown membership event/);
});

test("a call event round-trips, for each event", () => {
  for (const event of ["invite", "ended", "missed"] as const) {
    const body = { kind: "call", event, call: "9f2c41ab7d0e5638", seconds: 197 } as const;
    assert.deepEqual(decode(encode(body)), { body });
  }
});

test("a call event is not control: a missed call has to be visible", () => {
  // Control would drop it from the thread, from the vault and from the unread count — which is
  // to say, a call nobody answered would leave no trace at all.
  assert.equal(isControl({ kind: "call", event: "missed", call: "9f2c", seconds: 0 }), false);
});

test("a call keeps its timestamp", () => {
  const at = new Date("2024-03-04T12:00:00Z").getTime();
  const decoded = decode(encode({ kind: "call", event: "ended", call: "9f2c", seconds: 61 }, at));

  assert.equal(decoded.sentAt, at);
  assert.deepEqual(decoded.body, { kind: "call", event: "ended", call: "9f2c", seconds: 61 });
});

test("a call longer than a day keeps its duration", () => {
  // Seconds in a `u32`: the field overflows after a hundred and thirty-six years, which is the
  // right kind of margin for a number that is only ever read as a duration.
  const seconds = 60 * 60 * 30;
  const decoded = decode(encode({ kind: "call", event: "ended", call: "9f2c", seconds }));

  assert.deepEqual(decoded.body, { kind: "call", event: "ended", call: "9f2c", seconds });
});

test("an unknown call event is refused rather than drawn with a blank verb", () => {
  const forged = new Uint8Array([13, 99, 0, 0, 0, 0, ...new TextEncoder().encode("9f2c")]);
  assert.throws(() => decode(forged), /unknown call event/);
});

test("a truncated call event is refused rather than read past its end", () => {
  assert.throws(() => decode(new Uint8Array([13, 0, 0, 0])), /truncated call event/);
});

test("a handle with an astral character survives the round trip", () => {
  // The subject is somebody else's handle: it is not our string to assume anything about.
  const handle = "dana\u{1F600}4417";
  const decoded = decode(encode({ kind: "membership", event: "removed", handle }));
  assert.deepEqual(decoded.body, { kind: "membership", event: "removed", handle });
});

test("a sealed settings blob round-trips untouched", () => {
  const sealed = new Uint8Array(12 + 16 + 9).map((_, i) => i);
  const decoded = decode(encode({ kind: "signals", sealed }));

  assert.deepEqual(decoded, { body: { kind: "signals", sealed } });
});

test("settings are control, so they draw no bubble and move no receipt cursor", () => {
  // The third of those three is what would bite: an acknowledged settings message would be
  // acknowledged by a message, and two devices would trade acknowledgements forever.
  assert.equal(isControl({ kind: "signals", sealed: new Uint8Array(28) }), true);
});

test("settings are never stamped, even when a time is passed", () => {
  const sealed = new Uint8Array(28);
  assert.deepEqual(encode({ kind: "signals", sealed }, 1_700_000_000_000), encode({ kind: "signals", sealed }));
});

test("a settings blob too short to be a sealed anything is refused on both sides", () => {
  // Twelve bytes of nonce and sixteen of tag: nothing shorter can have been sealed at all, and
  // catching it here is what keeps the failure from surfacing inside WebCrypto with no name on it.
  assert.throws(() => encode({ kind: "signals", sealed: new Uint8Array(27) }));

  const truncated = new Uint8Array(1 + 27);
  truncated[0] = 12;
  assert.throws(() => decode(truncated));
});

test("an oversized settings blob is refused rather than allocated", () => {
  const huge = new Uint8Array(1 + 12 + 16 + 129);
  huge[0] = 12;

  assert.throws(() => decode(huge));
  assert.throws(() => encode({ kind: "signals", sealed: new Uint8Array(12 + 16 + 129) }));
});

test("an expiry notice survives the round trip", () => {
  const encoded = encode({ kind: "expiry", seconds: 604800 });
  const decoded = decode(encoded);

  assert.deepEqual(decoded.body, { kind: "expiry", seconds: 604800 });
});

test("turning it off is a notice too, and is not an absent one", () => {
  const decoded = decode(encode({ kind: "expiry", seconds: 0 }));

  assert.deepEqual(decoded.body, { kind: "expiry", seconds: 0 });
});

test("an expiry notice is not control, so the room sees its memory change", () => {
  assert.equal(isControl({ kind: "expiry", seconds: 604800 }), false);
});

test("a body of the wrong length is refused, as the other fixed-width bodies are", () => {
  const truncated = new Uint8Array([14, 0, 0, 0]);
  assert.throws(() => decode(truncated));
});
