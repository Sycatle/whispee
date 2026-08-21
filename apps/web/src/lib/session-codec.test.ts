import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeSession, encodeSession } from "./session-codec.ts";
import type { StoredSession } from "./storage.ts";

function session(extra: Partial<StoredSession> = {}): StoredSession {
  return {
    deviceId: "device-1",
    handle: "alice",
    accountSeed: new Uint8Array([1, 2, 3, 4]),
    groupIds: [],
    verified: {},
    cursors: {},
    knownDevices: {},
    ...extra,
  };
}

const roundTrip = (value: StoredSession) => decodeSession(encodeSession(value));

test("a complete session reads back identically", () => {
  const original = session({
    lock: { salt: "c2Vs", wrapped: "Y2xl" },
    vaultEnabled: true,
    state: new Uint8Array([9, 8, 7]),
    groupIds: [new Uint8Array([1]), new Uint8Array([2, 3])],
    verified: { bob: "fingerprint" },
    cursors: { "0a0b": 42 },
    knownDevices: { bob: ["device-2"] },
    signals: { readReceipts: true, typingIndicator: false, presence: true },
    postingKeys: { "0a0b": "key" },
    logHead: { size: 7, root: "cm9vdA==", logKey: "a2V5" },
  });

  assert.deepEqual(roundTrip(original), original);
});

/**
 * The anchor is the only thing that makes a consistency proof mean anything, and a codec that
 * dropped it would put the client back where it was: accepting, on every start, any log that is
 * merely consistent with itself. The failure would be invisible — the application works, the
 * proof just stops proving.
 */
test("the log anchor survives the round trip", () => {
  const anchored = session({ logHead: { size: 12, root: "cm9vdA==", logKey: "a2V5" } });

  assert.deepEqual(roundTrip(anchored).logHead, anchored.logHead);
});

/** A session written before the anchor existed has none, and must not gain an empty one. */
test("a session with no anchor reads back without one", () => {
  assert.ok(!("logHead" in roundTrip(session())));
});

/**
 * **The test that carries the property of the module.**
 *
 * Absent means enabled, `false` is a refusal. Confusing the two would switch history backup back
 * on behind the back of someone who had turned it off — with nothing on screen to say so.
 */
test("vaultEnabled tells absence apart from refusal", () => {
  const fresh = roundTrip(session());
  assert.equal(fresh.vaultEnabled, undefined);
  // Absent, and not present with the value `undefined`: the session read back must have exactly
  // the shape of the one written, or a structural comparison or an `in` would answer wrong.
  assert.ok(!("vaultEnabled" in fresh));
  assert.equal(roundTrip(session({ vaultEnabled: false })).vaultEnabled, false);
  assert.equal(roundTrip(session({ vaultEnabled: true })).vaultEnabled, true);
});

/** The same distinction, one notch lower: an absent `presence` means enabled. */
test("presence tells absence apart from refusal", () => {
  const without = roundTrip(session({ signals: { readReceipts: true, typingIndicator: true } }));
  assert.equal(without.signals?.presence, undefined);

  const refused = roundTrip(
    session({ signals: { readReceipts: true, typingIndicator: true, presence: false } }),
  );
  assert.equal(refused.signals?.presence, false);
});

/**
 * Bytes survive past 127.
 *
 * The encoding goes through `String.fromCharCode` then `btoa`: a byte handled as a UTF-16 code
 * point would break above 127. The account seed is random, so half of its bytes fall in that
 * range — the failure would be immediate and total, but only in production.
 */
test("high bytes pass through intact", () => {
  const seed = new Uint8Array(256).map((_, i) => i);
  assert.deepEqual(roundTrip(session({ accountSeed: seed })).accountSeed, seed);
});

/** An absent state is not an empty state: the first one means "no MLS yet". */
test("an absent state stays distinct from an empty one", () => {
  assert.equal(roundTrip(session()).state, undefined);
  assert.deepEqual(roundTrip(session({ state: new Uint8Array() })).state, new Uint8Array());
});

test("an unknown version is rejected", () => {
  const future = new TextEncoder().encode(JSON.stringify({ v: 99, deviceId: "x" }));
  assert.throws(() => decodeSession(future), /version 99/);
});

/**
 * A missing required field throws, rather than yielding an amputated session.
 *
 * A lost cursor replays MLS keys that were already consumed: the conversation stays empty after a
 * reload, with no error to explain it.
 */
test("a missing required field throws", () => {
  const bytes = encodeSession(session());
  const raw = JSON.parse(new TextDecoder().decode(bytes));
  delete raw.cursors;

  assert.throws(
    () => decodeSession(new TextEncoder().encode(JSON.stringify(raw))),
    /cursors/,
  );
});

/**
 * The fields added for pinning, muting, language, search coverage and contact policy are all
 * optional, and none of them raised `VERSION`. That is the contract this test pins down: a
 * session written before they existed has to keep opening, or the upgrade costs everyone their
 * identity.
 */
test("a session written before the preference fields existed still reads back", () => {
  const original = session({ cursors: { "0a0b": 3 } });
  const restored = roundTrip(original);

  assert.deepEqual(restored, original);
  assert.equal("conversationFlags" in restored, false);
  assert.equal("locale" in restored, false);
  assert.equal("blocked" in restored, false);
});

test("conversation flags survive a round trip through the native codec", () => {
  const original = session({
    conversationFlags: {
      "0a0b": { pinned: true, mutedUntil: 1_700_000_000_000 },
      "0c0d": { archived: true, ephemeralMs: 86_400_000 },
    },
  });

  assert.deepEqual(roundTrip(original), original);
});

/**
 * Three states, not two. "Never chosen" has to stay distinguishable from "chosen to match the
 * current default", or changing the default later silently overrides somebody's decision.
 */
test("an absent locale is not turned into a present undefined", () => {
  const restored = roundTrip(session());

  assert.equal("locale" in restored, false);
  assert.equal(restored.locale, undefined);
});

test("a locale that was chosen comes back as the same string", () => {
  assert.equal(roundTrip(session({ locale: "fr" })).locale, "fr");
});

test("search coverage records the range each conversation was indexed over", () => {
  const original = session({ searchCoverage: { "0a0b": { from: 1, to: 200 } } });

  assert.deepEqual(roundTrip(original).searchCoverage, { "0a0b": { from: 1, to: 200 } });
});

test("a blocked handle that is not a string is refused rather than stored", () => {
  const raw = JSON.parse(new TextDecoder().decode(encodeSession(session()))) as Record<
    string,
    unknown
  >;
  raw.blocked = ["bob", 7];

  assert.throws(() => decodeSession(new TextEncoder().encode(JSON.stringify(raw))), /blocked\[1\]/);
});

test("the contact policy is a cache of the server's answer and round trips as one", () => {
  assert.equal(roundTrip(session({ contactPolicy: "known" })).contactPolicy, "known");
});

test("the emoji preferences survive the native codec", () => {
  const restored = roundTrip(session({ recentEmojis: ["👍", "🎉"], skinTone: 3 }));

  assert.deepEqual(restored.recentEmojis, ["👍", "🎉"]);
  assert.equal(restored.skinTone, 3);
});

test("a chosen yellow skin tone is not confused with never having chosen", () => {
  // `0` is a decision — the yellow glyph — and absence is the lack of one. A codec that
  // normalised either way would claim something the reader never said.
  const chosen = roundTrip(session({ skinTone: 0 }));
  const never = roundTrip(session());

  assert.equal(chosen.skinTone, 0);
  assert.ok("skinTone" in chosen);
  assert.ok(!("skinTone" in never));
});
