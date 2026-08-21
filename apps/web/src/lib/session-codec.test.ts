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
  });

  assert.deepEqual(roundTrip(original), original);
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
