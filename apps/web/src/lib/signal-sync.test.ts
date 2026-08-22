import assert from "node:assert/strict";
import { test } from "node:test";

import { importSyncKey, openSignals, sealSignals } from "./signal-sync.ts";

const KEY = new Uint8Array(32).fill(7);
const OTHER_KEY = new Uint8Array(32).fill(9);

const NOW = 1_700_000_000_000;

const SIGNALS = {
  readReceipts: false,
  typingIndicator: true,
  presence: false,
  at: NOW - 1000,
};

test("the settings round-trip through the seal", async () => {
  const opened = await openSignals(
    await importSyncKey(KEY),
    await sealSignals(await importSyncKey(KEY), SIGNALS),
    NOW,
  );

  assert.deepEqual(opened, SIGNALS);
});

test("each of the three switches survives on its own", async () => {
  const key = await importSyncKey(KEY);

  for (const field of ["readReceipts", "typingIndicator", "presence"] as const) {
    const all = { readReceipts: true, typingIndicator: true, presence: true, at: NOW };
    const one = { ...all, [field]: false };

    // One bit per switch, and a bitfield is exactly where two of them get read into one place.
    assert.deepEqual(await openSignals(key, await sealSignals(key, one), NOW), one);
  }
});

test("a peer cannot read the settings it carries", async () => {
  // The whole reason this is sealed rather than a plain field in the message body: knowing
  // somebody turned their read receipts off is the lever the setting exists to remove.
  const sealed = await sealSignals(await importSyncKey(KEY), SIGNALS);

  assert.equal(await openSignals(await importSyncKey(OTHER_KEY), sealed, NOW), null);
});

test("an unreadable blob is null rather than a throw", async () => {
  // It is the ordinary case, not an error: every peer in the room receives this message.
  const key = await importSyncKey(KEY);

  assert.equal(await openSignals(key, new Uint8Array(0), NOW), null);
  assert.equal(await openSignals(key, new Uint8Array(12), NOW), null);
  assert.equal(await openSignals(key, new Uint8Array(64), NOW), null);
});

test("a time far in the future is replaced by the moment of receipt", async () => {
  // Otherwise a device whose clock is wrong wins last-writer-wins forever, and its owner has no
  // way to see why the setting keeps coming back.
  const key = await importSyncKey(KEY);
  const pinned = { ...SIGNALS, at: NOW + 10 * 365 * 24 * 3600 * 1000 };

  const opened = await openSignals(key, await sealSignals(key, pinned), NOW);
  assert.equal(opened?.at, NOW);
});

test("ordinary clock skew is believed rather than clamped", async () => {
  // Two consumer devices are routinely a minute apart. Clamping that would make the later of the
  // two announcements lose to the earlier one at random.
  const key = await importSyncKey(KEY);
  const skewed = { ...SIGNALS, at: NOW + 60_000 };

  const opened = await openSignals(key, await sealSignals(key, skewed), NOW);
  assert.equal(opened?.at, NOW + 60_000);
});

test("a tampered blob does not open", async () => {
  const sealed = await sealSignals(await importSyncKey(KEY), SIGNALS);
  // The last byte is inside the GCM tag, so flipping it is the cheapest way to prove the tag is
  // actually checked — which is what stops a peer from flipping a switch it cannot read.
  sealed[sealed.length - 1] ^= 0xff;

  assert.equal(await openSignals(await importSyncKey(KEY), sealed, NOW), null);
});
