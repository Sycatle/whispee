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
  calls: true,
  at: NOW - 1000,
};

test("the settings round-trip through the seal", async () => {
  const opened = await openSignals(
    await importSyncKey(KEY),
    await sealSignals(await importSyncKey(KEY), SIGNALS),
    NOW,
  );

  assert.deepEqual(opened?.signals, SIGNALS);
  // Nothing after the fixed head is an older device with no preferences to send — which is not
  // the same as a device asking to clear them.
  assert.equal(opened?.preferences, undefined);
});

test("each of the four switches survives on its own", async () => {
  const key = await importSyncKey(KEY);

  for (const field of ["readReceipts", "typingIndicator", "presence", "calls"] as const) {
    const all = {
      readReceipts: true,
      typingIndicator: true,
      presence: true,
      calls: true,
      at: NOW,
    };
    const one = { ...all, [field]: false };

    // One bit per switch, and a bitfield is exactly where two of them get read into one place.
    assert.deepEqual((await openSignals(key, await sealSignals(key, one), NOW))?.signals, one);
  }
});

/**
 * **The bit that reads backwards, and the test that says why.**
 *
 * A device built before calls existed announces a byte with every bit above the third clear, and
 * it announces it whenever any *other* setting changes. Were the call bit to mean "on", that
 * device would silently switch calls off across the account — a feature turned off by a client
 * that has never heard of it.
 */
test("a settings byte from a client that predates calls leaves them on", async () => {
  const key = await importSyncKey(KEY);
  const before = { readReceipts: true, typingIndicator: true, presence: true, at: NOW };

  // Exactly the byte such a client writes: the three bits it knows, and nothing else.
  const opened = await openSignals(key, await sealSignals(key, { ...before, calls: true }), NOW);

  assert.equal(opened?.calls, true);
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
  assert.equal(opened?.signals.at, NOW);
});

test("ordinary clock skew is believed rather than clamped", async () => {
  // Two consumer devices are routinely a minute apart. Clamping that would make the later of the
  // two announcements lose to the earlier one at random.
  const key = await importSyncKey(KEY);
  const skewed = { ...SIGNALS, at: NOW + 60_000 };

  const opened = await openSignals(key, await sealSignals(key, skewed), NOW);
  assert.equal(opened?.signals.at, NOW + 60_000);
});

test("a tampered blob does not open", async () => {
  const sealed = await sealSignals(await importSyncKey(KEY), SIGNALS);
  // The last byte is inside the GCM tag, so flipping it is the cheapest way to prove the tag is
  // actually checked — which is what stops a peer from flipping a switch it cannot read.
  sealed[sealed.length - 1] ^= 0xff;

  assert.equal(await openSignals(await importSyncKey(KEY), sealed, NOW), null);
});

const PREFERENCES = {
  scalars: { at: NOW - 500, disclose: true, vault: false },
  flags: { aa: { at: NOW - 400, v: { pinned: true, mutedUntil: NOW + 60_000 } } },
  petnames: { cc33453670c79bf3fa37635c08c8a677: { at: NOW - 300, v: "Le voisin" } },
  blocked: { a8f8e14c20e4efd81117d54bb95c96f2: { at: NOW - 200, v: true as const } },
};

test("the preferences round-trip alongside the settings", async () => {
  const key = await importSyncKey(KEY);
  const opened = await openSignals(key, await sealSignals(key, SIGNALS, PREFERENCES), NOW);

  assert.deepEqual(opened?.signals, SIGNALS);
  assert.deepEqual(opened?.preferences, PREFERENCES);
});

test("a peer cannot read the preferences either", async () => {
  // They are notes about people — petnames and blocks — carried by the very people they name.
  const sealed = await sealSignals(await importSyncKey(KEY), SIGNALS, PREFERENCES);

  assert.equal(await openSignals(await importSyncKey(OTHER_KEY), sealed, NOW), null);
});

test("every stamp in the preferences is clamped, not only the scalars'", async () => {
  // A device whose clock is wrong would otherwise pin one petname or one block for ever, and its
  // owner would have no way to see why the entry keeps coming back.
  const key = await importSyncKey(KEY);
  const far = NOW + 10 * 365 * 24 * 3600 * 1000;
  const pinned = {
    scalars: { at: far, disclose: true, vault: true },
    flags: { aa: { at: far, v: { pinned: true } } },
    petnames: { bb: { at: far, v: "Pinned" } },
    blocked: { cc: { at: far, v: true as const } },
  };

  const opened = await openSignals(key, await sealSignals(key, SIGNALS, pinned), NOW);

  assert.equal(opened?.preferences?.scalars.at, NOW);
  assert.equal(opened?.preferences?.flags.aa.at, NOW);
  assert.equal(opened?.preferences?.petnames.bb.at, NOW);
  assert.equal(opened?.preferences?.blocked.cc.at, NOW);
});

test("a removal survives the round trip as a removal, not as an absence", async () => {
  const key = await importSyncKey(KEY);
  const tombstoned = { ...PREFERENCES, blocked: { bob: { at: NOW - 100, v: null } } };

  const opened = await openSignals(key, await sealSignals(key, SIGNALS, tombstoned), NOW);
  assert.deepEqual(opened?.preferences?.blocked, { bob: { at: NOW - 100, v: null } });
});

test("a malformed preference set is dropped without taking the settings with it", async () => {
  // Losing one message's preferences is cheap — they are re-announced at every epoch. Letting a
  // shape we do not recognise through to the merge is not: the merge writes to disk, and every
  // other device would then be told the corrupt version is the newer one.
  const key = await importSyncKey(KEY);

  for (const broken of [
    { ...PREFERENCES, scalars: { at: NOW, disclose: "yes", vault: false } },
    { ...PREFERENCES, flags: { aa: { at: NOW, v: { pinned: "true" } } } },
    { ...PREFERENCES, petnames: { bb: { at: "soon", v: "x" } } },
    { ...PREFERENCES, blocked: { cc: { at: NOW, v: "true" } } },
    { ...PREFERENCES, scalars: undefined },
  ]) {
    const sealed = await sealSignals(key, SIGNALS, broken as never);
    const opened = await openSignals(key, sealed, NOW);

    assert.deepEqual(opened?.signals, SIGNALS, "the settings were lost with the preferences");
    assert.equal(opened?.preferences, undefined);
  }
});

test("an unknown flag from a later build does not throw the conversation away", async () => {
  // Otherwise every upgrade is a synchronisation outage for whoever upgrades second.
  const key = await importSyncKey(KEY);
  const ahead = { ...PREFERENCES, flags: { aa: { at: NOW, v: { pinned: true, folded: true } } } };

  const opened = await openSignals(key, await sealSignals(key, SIGNALS, ahead as never), NOW);
  assert.equal(opened?.preferences?.flags.aa.v?.pinned, true);
});

test("a snapshot past the ceiling is refused on the way out", async () => {
  // Refused rather than truncated: half a preference set reads as a decision to clear the half
  // that fell off the end.
  const key = await importSyncKey(KEY);
  const huge = {
    ...PREFERENCES,
    petnames: Object.fromEntries(
      Array.from({ length: 2000 }, (_, i) => [`account${i}`, { at: NOW, v: "a name that is long" }]),
    ),
  };

  await assert.rejects(() => sealSignals(key, SIGNALS, huge));
});
