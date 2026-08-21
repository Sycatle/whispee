/**
 * What people are called, and whether it survives being written down.
 *
 * Two of these three fields are keyed by account, which is what makes the round trip below more
 * than a formality: a record written under one key and read under another does not fail, it comes
 * back empty. Names simply vanish and nothing says why. While the two halves of the mapping lived
 * in two different files three hundred lines apart, nothing could ask them whether they agreed.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { Names } from "./session-naming.ts";
import type { StoredSession } from "./storage";

/** A stored session carrying only what this file reads. The rest is required by the type. */
function stored(over: Partial<StoredSession> = {}): StoredSession {
  return {
    deviceId: "alice:laptop",
    handle: "alice",
    accountSeed: new Uint8Array(),
    groupIds: [],
    verified: {},
    cursors: {},
    knownDevices: {},
    ...over,
  };
}

test("an account nobody has named carries nothing", () => {
  const names = Names.hydrate(undefined);

  assert.equal(names.mine, undefined);
  assert.deepEqual(names.profiles, {});
  assert.deepEqual(names.petnames, {});
});

test("what is written is what comes back", () => {
  const names = Names.hydrate(undefined);
  names.setMine("Alice");
  names.setPetname("bob", "the neighbour");
  names.absorb("bob", "Bob", 3);

  // Written, read back, written again. A field one half knows and the other does not drops out
  // here, and this is the only place that can see it happen — which is the point, because the
  // records are keyed by account and a rekey is exactly what would make a read come back empty.
  const once = names.snapshot();
  const twice = Names.hydrate(stored(once)).snapshot();

  assert.deepEqual(twice, once);
  assert.equal(twice.displayName, "Alice");
  assert.deepEqual(twice.petnames, { bob: "the neighbour" });
  assert.deepEqual(twice.profiles, { bob: { name: "Bob", at: 3 } });
});

test("a name nobody has given is absent, not undefined", () => {
  const snapshot = Names.hydrate(stored()).snapshot();

  // Absence is what keeps an account that never named itself on the exact on-disk shape it had
  // before these fields existed, which is what makes an unchanged `VERSION` honest.
  assert.equal("displayName" in snapshot, false);
  assert.equal("profiles" in snapshot, false);
  assert.equal("petnames" in snapshot, false);
});

test("clearing a name removes it rather than storing an empty string", () => {
  const names = Names.hydrate(undefined);
  names.setMine("Alice");
  names.setPetname("bob", "the neighbour");

  names.setMine("   ");
  names.setPetname("bob", "");

  // One representation of "no name". The display falls back on the absence, and two ways to spell
  // it would be two things for every caller to test for.
  assert.equal(names.mine, undefined);
  assert.equal(names.petnames.bob, undefined);
  assert.equal("displayName" in names.snapshot(), false);
  assert.equal("petnames" in names.snapshot(), false);
});

test("a name is judged for what it means, not for what the keyboard put in it", () => {
  const names = Names.hydrate(undefined);

  // Cleaned before it is judged: refusing "Charlie " for a trailing space the user cannot see
  // would be an error message about nothing.
  names.setMine("  Charlie  ");
  assert.equal(names.mine, "Charlie");
});

test("a peer cannot pin its name by dating it far ahead", () => {
  const names = Names.hydrate(undefined);
  names.absorb("bob", "Bob", 10);

  // Last writer wins on the clamped time, and a tie keeps what is stored — so a replayed message
  // is a no-op rather than a flicker.
  assert.equal(names.absorb("bob", "Robert", 5), false);
  assert.equal(names.absorb("bob", "Robert", 10), false);
  assert.equal(names.profiles.bob?.name, "Bob");

  assert.equal(names.absorb("bob", "Robert", 11), true);
  assert.equal(names.profiles.bob?.name, "Robert");
});

test("a declared name that cleans away to nothing removes the entry", () => {
  const names = Names.hydrate(undefined);
  names.absorb("bob", "Bob", 1);

  assert.equal(names.absorb("bob", "   ", 2), true);
  assert.equal("bob" in names.profiles, false);
});

test("a declared name too long to draw is refused, not truncated", () => {
  const names = Names.hydrate(undefined);
  names.absorb("bob", "Bob", 1);

  // Cutting somebody's name to fit would show a name they never chose. The peer keeps the name it
  // last declared legitimately.
  assert.equal(names.absorb("bob", "x".repeat(500), 2), false);
  assert.equal(names.profiles.bob?.name, "Bob");
});

test("a petname is refused on the same grounds as a display name", () => {
  const names = Names.hydrate(undefined);

  // It lands in the same slots of the same layouts: a petname that overflowed a bubble author
  // would be a petname that broke a thread.
  assert.throws(() => names.setPetname("bob", "x".repeat(500)));
  assert.equal("bob" in names.petnames, false);
});

test("forgetting drops every name, ours included", () => {
  const names = Names.hydrate(undefined);
  names.setMine("Alice");
  names.setPetname("bob", "the neighbour");
  names.absorb("bob", "Bob", 1);

  names.forget();

  assert.deepEqual(names.snapshot(), {});
});
