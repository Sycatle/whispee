/**
 * Everything the user has chosen, and whether it survives being written down.
 *
 * The round trip is the point of this file. `snapshot` and `hydrate` are mirrors, and the failure
 * they exist to prevent is silent: a field written on one side and not read on the other reads
 * back as `undefined` at the next start, with no error, and the user simply finds a setting
 * reverted. While the two halves lived three hundred lines apart in two different files, nothing
 * could ask them whether they agreed.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { PreferencesStore } from "./session-preferences.ts";
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

test("an account that has chosen nothing carries nothing", () => {
  const store = PreferencesStore.hydrate(undefined);

  assert.equal(store.discloseConversationName, false);
  assert.deepEqual(store.value.blocked, []);
  assert.deepEqual(store.value.recentEmojis, []);
  assert.equal(store.value.locale, undefined);
});

test("what is written is what comes back", () => {
  const store = PreferencesStore.hydrate(undefined);
  store.setDisclose(true);
  store.update((preferences) => {
    preferences.blocked = ["mallory"];
    preferences.conversations = { aa: { muted: true } };
    preferences.searchCoverage = { aa: { from: 1, to: 9 } };
    preferences.locale = "fr";
    preferences.contactPolicy = "known";
    preferences.skinTone = 3;
  });
  store.noteEmoji("👍");

  // Written, read back, written again. Any field one half knows and the other does not drops out
  // here, and this is the only place that can see it happen.
  const once = store.snapshot();
  const twice = PreferencesStore.hydrate(stored(once)).snapshot();

  assert.deepEqual(twice, once);
});

test("a choice nobody made stays absent rather than becoming undefined", () => {
  const snapshot = PreferencesStore.hydrate(stored()).snapshot();

  // `in`, not a comparison with `undefined`: the two are indistinguishable to a reader and
  // different to the store, and it is absence that keeps an untouched account on the exact
  // on-disk shape it had before these fields existed.
  assert.equal("locale" in snapshot, false);
  assert.equal("contactPolicy" in snapshot, false);
  assert.equal("skinTone" in snapshot, false);
});

test("the yellow glyph is a choice, not the absence of one", () => {
  // `skinTone: 0` is somebody picking yellow; missing is nobody having been asked. A falsiness
  // test anywhere on this path would conflate them and silently reinstate a later default.
  const snapshot = PreferencesStore.hydrate(stored({ skinTone: 0 })).snapshot();

  assert.equal("skinTone" in snapshot, true);
  assert.equal(snapshot.skinTone, 0);
});

test("the quiet default is only left on an explicit yes", () => {
  assert.equal(PreferencesStore.hydrate(stored()).discloseConversationName, false);
  assert.equal(
    PreferencesStore.hydrate(stored({ discloseConversationName: true })).discloseConversationName,
    true,
  );
  assert.equal(
    PreferencesStore.hydrate(stored({ discloseConversationName: false })).discloseConversationName,
    false,
  );
});

test("a mutator sees the current value, not a copy handed back", () => {
  const store = PreferencesStore.hydrate(undefined);

  // Two callers changing different preferences must not overwrite each other, which is why this
  // takes a mutator rather than a whole object.
  store.update((preferences) => (preferences.blocked = ["mallory"]));
  store.update((preferences) => (preferences.locale = "fr"));

  assert.deepEqual(store.value.blocked, ["mallory"]);
  assert.equal(store.value.locale, "fr");
});

test("an emoji is remembered without its tone, and only once", () => {
  const store = PreferencesStore.hydrate(undefined);

  assert.equal(store.noteEmoji("👍🏽"), true);
  assert.equal(store.noteEmoji("👋"), true);
  assert.equal(store.noteEmoji("👍🏿"), true);

  // One thumb, at the front. Storing the toned forms would fill the list with five variants of the
  // same glyph and push everything else off it.
  assert.deepEqual(store.value.recentEmojis, ["👍", "👋"]);
});

test("a glyph that is nothing but a tone is not worth a write", () => {
  const store = PreferencesStore.hydrate(undefined);

  assert.equal(store.noteEmoji("🏽"), false);
  assert.deepEqual(store.value.recentEmojis, []);
});

test("the list stops at two rows of twelve", () => {
  const store = PreferencesStore.hydrate(undefined);
  for (let i = 0; i < 40; i++) store.noteEmoji(String.fromCodePoint(0x1f600 + i));

  // A longer list is not a longer memory, it is a second grid nobody scrolls.
  assert.equal(store.value.recentEmojis.length, 24);
  assert.equal(store.value.recentEmojis[0], String.fromCodePoint(0x1f600 + 39));
});
