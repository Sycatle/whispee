/**
 * What the session writes down, and what it deliberately leaves out.
 *
 * These tests exist because the mapping they cover had none, and because its failure mode is
 * silence: a field dropped on the way to disk reads back as `undefined` at the next start, with no
 * error and no symptom until somebody notices their petnames are gone. `Session` itself cannot be
 * reached from here — private constructor, WASM, IndexedDB — which is exactly why the mapping was
 * extracted into `composeStored`.
 *
 * The seal is the identity function throughout. What is under test is which bytes go where, not
 * the cipher, and an identity seal is what lets `history` be decoded back and compared.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeHistory } from "./history.ts";
import { fromBase64 } from "./keys.ts";
import { composeStored, type PersistInput } from "./session-persist.ts";
import { freshPreferences, freshSignalState, type ConversationView } from "./session-types.ts";

const seal = (bytes: Uint8Array): Promise<Uint8Array> => Promise.resolve(bytes);

function view(key: string, over: Partial<ConversationView> = {}): ConversationView {
  return {
    groupId: new Uint8Array([1, 2, 3]),
    key,
    messages: [],
    peers: [],
    accounts: [],
    epoch: 0n,
    cursor: 0,
    mine: new Set<number>(),
    ...freshSignalState(),
    ...over,
  };
}

function input(over: Partial<PersistInput> = {}): PersistInput {
  return {
    deviceId: "alice:laptop",
    handle: "alice",
    accountSeed: new Uint8Array([9, 9]),
    mlsState: new Uint8Array([7, 7, 7]),
    groupIds: [new Uint8Array([1, 2, 3])],
    conversations: new Map(),
    lock: undefined,
    vaultEnabled: true,
    verified: {},
    knownDevices: {},
    signals: { readReceipts: true, typingIndicator: true, presence: true },
    discloseConversationName: false,
    preferences: freshPreferences(),
    displayName: undefined,
    profiles: {},
    petnames: {},
    seenHead: undefined,
    seal,
    ...over,
  };
}

test("the identity and the sealed material land in their fields", async () => {
  const stored = await composeStored(input());

  assert.equal(stored.deviceId, "alice:laptop");
  assert.equal(stored.handle, "alice");
  assert.deepEqual(stored.accountSeed, new Uint8Array([9, 9]));
  assert.deepEqual(stored.state, new Uint8Array([7, 7, 7]));
  assert.deepEqual(stored.groupIds, [new Uint8Array([1, 2, 3])]);
});

test("the account seed, the MLS state and the history are all sealed", async () => {
  const sealed: Uint8Array[] = [];
  await composeStored(
    input({
      seal: (bytes) => {
        sealed.push(bytes);
        return Promise.resolve(bytes);
      },
    }),
  );

  // Three, and not two: forgetting the history would put message text on disk in the clear, and
  // nothing else in the shape would look wrong.
  assert.equal(sealed.length, 3);
});

test("cursors and posting keys are indexed by the view's own key", async () => {
  const conversations = new Map([
    ["aa", view("aa", { cursor: 12, postingKey: new Uint8Array([4, 5]) })],
    ["bb", view("bb", { cursor: 3 })],
  ]);

  const stored = await composeStored(input({ conversations }));

  assert.deepEqual(stored.cursors, { aa: 12, bb: 3 });
  // Only the conversation that has one. A group with no posting key has not migrated to the
  // anonymous path, and writing an empty string for it would claim it had.
  assert.deepEqual(Object.keys(stored.postingKeys ?? {}), ["aa"]);
  assert.deepEqual(fromBase64((stored.postingKeys ?? {}).aa), new Uint8Array([4, 5]));
});

test("the history carries each conversation's thread, outbox and read cursor", async () => {
  const conversations = new Map([
    [
      "aa",
      view("aa", {
        readCursor: 4,
        messages: [{ seq: 1, sender: "bob", mine: false, content: { kind: "text", text: "hi" } }],
        outbox: [{ localId: "x", text: "later", sentAt: 5, state: "failed" }],
      }),
    ],
  ]);

  const stored = await composeStored(input({ conversations }));
  const back = decodeHistory(stored.history as Uint8Array);

  assert.equal(back.get("aa")?.readCursor, 4);
  assert.equal(back.get("aa")?.messages.length, 1);
  assert.deepEqual(back.get("aa")?.outbox, [
    { localId: "x", text: "later", sentAt: 5, state: "failed" },
  ]);
});

test("a name nobody has given is absent, not undefined", async () => {
  const stored = await composeStored(input());

  // `in` rather than a comparison with `undefined`: the two are indistinguishable to a reader and
  // different to the store, and it is absence that keeps an untouched account's on-disk shape
  // exactly what it was before these fields existed.
  assert.equal("displayName" in stored, false);
  assert.equal("profiles" in stored, false);
  assert.equal("petnames" in stored, false);
  assert.equal("locale" in stored, false);
  assert.equal("contactPolicy" in stored, false);
  assert.equal("skinTone" in stored, false);
  assert.equal("logHead" in stored, false);
});

test("a name somebody has given is written", async () => {
  const stored = await composeStored(
    input({
      displayName: "Alice",
      profiles: { bob: { name: "Bob", at: 3 } },
      petnames: { bob: "the neighbour" },
      preferences: {
        ...freshPreferences(),
        locale: "fr",
        contactPolicy: "known",
        skinTone: 0,
      },
    }),
  );

  assert.equal(stored.displayName, "Alice");
  assert.deepEqual(stored.profiles, { bob: { name: "Bob", at: 3 } });
  assert.deepEqual(stored.petnames, { bob: "the neighbour" });
  assert.equal(stored.locale, "fr");
  assert.equal(stored.contactPolicy, "known");
  // Zero is a choice — the yellow glyph — not the absence of one. A falsiness test here would
  // drop it and silently reinstate whatever the default becomes later.
  assert.equal(stored.skinTone, 0);
});

test("the preferences that are always present are copied across", async () => {
  const stored = await composeStored(
    input({
      discloseConversationName: true,
      preferences: {
        conversations: { aa: { muted: true } },
        searchCoverage: { aa: { from: 1, to: 9 } },
        blocked: ["mallory"],
        recentEmojis: ["1f600"],
      },
    }),
  );

  assert.equal(stored.discloseConversationName, true);
  assert.deepEqual(stored.conversationFlags, { aa: { muted: true } });
  assert.deepEqual(stored.searchCoverage, { aa: { from: 1, to: 9 } });
  assert.deepEqual(stored.blocked, ["mallory"]);
  assert.deepEqual(stored.recentEmojis, ["1f600"]);
});

test("a seen log head is written as base64, and only when there is one", async () => {
  const stored = await composeStored(
    input({
      seenHead: { size: 42, root: new Uint8Array([1, 2]), logKey: new Uint8Array([3, 4]) },
    }),
  );

  assert.equal(stored.logHead?.size, 42);
  assert.deepEqual(fromBase64(stored.logHead?.root ?? ""), new Uint8Array([1, 2]));
  assert.deepEqual(fromBase64(stored.logHead?.logKey ?? ""), new Uint8Array([3, 4]));
});

test("turning the vault off is recorded as a decision", async () => {
  // Three values, not two: `false` is a refusal to honour, `undefined` is a fresh account. See
  // `StoredSession.vaultEnabled`.
  assert.equal((await composeStored(input({ vaultEnabled: false }))).vaultEnabled, false);
  assert.equal((await composeStored(input({ vaultEnabled: true }))).vaultEnabled, true);
});
