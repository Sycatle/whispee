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
import { freshSignalState, type ConversationView } from "./session-types.ts";

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
    trust: { verified: {}, knownDevices: {} },
    signals: { readReceipts: true, typingIndicator: true, presence: true },
    preferences: {},
    names: {},
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

test("a log head nobody has accepted is absent, not undefined", async () => {
  const stored = await composeStored(input());

  // `in` rather than a comparison with `undefined`: the two are indistinguishable to a reader and
  // different to the store, and it is absence that keeps an untouched account's on-disk shape
  // exactly what it was before this field existed.
  assert.equal("logHead" in stored, false);
});

test("the names slice is spread in exactly as given", async () => {
  // `composeStored` no longer knows what a name is: `Names` owns that mapping in both directions,
  // and `session-naming.test.ts` is where the round trip is asserted.
  const stored = await composeStored(
    input({ names: { displayName: "Alice", petnames: { bob: "the neighbour" } } }),
  );

  assert.equal(stored.displayName, "Alice");
  assert.deepEqual(stored.petnames, { bob: "the neighbour" });
  assert.equal("profiles" in stored, false);
});

test("the preferences slice is spread in exactly as given", async () => {
  // `composeStored` no longer knows what a preference is: `PreferencesStore` owns that mapping in
  // both directions, and `session-preferences.test.ts` is where the round trip is asserted. What
  // is checked here is only that the slice arrives whole and overrides nothing else.
  const stored = await composeStored(
    input({
      preferences: { discloseConversationName: true, locale: "fr", blocked: ["mallory"] },
    }),
  );

  assert.equal(stored.discloseConversationName, true);
  assert.equal(stored.locale, "fr");
  assert.deepEqual(stored.blocked, ["mallory"]);
  assert.equal(stored.handle, "alice");
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
