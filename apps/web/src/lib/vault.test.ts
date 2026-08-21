import assert from "node:assert/strict";
import { test } from "node:test";

import type { Message } from "./session.ts";
import { decryptEntry, encryptEntry, importVaultKey, merge, restore, store } from "./vault.ts";
import type { VaultApi } from "./vault.ts";

const GROUP = new Uint8Array([1, 2, 3, 4]);

function key(): Promise<CryptoKey> {
  return importVaultKey(new Uint8Array(32).fill(7));
}

function message(seq: number): Message {
  return { seq, sender: "alice", mine: false, content: { kind: "text", text: `no. ${seq}` } };
}

/** A fake transport: records the batches posted, serves pages on demand. */
function fake(pages: { seq: number; payload: Uint8Array }[][] = []): VaultApi & {
  batches: number[];
  requests: number[];
} {
  const batches: number[] = [];
  const requests: number[] = [];

  return {
    batches,
    requests,
    async storeVault(_groupId, entries) {
      batches.push(entries.length);
      return { stored: entries.length };
    },
    async fetchVault(_groupId, after) {
      requests.push(after);
      return pages.shift() ?? [];
    },
  };
}

test("an archived entry reads back identically", async () => {
  const k = await key();
  const original: Message = {
    seq: 42,
    sender: "bob",
    mine: true,
    content: { kind: "reply", target: 7, text: "agreed" },
  };

  const readBack = await decryptEntry(k, 42, await encryptEntry(k, original));
  assert.deepEqual(readBack, original);
});

/**
 * The vault key derives from the recovery phrase: it **never** changes. AES-GCM fails
 * catastrophically if a nonce is reused under the same key — this is the one place in the project
 * where that rule has no safety net.
 */
test("two encryptions of the same message do not share a nonce", async () => {
  const k = await key();
  const a = await encryptEntry(k, message(1));
  const b = await encryptEntry(k, message(1));

  assert.notDeepEqual([...a.slice(0, 12)], [...b.slice(0, 12)]);
});

/**
 * **The test that prevents the silent 400.** The server rejects any batch of more than two
 * hundred entries; a device catching up on a backlog has far more than that to archive at once.
 */
test("an oversized upload is split into batches the server accepts", async () => {
  const api = fake();
  await store(api, await key(), GROUP, Array.from({ length: 450 }, (_, i) => message(i)));

  assert.deepEqual(api.batches, [200, 200, 50]);
});

test("an empty upload does not talk to the server", async () => {
  const api = fake();
  await store(api, await key(), GROUP, []);

  assert.deepEqual(api.batches, []);
});

/**
 * **The test that prevents silently truncated history.** The server serves at most two hundred
 * rows; without pagination, everything after that vanished without the slightest error.
 */
test("a restore follows the cursor until it runs out", async () => {
  const k = await key();

  const page = async (start: number, size: number) =>
    await Promise.all(
      Array.from({ length: size }, async (_, i) => ({
        seq: start + i,
        payload: await encryptEntry(k, message(start + i)),
      })),
    );

  const api = fake([await page(1, 200), await page(201, 200), await page(401, 30)]);
  const { messages, unreadable } = await restore(api, k, GROUP);

  assert.equal(messages.length, 430);
  assert.equal(unreadable, 0);
  // The cursor resumes from the last `seq` served, never from a local count.
  assert.deepEqual(api.requests, [0, 200, 400]);
});

test("a full page followed by an empty one does not loop forever", async () => {
  const k = await key();
  const full = await Promise.all(
    Array.from({ length: 200 }, async (_, i) => ({
      seq: i + 1,
      payload: await encryptEntry(k, message(i + 1)),
    })),
  );

  const { messages } = await restore(fake([full, []]), k, GROUP);
  assert.equal(messages.length, 200);
});

test("an unreadable entry is counted, not fatal", async () => {
  const k = await key();
  const api = fake([
    [
      { seq: 1, payload: await encryptEntry(k, message(1)) },
      { seq: 2, payload: new Uint8Array(40) },
      { seq: 3, payload: await encryptEntry(k, message(3)) },
    ],
  ]);

  const { messages, unreadable } = await restore(api, k, GROUP);
  assert.deepEqual(messages.map((m) => m.seq), [1, 3]);
  assert.equal(unreadable, 1);
});

test("the merge brings back only what the thread is missing", () => {
  const existing = [message(1), message(2)];
  assert.deepEqual(
    merge(existing, [message(1), message(2), message(3)]).map((m) => m.seq),
    [3],
  );
});
