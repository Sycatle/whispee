/**
 * The history vault, from the session's side.
 *
 * The property this file exists to protect is not asserted here, because it cannot be broken:
 * `Archive` never receives a `ConversationView`, so no cursor is within its reach. What is
 * asserted is everything else — what it fetches, what it hands back, what it refuses to say, and
 * the one place where failing quietly is the right answer.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { Archive, type VaultApi } from "./session-vault.ts";
import type { Message } from "./session-types.ts";

const GROUP = new Uint8Array([1, 2, 3]);

/** A vault key that imports cleanly under `node --test`: raw AES-GCM material is thirty-two bytes. */
const KEY = new Uint8Array(32).fill(7);

function said(seq: number, text: string): Message {
  return { seq, sender: "bob", mine: false, content: { kind: "text", text } };
}

/** Serves what it was given, and records what it was asked to keep. */
function server(entries: { seq: number; payload: Uint8Array }[] = []): VaultApi & {
  kept: number;
  failing?: boolean;
} {
  return {
    kept: 0,
    fetchVault() {
      return Promise.resolve(entries);
    },
    storeVault(_group: Uint8Array, batch: { seq: number; payload: Uint8Array }[]) {
      if (this.failing) return Promise.reject(new Error("network"));
      this.kept += batch.length;
      return Promise.resolve();
    },
  } as unknown as VaultApi & { kept: number; failing?: boolean };
}

test("an account that turned the vault off archives nothing", async () => {
  const archive = Archive.off();
  const api = server();

  assert.equal(archive.enabled, false);
  await archive.store(api, GROUP, [said(1, "hi")]);

  // Not "tried and failed" — never asked. The setting is honoured before the network, not after.
  assert.equal((api as unknown as { kept: number }).kept, 0);
});

test("an unusable vault key leaves archiving off rather than throwing", async () => {
  // This sits on the opening path of every session now that the vault is on by default. An
  // exception here would make messages inaccessible because their backup failed.
  const archive = await Archive.open(() => new Uint8Array(3));

  assert.equal(archive.enabled, false);
});

test("deriving the key is inside the same net as importing it", async () => {
  // A caller who evaluated the key one line earlier would have moved the derivation outside the
  // `try` without noticing, and the derivation is the half more likely to fail.
  const archive = await Archive.open(() => {
    throw new Error("seed unavailable");
  });

  assert.equal(archive.enabled, false);
});

test("turning it back on reports failure, unlike opening", async () => {
  const archive = Archive.off();

  // The user asked for this one. Telling them it worked when it did not is worse than an error.
  await assert.rejects(() => archive.enable(new Uint8Array(3)));
});

test("turning it off and on again is recorded as a decision either way", async () => {
  const archive = await Archive.open(() => KEY);
  assert.deepEqual(archive.snapshot(), { vaultEnabled: true });

  archive.disable();
  // `false`, not absent: a refusal to honour, distinct from an account that never had to decide.
  assert.deepEqual(archive.snapshot(), { vaultEnabled: false });

  await archive.enable(KEY);
  assert.deepEqual(archive.snapshot(), { vaultEnabled: true });
});

test("a disabled vault restores nothing without asking the server", async () => {
  const archive = Archive.off();

  assert.deepEqual(await archive.restore(server(), GROUP, []), []);
});

test("an archive nobody can read is reported, not served as an empty thread", async () => {
  const archive = await Archive.open(() => KEY);
  // Entries exist and none of them decrypt: the vault key is no longer the right one, which means
  // the account was rotated. An empty thread would look like a conversation nobody ever had.
  const unreadable = server([{ seq: 1, payload: new Uint8Array([0, 1, 2]) }]);

  await assert.rejects(
    () => archive.restore(unreadable, GROUP, []),
    /recovery phrase changed/,
  );
});

test("a conversation with nothing archived is not an error", async () => {
  const archive = await Archive.open(() => KEY);

  // No entries at all is the ordinary case for a fresh group, and distinct from entries that will
  // not open. Only the second is worth interrupting somebody for.
  assert.deepEqual(await archive.restore(server(), GROUP, []), []);
});

test("a failed archive is swallowed, because the message is already delivered", async () => {
  const archive = await Archive.open(() => KEY);
  const api = server();
  (api as unknown as { failing: boolean }).failing = true;

  // Only the backup is missing, and it is retried on the next send. Throwing here would block a
  // conversation over a copy of it.
  await archive.store(api, GROUP, [said(1, "hi")]);
});
