import assert from "node:assert/strict";
import { test } from "node:test";

import { NativeStore, type SessionBridge } from "./storage-native.ts";
import type { StoredSession } from "./storage.ts";
import type { DeviceCipher } from "./cipher.ts";

/**
 * A fake cipher, but **not a transparent one**: it shifts every byte.
 *
 * A fake that returned the plaintext would let a store that forgets to seal go through — exactly
 * the failure we want to rule out, since it would write the MLS state to disk in the clear with
 * nothing to signal it.
 */
function fakeCipher(): DeviceCipher & { sawPlaintext: boolean } {
  const shift = (bytes: Uint8Array, direction: number) =>
    Uint8Array.from(bytes, (byte) => (byte + direction + 256) % 256);

  return {
    sawPlaintext: false,
    authPublicKey: () => Promise.resolve(new Uint8Array([1])),
    sign: () => Promise.resolve(""),
    seal: (plaintext) => Promise.resolve(shift(plaintext, 1)),
    open: (blob) => Promise.resolve(shift(blob, -1)),
  };
}

function memoryBridge(): SessionBridge & { content: string | null } {
  return {
    content: null,
    load() {
      return Promise.resolve(this.content);
    },
    save(content: string) {
      this.content = content;
      return Promise.resolve();
    },
    clear() {
      this.content = null;
      return Promise.resolve();
    },
  };
}

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

test("a saved session reads back identically", async () => {
  const bridge = memoryBridge();
  const store = new NativeStore(fakeCipher(), bridge);

  const original = session({
    state: new Uint8Array([9, 8, 7]),
    cursors: { "0a0b": 3 },
    vaultEnabled: false,
  });
  await store.save(original);

  assert.deepEqual(await store.load(), original);
});

/**
 * **The test that carries the property of the module.**
 *
 * What reaches the bridge must give nothing away. The handle is in the clear on the server, but
 * the MLS state is in the clear nowhere — and a store that forgot to seal would write everything
 * to disk without any other test noticing.
 */
test("nothing reaches the disk in the clear", async () => {
  const bridge = memoryBridge();
  await new NativeStore(fakeCipher(), bridge).save(session({ handle: "alice" }));

  assert.ok(bridge.content !== null);
  assert.ok(!atob(bridge.content).includes("alice"), "the content was written unsealed");
});

/** A first launch yields `undefined`, and not an empty session. */
test("a missing file is not a session", async () => {
  assert.equal(await new NativeStore(fakeCipher(), memoryBridge()).load(), undefined);
});

test("clearing leaves the storage blank", async () => {
  const bridge = memoryBridge();
  const store = new NativeStore(fakeCipher(), bridge);

  await store.save(session());
  await store.clear();

  assert.equal(await store.load(), undefined);
});

/**
 * An unreadable blob throws, rather than passing for a fresh install.
 *
 * The two situations call for opposite answers: one creates an account, the other raises an
 * alarm. Confusing them would erase an account instead of reporting a broken disk.
 */
test("a corrupted blob does not pass for a first launch", async () => {
  const bridge = memoryBridge();
  bridge.content = btoa("bytes that are not a session");

  await assert.rejects(() => new NativeStore(fakeCipher(), bridge).load());
});
