/**
 * The local lock, as policy.
 *
 * None of these tests derives a key. The real derivation is Argon2id inside the WASM module and
 * the biometric store is Tauri IPC, neither of which `node --test` can load — which is why the
 * operations arrive as a port. What is checked here is the set of rules that a wrong
 * implementation would break silently: that a lock cannot be removed without its password, that a
 * key kept for biometrics does not outlive the lock that justified it, that the signing cipher
 * never moves.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import type { DeviceCipher } from "./cipher";
import type { LockEnvelope } from "./lock";
import { Lockbox, LockedSession, type LockKit } from "./session-lock.ts";

const SIGNING = { name: "signing" } as unknown as DeviceCipher;
const ENVELOPE = { salt: "AAAA" } as unknown as LockEnvelope;
const MASTER = { name: "master" } as unknown as CryptoKey;

/** A kit that records what it was asked, and can be told to refuse a password. */
function kit(over: Partial<LockKit> = {}) {
  const calls: string[] = [];
  const base: LockKit = {
    create(password) {
      calls.push(`create:${password}`);
      return Promise.resolve([ENVELOPE, MASTER]);
    },
    open(_envelope, password) {
      calls.push(`open:${password}`);
      return password === "right" ? Promise.resolve(MASTER) : Promise.reject(new Error("wrong"));
    },
    rekey(_envelope, current, next) {
      calls.push(`rekey:${current}->${next}`);
      return Promise.resolve({ salt: "BBBB" } as unknown as LockEnvelope);
    },
    wrap(signing, master) {
      calls.push("wrap");
      return { name: "sealed", signing, master } as unknown as DeviceCipher;
    },
    keepBiometric() {
      calls.push("keepBiometric");
      return Promise.resolve();
    },
    dropBiometric() {
      calls.push("dropBiometric");
      return Promise.resolve();
    },
    ...over,
  };
  return { kit: base, calls };
}

test("a device with no lock seals with the key that signs", async () => {
  const { kit: k } = kit();
  const box = await Lockbox.open(k, SIGNING, {});

  assert.equal(box.engaged, false);
  assert.equal(box.cipher, SIGNING);
  assert.deepEqual(box.snapshot(), { lock: undefined });
});

test("a locked session with nothing to open it says so in its own type", async () => {
  const { kit: k } = kit();

  // A distinct type rather than a message: the caller has to tell "ask for a password" from
  // "that password was wrong", and those want different screens.
  await assert.rejects(() => Lockbox.open(k, SIGNING, { lock: ENVELOPE }), LockedSession);
});

test("a wrong password does not open a stored session", async () => {
  const { kit: k } = kit();

  await assert.rejects(() => Lockbox.open(k, SIGNING, { lock: ENVELOPE }, "wrong"), /wrong/);
});

test("biometrics hand the key over directly, without a password", async () => {
  const { kit: k, calls } = kit();
  const box = await Lockbox.open(k, SIGNING, { lock: ENVELOPE }, MASTER);

  assert.equal(box.engaged, true);
  assert.notEqual(box.cipher, SIGNING);
  // No derivation: uniting the two paths behind a string would mean encoding a key as text.
  assert.equal(
    calls.some((call) => call.startsWith("open:")),
    false,
  );
});

test("setting a lock swaps what seals and never what signs", async () => {
  const { kit: k } = kit();
  const box = Lockbox.none(k, SIGNING);

  await box.enable("right");

  assert.equal(box.engaged, true);
  assert.notEqual(box.cipher, SIGNING);
  // The server authenticates requests against the signing key and must see no difference between
  // a locked device and an unlocked one.
  assert.equal((box.cipher as unknown as { signing: DeviceCipher }).signing, SIGNING);
});

test("a second lock is refused rather than silently replacing the first", async () => {
  const { kit: k } = kit();
  const box = Lockbox.none(k, SIGNING);
  await box.enable("right");

  await assert.rejects(() => box.enable("other"), /already set/);
});

test("removing a lock requires its password", async () => {
  const { kit: k } = kit();
  const box = await Lockbox.open(k, SIGNING, { lock: ENVELOPE }, "right");

  // Without this, anyone who finds an unlocked device disarms it for good in one click.
  await assert.rejects(() => box.disable("wrong"), /wrong/);
  assert.equal(box.engaged, true);
  assert.notEqual(box.cipher, SIGNING);
});

test("a refused removal leaves a working lock, not a half-removed one", async () => {
  const { kit: k } = kit();
  const box = await Lockbox.open(k, SIGNING, { lock: ENVELOPE }, "right");

  await box.disable("wrong").catch(() => {});

  assert.deepEqual(box.snapshot(), { lock: ENVELOPE });
});

test("removing a lock takes the biometric key with it", async () => {
  const { kit: k, calls } = kit();
  const box = await Lockbox.open(k, SIGNING, { lock: ENVELOPE }, "right");

  await box.disable("right");

  assert.equal(box.engaged, false);
  assert.equal(box.cipher, SIGNING);
  // A key kept for biometrics has nothing left to open, and leaving it would be worse than
  // useless: it would outlive the lock that justified it.
  assert.equal(calls.includes("dropBiometric"), true);
});

test("a biometric store that fails does not block the removal", async () => {
  const { kit: k } = kit({ dropBiometric: () => Promise.reject(new Error("no such device")) });
  const box = await Lockbox.open(k, SIGNING, { lock: ENVELOPE }, "right");

  await box.disable("right");

  assert.equal(box.engaged, false);
});

test("biometrics are refused when there is no key to keep", async () => {
  const { kit: k } = kit();
  const box = Lockbox.none(k, SIGNING);

  await assert.rejects(() => box.enableBiometric(), /Set a lock first/);
});

test("biometrics keep the master key of the lock that is set", async () => {
  const { kit: k, calls } = kit();
  const box = Lockbox.none(k, SIGNING);
  await box.enable("right");

  await box.enableBiometric();

  assert.equal(calls.includes("keepBiometric"), true);
});

test("changing the password re-seals the key and leaves the state alone", async () => {
  const { kit: k, calls } = kit();
  const box = await Lockbox.open(k, SIGNING, { lock: ENVELOPE }, "right");
  const before = box.cipher;

  await box.changePassword("right", "next");

  assert.equal(calls.includes("rekey:right->next"), true);
  // The sealing cipher does not change: the master key behind it is the same one, and the state —
  // several kilobytes, growing with the conversations — never goes back through memory in the
  // clear at the most delicate moment.
  assert.equal(box.cipher, before);
  assert.notDeepEqual(box.snapshot().lock, ENVELOPE);
});

test("there is no password to change when no lock is set", async () => {
  const { kit: k } = kit();

  await assert.rejects(() => Lockbox.none(k, SIGNING).changePassword("a", "b"), /No lock/);
});
