/**
 * What this device has checked, and whether it survives being written down.
 *
 * This is the slice whose round trip matters most, and not for tidiness. `verified` is keyed by
 * account: read under a key it was not written under, it does not fail — it reports every
 * correspondent the user compared out of band as unverified, or worse as *changed*, which raises
 * the banner that exists to announce a server substituting somebody's key. Raised by our own
 * bookkeeping, on somebody who did nothing, it teaches people to click through the one warning the
 * whole verification apparatus exists to produce.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import type { ResolvedAccount } from "./account.ts";
import { TrustStore } from "./session-trust.ts";
import type { StoredSession } from "./storage";

function account(handle: string, fingerprint: string) {
  return { handle, fingerprint } as ResolvedAccount;
}

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

test("what is written is what comes back", () => {
  const trust = TrustStore.hydrate(undefined);
  trust.markVerified(account("bob", "AAAA"));
  trust.noteDevices("bob", ["bob:phone", "bob:laptop"]);

  // The assertion this file exists for. A verification that does not survive the round trip is
  // not a lost convenience: it is a red banner on a correspondent who did nothing.
  const once = trust.snapshot();
  const twice = TrustStore.hydrate(stored(once)).snapshot();

  assert.deepEqual(twice, once);
  assert.equal(twice.verified.bob, "AAAA");
  assert.deepEqual(twice.knownDevices.bob, ["bob:phone", "bob:laptop"]);
});

test("a verification survives being written down and read back", () => {
  const trust = TrustStore.hydrate(undefined);
  trust.markVerified(account("bob", "AAAA"));

  const reopened = TrustStore.hydrate(stored(trust.snapshot()));

  assert.deepEqual(reopened.verificationOf(account("bob", "AAAA")), { status: "verified" });
});

test("a peer nobody compared out of band is unverified", () => {
  const trust = TrustStore.hydrate(undefined);

  assert.deepEqual(trust.verificationOf(account("bob", "AAAA")), { status: "unverified" });
});

test("a fingerprint that moved reports what it used to be", () => {
  const trust = TrustStore.hydrate(stored({ verified: { bob: "AAAA" } }));

  // Keeping the old value — rather than a bare boolean — is the whole point: only the user can
  // tell a recovery from a substitution, and they cannot without being shown both.
  assert.deepEqual(trust.verificationOf(account("bob", "BBBB")), {
    status: "changed",
    previous: "AAAA",
  });
});

test("a session written before these fields existed reads as nothing checked", () => {
  // Not as something checked, and not as something changed. An empty record is the honest reading
  // of an absent one, and it is the only reading that does not invent an alert.
  const trust = TrustStore.hydrate({ ...stored(), verified: undefined, knownDevices: undefined } as
    unknown as StoredSession);

  assert.deepEqual(trust.verificationOf(account("bob", "AAAA")), { status: "unverified" });
  assert.deepEqual(trust.snapshot(), { verified: {}, knownDevices: {} });
});

test("a device nobody had seen before is reported once", () => {
  const trust = TrustStore.hydrate(undefined);
  trust.noteDevices("bob", ["bob:phone"]);

  // A device appearing on a peer is the event that reveals a hostile device legitimately attested
  // by a compromised account — the fingerprint, deliberately stable, does not move for it.
  assert.deepEqual(trust.newDevicesIn("bob", ["bob:phone", "bob:laptop"]), ["bob:laptop"]);
  assert.deepEqual(trust.newDevicesIn("bob", ["bob:phone", "bob:laptop"]), []);
});

test("a peer never seen before has all of its devices reported", () => {
  const trust = TrustStore.hydrate(undefined);

  assert.deepEqual(trust.newDevicesIn("bob", ["bob:phone"]), ["bob:phone"]);
});

test("a device that disappeared is not remembered as new when it returns", () => {
  const trust = TrustStore.hydrate(undefined);
  trust.noteDevices("bob", ["bob:phone", "bob:laptop"]);

  // Nothing is recorded when nothing is new, so the stored list still holds the laptop — a revoked
  // device coming back is not the same event as a device nobody had ever seen.
  assert.deepEqual(trust.newDevicesIn("bob", ["bob:phone"]), []);
  assert.deepEqual(trust.snapshot().knownDevices.bob, ["bob:phone", "bob:laptop"]);
});
