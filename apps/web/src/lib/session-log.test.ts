/**
 * What this device has accepted about the key log.
 *
 * No Merkle proof is built here. `transparency.ts` holds that and has its own tests; what is
 * checked below is the state machine around it — when the anchor moves, when it must not, and
 * which failures reach the caller. Both of the rules that matter are one `if` apart in the same
 * `catch`, and getting either backwards is silent.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { LogWitness, type LogChecks } from "./session-log.ts";
import { LogProofRefused } from "./session-types.ts";
import type { StoredSession } from "./storage";
import type { SeenHead } from "./transparency";

function head(size: number, root = 1): SeenHead {
  return { size, root: new Uint8Array([root]), logKey: new Uint8Array([9]) };
}

/** States verdicts instead of proving them. */
function checks(over: Partial<LogChecks> = {}): LogChecks {
  return {
    account: () => Promise.resolve({ verdict: { ok: true }, head: head(1) }),
    extendsView: () => Promise.resolve({ ok: true }),
    ...over,
  };
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

test("a device that has accepted no head carries none", () => {
  const witness = LogWitness.hydrate(undefined);

  assert.equal(witness.head, undefined);
  assert.equal(witness.gossip(), undefined);
  assert.deepEqual(witness.snapshot(), {});
});

test("what is written is what comes back", async () => {
  const witness = LogWitness.hydrate(undefined);
  await witness.check(checks({ account: () => Promise.resolve({ verdict: { ok: true }, head: head(42, 7) }) }), "bob", new Uint8Array());

  // Base64 on disk and bytes in memory: `JSON.stringify` turns a `Uint8Array` into an object keyed
  // by strings, and an anchor that does not survive a reload is not an anchor.
  const once = witness.snapshot();
  const back = LogWitness.hydrate(stored(once));

  assert.deepEqual(back.snapshot(), once);
  assert.equal(back.head?.size, 42);
  assert.deepEqual(back.head?.root, new Uint8Array([7]));
});

test("the anchor moves only when the log actually grew", async () => {
  const witness = LogWitness.hydrate(stored({ logHead: { size: 5, root: "AQ==", logKey: "CQ==" } }));

  // Same size: the caller must not be told to persist. `persist` re-seals the whole MLS state, and
  // a log only grows when an account is created or a key rotated.
  assert.equal(
    await witness.check(checks({ account: () => Promise.resolve({ verdict: { ok: true }, head: head(5) }) }), "bob", new Uint8Array()),
    false,
  );

  assert.equal(
    await witness.check(checks({ account: () => Promise.resolve({ verdict: { ok: true }, head: head(6) }) }), "bob", new Uint8Array()),
    true,
  );
});

test("a refused proof reaches the caller instead of being deferred", async () => {
  const witness = LogWitness.hydrate(undefined);
  const refusing = checks({
    account: () => Promise.resolve({ verdict: { ok: false, reason: "root mismatch" } }),
  });

  // Swallowing this is what let a conversation open on a key the server had just failed to prove.
  await assert.rejects(
    () => witness.check(refusing, "bob", new Uint8Array()),
    LogProofRefused,
  );
});

test("a refusal is recorded before it is thrown", async () => {
  const witness = LogWitness.hydrate(undefined);
  const refusing = checks({
    account: () => Promise.resolve({ verdict: { ok: false, reason: "root mismatch" } }),
  });

  await witness.check(refusing, "bob", new Uint8Array()).catch(() => {});

  // The alert must survive a caller that catches: it is the signal the apparatus exists to produce.
  assert.deepEqual(witness.alerts, ["root mismatch"]);
});

test("a head we have just refused is not remembered", async () => {
  const witness = LogWitness.hydrate(stored({ logHead: { size: 5, root: "AQ==", logKey: "CQ==" } }));
  const refusing = checks({
    account: () => Promise.resolve({ verdict: { ok: false, reason: "root mismatch" }, head: head(9) }),
  });

  await witness.check(refusing, "bob", new Uint8Array()).catch(() => {});

  // Endorsing it would measure the next log against the attacker's anchor rather than the last
  // honest one.
  assert.equal(witness.head?.size, 5);
});

test("an unreachable log invents no alert and remembers nothing", async () => {
  const witness = LogWitness.hydrate(stored({ logHead: { size: 5, root: "AQ==", logKey: "CQ==" } }));
  const offline = checks({ account: () => Promise.reject(new Error("network")) });

  assert.equal(await witness.check(offline, "bob", new Uint8Array()), false);
  assert.deepEqual(witness.alerts, []);
  assert.equal(witness.head?.size, 5);
});

test("the same anomaly is said once", async () => {
  const witness = LogWitness.hydrate(undefined);
  const refusing = checks({
    account: () => Promise.resolve({ verdict: { ok: false, reason: "root mismatch" } }),
  });

  await witness.check(refusing, "bob", new Uint8Array()).catch(() => {});
  await witness.check(refusing, "carol", new Uint8Array()).catch(() => {});

  assert.equal(witness.alerts.length, 1);
});

test("a log that does not extend a peer's view is an attack, and is said so", async () => {
  const witness = LogWitness.hydrate(undefined);
  const forked = checks({ extendsView: () => Promise.resolve({ ok: false, reason: "no proof" }) });

  await witness.compare(forked, { size: 3, root: new Uint8Array([2]) });

  assert.equal(witness.alerts.length, 1);
  assert.match(witness.alerts[0] ?? "", /that is an attack, not a glitch/);
});

test("an unreachable server is not evidence of a fork", async () => {
  const witness = LogWitness.hydrate(undefined);
  const offline = checks({ extendsView: () => Promise.reject(new Error("network")) });

  await witness.compare(offline, { size: 3, root: new Uint8Array([2]) });

  assert.deepEqual(witness.alerts, []);
});

test("what we tell a peer carries the view, not our copy of the key", async () => {
  const witness = LogWitness.hydrate(stored({ logHead: { size: 5, root: "AQ==", logKey: "CQ==" } }));

  // Sending our log key would offer the peer a value to agree with rather than a claim to check.
  assert.deepEqual(witness.gossip(), { size: 5, root: new Uint8Array([1]) });
});
