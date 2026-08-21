import assert from "node:assert/strict";
import { test } from "node:test";

import { decide, migrate, PropagationIncomplete, type Steps } from "./migration.ts";

const web = { handle: "alice" };
const native = { handle: "alice" };

test("nothing stored: the install is fresh", () => {
  assert.deepEqual(decide(undefined, undefined), { kind: "fresh" });
});

test("a native session alone: the migration is over", () => {
  assert.deepEqual(decide(undefined, native), { kind: "native" });
});

test("a web session alone: the migration is still to do", () => {
  assert.deepEqual(decide(web, undefined), { kind: "start", handle: "alice" });
});

test("both sessions: the migration is to be resumed", () => {
  assert.deepEqual(decide(web, native), { kind: "resume", handle: "alice" });
});

/**
 * **The test that carries the design decision.**
 *
 * Without a vault, history exists only in the current device's MLS state, and the ratchet has
 * destroyed its keys along the way: the new device could read it back nowhere. Migrating would
 * trade a possible eviction for a certain loss.
 */
test("a refused vault forbids the migration", () => {
  const decision = decide({ handle: "alice", vaultEnabled: false }, undefined);

  assert.equal(decision.kind, "fallback");
  assert.match(decision.kind === "fallback" ? decision.reason : "", /History backup/);
});

/**
 * Absent is not `false`.
 *
 * Accounts older than the flag never had to decide; treating them as a refusal would refuse to
 * migrate exactly the oldest installs.
 */
test("a vault that was never refused migrates", () => {
  assert.equal(decide({ handle: "alice" }, undefined).kind, "start");
  assert.equal(decide({ handle: "alice", vaultEnabled: true }, undefined).kind, "start");
});

/** Two distinct accounts are not a half-finished migration. */
test("two different accounts make it back off", () => {
  const decision = decide(web, { handle: "bob" });

  assert.equal(decision.kind, "fallback");
  assert.match(decision.kind === "fallback" ? decision.reason : "", /another account/);
});

function steps(extra: Partial<Steps> = {}): Steps & { log: string[] } {
  const log: string[] = [];
  const note = (name: string) => () => {
    log.push(name);
    return Promise.resolve();
  };

  return {
    log,
    registerNativeDevice: () => {
      log.push("register");
      return Promise.resolve("alice:desktop-2");
    },
    propagateFromOld: note("propagate"),
    progress: () => Promise.resolve({ joined: 2, expected: 2 }),
    restoreHistory: note("restore"),
    revokeOld: (old: string) => {
      log.push(`revoke:${old}`);
      return Promise.resolve();
    },
    forgetWeb: note("forget"),
    ...extra,
  };
}

const noWait = () => Promise.resolve();

/**
 * **The test that carries the order of the steps.**
 *
 * Revocation before erasure, and both after propagation: revoking the old device too early would
 * cut it off from the groups before it had introduced the new one, and erasing the web session
 * first would remove the one thing that makes a replay possible.
 */
test("a complete migration follows the imposed order", async () => {
  const plan = steps();
  await migrate({ kind: "start", handle: "alice" }, plan, "alice:desktop", noWait);

  assert.deepEqual(plan.log, [
    "register",
    "propagate",
    "restore",
    "revoke:alice:desktop",
    "forget",
  ]);
});

/** Resuming does not re-register: the native device already exists, and the server would create a second one. */
test("a resume does not register one more device", async () => {
  const plan = steps();
  await migrate({ kind: "resume", handle: "alice" }, plan, "alice:desktop", noWait);

  assert.ok(!plan.log.includes("register"));
  assert.deepEqual(plan.log[0], "propagate");
});

/**
 * We wait for the **result** of the propagation, not for the gesture.
 *
 * The old device posts commits, the new one has to pick them up: revoking in between would make
 * the conversations unreachable on this side, with no recourse.
 */
test("revocation waits until the groups have been joined", async () => {
  let rounds = 0;
  const plan = steps({
    progress: () => {
      rounds += 1;
      return Promise.resolve({ joined: rounds >= 3 ? 2 : 0, expected: 2 });
    },
  });

  await migrate({ kind: "resume", handle: "alice" }, plan, "alice:desktop", noWait);

  assert.equal(plan.log.filter((e) => e === "propagate").length, 3);
  assert.ok(plan.log.indexOf("revoke:alice:desktop") > plan.log.lastIndexOf("propagate"));
});

/**
 * A silent server makes it give up, without destroying anything.
 *
 * Giving up leaves two active devices: a healthy state, merely redundant, which the next start
 * picks up again. What must never happen is revoking or erasing out of spite.
 */
test("a propagation that does not complete revokes nothing", async () => {
  const plan = steps({ progress: () => Promise.resolve({ joined: 0, expected: 2 }) });

  await assert.rejects(
    () => migrate({ kind: "resume", handle: "alice" }, plan, "alice:desktop", noWait),
    PropagationIncomplete,
  );

  assert.ok(!plan.log.some((e) => e.startsWith("revoke")));
  assert.ok(!plan.log.includes("forget"));
});

/** No fallback decision may touch anything at all. */
test("a fallback runs no step", async () => {
  for (const decision of [
    { kind: "fallback", reason: "no matter" },
    { kind: "native" },
    { kind: "fresh" },
  ] as const) {
    const plan = steps();
    await migrate(decision, plan, "alice:desktop", noWait);
    assert.deepEqual(plan.log, [], `${decision.kind} acted`);
  }
});

/** One conversation more on the new side (rare, but possible) does not block. */
test("progress beyond what was expected does not loop", async () => {
  const plan = steps({ progress: () => Promise.resolve({ joined: 3, expected: 2 }) });
  await migrate({ kind: "resume", handle: "alice" }, plan, "alice:desktop", noWait);

  assert.ok(plan.log.includes("forget"));
});
