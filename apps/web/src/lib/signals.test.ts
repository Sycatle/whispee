import assert from "node:assert/strict";
import { test } from "node:test";

import {
  TYPING_DEBOUNCE_MS,
  TYPING_TTL_MS,
  fresh,
  nextExpiry,
  openSignal,
  sealSignal,
  showing,
  without,
  type CallEvent,
  type Signal,
  type Typing,
} from "./signals.ts";

const T0 = 1_000_000;

/** The epoch key, as far as this module is concerned: thirty-two bytes nobody else knows. */
const KEY = new Uint8Array(32).fill(7);

test("the send threshold never exceeds half the TTL", () => {
  // Beyond that, the last signal can expire before the next one: the indicator flickers.
  assert.ok(TYPING_DEBOUNCE_MS * 2 <= TYPING_TTL_MS);
});

test("an indicator expires at the end of the TTL, not before", () => {
  const typing: Typing[] = [{ account: "alice", at: T0 }];

  assert.equal(fresh(typing, T0 + TYPING_TTL_MS - 1).length, 1);
  assert.equal(fresh(typing, T0 + TYPING_TTL_MS).length, 0);
});

/**
 * **The test that keeps the indicator from staying lit.** Expiry is only evaluated at render
 * time, and nothing triggers a render when someone stops typing. Without this delay, the display
 * only learns of the expiry at the next event of any kind — up to thirty seconds later.
 */
test("the expiry delay targets the oldest entry", () => {
  const typing: Typing[] = [
    { account: "alice", at: T0 },
    { account: "bob", at: T0 + 500 },
  ];

  assert.equal(nextExpiry(typing, T0), TYPING_TTL_MS);
  assert.equal(nextExpiry(typing, T0 + 1000), TYPING_TTL_MS - 1000);
});

test("with no indicator, no wake-up is scheduled", () => {
  assert.equal(nextExpiry([], T0), undefined);
});

test("an already expired entry asks for an immediate render, never a negative delay", () => {
  const typing: Typing[] = [{ account: "alice", at: T0 }];
  assert.equal(nextExpiry(typing, T0 + TYPING_TTL_MS * 10), 0);
});

/**
 * What `absorb` does when a message arrives: sending proves its author has finished typing.
 * Without it, the sender appears to keep typing for the whole TTL after hitting send.
 */
test("removing one correspondent leaves the others untouched", () => {
  const typing: Typing[] = [
    { account: "alice", at: T0 },
    { account: "bob", at: T0 },
  ];

  assert.deepEqual(without(typing, "alice"), [{ account: "bob", at: T0 }]);
  assert.deepEqual(without(typing, "carol"), typing);
});

test("nobody is shown typing when we do not emit ourselves", () => {
  // The reciprocity, at the display end. Without it, turning the indicator off buys a one-way
  // view of who hesitates before answering — an advantage over the other side, not privacy from
  // the server, which is what the setting is actually for.
  const typing: Typing[] = [{ account: "bob", at: T0 }, { account: "carol", at: T0 }];

  assert.deepEqual(showing(typing, "alice", false), []);
  assert.deepEqual(showing(typing, "alice", true), ["bob", "carol"]);
});

/**
 * The entries are **account ids**, and this is the test that says so.
 *
 * The field used to be called `handle` while holding an account id, and `Session.typingIn`
 * filtered it against the session's handle — so the guard never matched anything, for as long as
 * account ids have existed. It cost nothing, because `absorbSignal` drops our own indicator
 * before recording it, but a backstop that cannot fire is not one. Realistic ids here rather than
 * first names, so that the next person to compare against the wrong field sees this fail.
 */
test("our own indicator is never shown back to us", () => {
  const mine = "cc33453670c79bf3fa37635c08c8a677";
  const theirs = "a8f8e14c20e4efd81117d54bb95c96f2";
  const typing: Typing[] = [
    { account: mine, at: T0 },
    { account: theirs, at: T0 },
  ];

  assert.deepEqual(showing(typing, mine, true), [theirs]);

  // A handle passed where an account id belongs filters nothing — which is precisely what the
  // call site was doing before this change.
  assert.deepEqual(showing(typing, "@alice0539", true), [mine, theirs]);
});

test("a typing signal survives the round trip", async () => {
  const sealed = await sealSignal(KEY, { kind: "typing", account: "a8f8e14c20e4efd8" });

  assert.deepEqual(await openSignal(KEY, sealed), {
    kind: "typing",
    account: "a8f8e14c20e4efd8",
  });
});

/**
 * Every call event, in one pass.
 *
 * The event travels as its index in a list, so a reordering of that list silently reinterprets
 * every frame in flight — a `left` read as `accepted`. Enumerating them here is what makes such a
 * reordering fail rather than merely misbehave.
 */
test("every call event survives the round trip", async () => {
  const events: CallEvent[] = [
    "ringing",
    "accepted",
    "declined",
    "left",
    "muted",
    "unmuted",
    "alive",
  ];

  for (const event of events) {
    const signal: Signal = {
      kind: "call",
      event,
      call: "9f2c41ab7d0e5638",
      device: "cc33453670c79bf3fa37635c08c8a677",
      account: "a8f8e14c20e4efd81117d54bb95c96f2",
    };

    assert.deepEqual(await openSignal(KEY, await sealSignal(KEY, signal)), signal);
  }
});

/**
 * The wrong key is the **ordinary** case, not an anomaly: the server relays without filtering by
 * epoch, so a signal sent just before a commit arrives after it. Throwing would raise an error on
 * every change of group composition.
 */
test("a signal under another epoch's key reads as nothing, not as an error", async () => {
  const sealed = await sealSignal(KEY, { kind: "typing", account: "alice" });
  const other = new Uint8Array(32).fill(9);

  assert.equal(await openSignal(other, sealed), undefined);
});

test("a truncated signal reads as nothing", async () => {
  const sealed = await sealSignal(KEY, { kind: "typing", account: "alice" });

  assert.equal(await openSignal(KEY, sealed.subarray(0, 20)), undefined);
});

test("one person typing from two devices is one person", () => {
  // Every device of an account posts under the same id, so the raw list repeats it. The screen
  // must read "Bob is typing", not "Bob and Bob".
  const typing: Typing[] = [{ account: "bob", at: T0 }, { account: "bob", at: T0 + 10 }];

  assert.deepEqual(showing(typing, "alice", true), ["bob"]);
});
