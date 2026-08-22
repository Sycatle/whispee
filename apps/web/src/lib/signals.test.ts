import assert from "node:assert/strict";
import { test } from "node:test";

import {
  TYPING_DEBOUNCE_MS,
  TYPING_TTL_MS,
  fresh,
  nextExpiry,
  showing,
  without,
  type Typing,
} from "./signals.ts";

const T0 = 1_000_000;

test("the send threshold never exceeds half the TTL", () => {
  // Beyond that, the last signal can expire before the next one: the indicator flickers.
  assert.ok(TYPING_DEBOUNCE_MS * 2 <= TYPING_TTL_MS);
});

test("an indicator expires at the end of the TTL, not before", () => {
  const typing: Typing[] = [{ handle: "alice", at: T0 }];

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
    { handle: "alice", at: T0 },
    { handle: "bob", at: T0 + 500 },
  ];

  assert.equal(nextExpiry(typing, T0), TYPING_TTL_MS);
  assert.equal(nextExpiry(typing, T0 + 1000), TYPING_TTL_MS - 1000);
});

test("with no indicator, no wake-up is scheduled", () => {
  assert.equal(nextExpiry([], T0), undefined);
});

test("an already expired entry asks for an immediate render, never a negative delay", () => {
  const typing: Typing[] = [{ handle: "alice", at: T0 }];
  assert.equal(nextExpiry(typing, T0 + TYPING_TTL_MS * 10), 0);
});

/**
 * What `absorb` does when a message arrives: sending proves its author has finished typing.
 * Without it, the sender appears to keep typing for the whole TTL after hitting send.
 */
test("removing one correspondent leaves the others untouched", () => {
  const typing: Typing[] = [
    { handle: "alice", at: T0 },
    { handle: "bob", at: T0 },
  ];

  assert.deepEqual(without(typing, "alice"), [{ handle: "bob", at: T0 }]);
  assert.deepEqual(without(typing, "carol"), typing);
});

test("nobody is shown typing when we do not emit ourselves", () => {
  // The reciprocity, at the display end. Without it, turning the indicator off buys a one-way
  // view of who hesitates before answering — an advantage over the other side, not privacy from
  // the server, which is what the setting is actually for.
  const typing: Typing[] = [{ handle: "bob", at: T0 }, { handle: "carol", at: T0 }];

  assert.deepEqual(showing(typing, "alice", false), []);
  assert.deepEqual(showing(typing, "alice", true), ["bob", "carol"]);
});

test("our own indicator is never shown back to us", () => {
  const typing: Typing[] = [{ handle: "alice", at: T0 }, { handle: "bob", at: T0 }];

  assert.deepEqual(showing(typing, "alice", true), ["bob"]);
});

test("one person typing from two devices is one person", () => {
  // Every device of an account posts under the same id, so the raw list repeats it. The screen
  // must read "Bob is typing", not "Bob and Bob".
  const typing: Typing[] = [{ handle: "bob", at: T0 }, { handle: "bob", at: T0 + 10 }];

  assert.deepEqual(showing(typing, "alice", true), ["bob"]);
});
