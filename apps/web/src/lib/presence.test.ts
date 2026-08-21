import assert from "node:assert/strict";
import { test } from "node:test";

import { ONLINE_WINDOW_MS, describePresence, isOnline } from "./presence.ts";

const NOW = Date.now();

test("an account seen within the window is online", () => {
  assert.equal(isOnline(NOW - 1000, NOW), true);
  assert.equal(describePresence(NOW - 1000, NOW), "online");
});

test("the bound is strict: at exactly the window, the account is offline", () => {
  assert.equal(isOnline(NOW - ONLINE_WINDOW_MS + 1, NOW), true);
  assert.equal(isOnline(NOW - ONLINE_WINDOW_MS, NOW), false);
});

test("outside the window, the time of the last activity is shown", () => {
  const seen = NOW - ONLINE_WINDOW_MS - 60_000;
  assert.match(describePresence(seen, NOW), /^last seen (at \d\d:\d\d|on )/);
});

/**
 * Not knowing is not the same as knowing someone is away. The account may never have been seen,
 * or may have refused to broadcast its presence — deciding on its behalf would be the screen's
 * first lie.
 */
test('with no data, nothing is shown — least of all "offline"', () => {
  assert.equal(describePresence(undefined, NOW), "");
  assert.equal(isOnline(undefined, NOW), false);
});

/**
 * Two clocks are being compared, and they drift apart: that is what `MAX_CLOCK_SKEW` exists for
 * on the server. "Seen in three minutes" would be the only other possible answer.
 */
test('a timestamp in the future reads as "online", never as "seen in three minutes"', () => {
  assert.equal(describePresence(NOW + 180_000, NOW), "online");
});

/** The server's clock decides, not the browser's. */
test("the reference is the server's now", () => {
  const server = NOW - 10 * ONLINE_WINDOW_MS;
  assert.equal(isOnline(server - 1000, server), true);
  assert.equal(isOnline(server - 1000, NOW), false);
});
