import assert from "node:assert/strict";
import { test } from "node:test";

import { ONLINE_WINDOW_MS, agoOf, describePresence, isOnline } from "./presence.ts";

const NOW = Date.now();

test("an account seen within the window is online", () => {
  assert.equal(isOnline(NOW - 1000, NOW), true);
  assert.equal(describePresence(NOW - 1000, NOW), "online");
});

test("the bound is strict: at exactly the window, the account is offline", () => {
  assert.equal(isOnline(NOW - ONLINE_WINDOW_MS + 1, NOW), true);
  assert.equal(isOnline(NOW - ONLINE_WINDOW_MS, NOW), false);
});

test("outside the window, how long ago is shown — not what time it was", () => {
  // The difference is the whole point: a clock time makes the reader do the subtraction, against
  // a clock they have to find and a timezone they have to assume.
  const seen = NOW - ONLINE_WINDOW_MS - 60_000;
  assert.equal(describePresence(seen, NOW), "last seen 3 minutes ago");
});

test("the steps get coarser as they get older", () => {
  const MINUTE = 60_000;
  const HOUR = 60 * MINUTE;
  const DAY = 24 * HOUR;

  assert.equal(agoOf(30_000), "moments ago");
  assert.equal(agoOf(MINUTE), "1 minute ago");
  assert.equal(agoOf(9 * MINUTE), "9 minutes ago");
  assert.equal(agoOf(HOUR), "1 hour ago");
  assert.equal(agoOf(5 * HOUR), "5 hours ago");
  assert.equal(agoOf(DAY), "yesterday");
  assert.equal(agoOf(3 * DAY), "3 days ago");
  assert.equal(agoOf(8 * DAY), "1 week ago");
  assert.equal(agoOf(40 * DAY), "1 month ago");
  assert.equal(agoOf(400 * DAY), "over a year ago");
});

test("elapsed time is measured against the server clock", () => {
  // A device whose own clock is ahead would otherwise report a peer as last seen in the future.
  const seen = NOW - 10 * 60_000;
  assert.equal(describePresence(seen, NOW), "last seen 10 minutes ago");
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
