import assert from "node:assert/strict";
import { test } from "node:test";

import {
  GROUPING_WINDOW_MS,
  continues,
  dayLabel,
  opensDay,
  spokenDuration,
  spokenLifetime,
  timeOf,
} from "./datetime.ts";

/** Local time, deliberately: these are read by a person in their own timezone. */
const at = (year: number, month: number, day: number, hour = 12, minute = 0) =>
  new Date(year, month - 1, day, hour, minute).getTime();

test("the time is zero-padded to HH:MM", () => {
  assert.equal(timeOf(at(2026, 3, 4, 9, 5)), "09:05");
  assert.equal(timeOf(at(2026, 3, 4, 23, 59)), "23:59");
});

test("today and yesterday are named rather than dated", () => {
  const now = at(2026, 3, 4, 12);

  assert.equal(dayLabel(now, now), "Today");
  assert.equal(dayLabel(at(2026, 3, 3, 23), now), "Yesterday");
  assert.notEqual(dayLabel(at(2026, 2, 27), now), "Yesterday");
});

/**
 * The boundary that a naive "less than 24 hours ago" gets wrong: one minute past midnight is
 * today, and 23:59 the evening before is yesterday, though they are two minutes apart.
 */
test("the day boundary is the calendar day, not a duration", () => {
  const justAfterMidnight = at(2026, 3, 4, 0, 1);

  assert.equal(dayLabel(justAfterMidnight, justAfterMidnight), "Today");
  assert.equal(dayLabel(at(2026, 3, 3, 23, 59), justAfterMidnight), "Yesterday");
  assert.ok(opensDay(justAfterMidnight, at(2026, 3, 3, 23, 59)));
});

test("the first message of a thread opens a day", () => {
  assert.ok(opensDay(at(2026, 3, 4), undefined));
});

/** No stamp, no day: putting a date on screen that the message does not carry would be a guess. */
test("an unstamped message opens no day", () => {
  assert.equal(opensDay(undefined, at(2026, 3, 4)), false);
});

test("two messages the same day do not open a second heading", () => {
  assert.equal(opensDay(at(2026, 3, 4, 18), at(2026, 3, 4, 9)), false);
});

test("the same author within the window continues", () => {
  const first = at(2026, 3, 4, 12, 0);

  assert.ok(continues("alice", first + GROUPING_WINDOW_MS - 1, "alice", first));
  assert.equal(continues("alice", first + GROUPING_WINDOW_MS, "alice", first), false);
});

test("a different author never continues", () => {
  const first = at(2026, 3, 4, 12, 0);

  assert.equal(continues("bob", first + 1000, "alice", first), false);
});

/** Two unknown senders are not known to be the same one. */
test("an unknown author never continues", () => {
  const first = at(2026, 3, 4, 12, 0);

  assert.equal(continues(null, first + 1000, null, first), false);
});

/** A burst either side of midnight is two turns, however close in time. */
test("crossing midnight breaks the group even within the window", () => {
  const before = at(2026, 3, 3, 23, 59);

  assert.equal(continues("alice", before + 60_000, "alice", before), false);
});

test("a missing stamp on either side breaks the group", () => {
  const first = at(2026, 3, 4, 12, 0);

  assert.equal(continues("alice", undefined, "alice", first), false);
  assert.equal(continues("alice", first, "alice", undefined), false);
});

test("a short call is said in seconds, not as a stopwatch", () => {
  // "0:11" reads as a running timer. Eleven seconds of call is a call somebody picked up and put
  // straight down, and the line in the thread should say that rather than look like a clock.
  assert.equal(spokenDuration(11), "11 s");
  assert.equal(spokenDuration(59), "59 s");
});

test("a call of a minute or more is said in minutes", () => {
  assert.equal(spokenDuration(60), "1 min");
  assert.equal(spokenDuration(3599), "59 min");
});

test("a long call keeps its minutes zero-padded beside the hours", () => {
  // Without the padding, "1 h 5" reads as five hours rather than five minutes past one.
  assert.equal(spokenDuration(3600), "1 h 00");
  assert.equal(spokenDuration(3900), "1 h 05");
});

test("a duration is never negative and never a fraction", () => {
  // The value is a difference of two clocks: one of them can be behind the other.
  assert.equal(spokenDuration(-5), "0 s");
  assert.equal(spokenDuration(1.6), "2 s");
});

test("a lifetime is spoken in the units it was chosen in", () => {
  assert.equal(spokenLifetime(604800), "7 days");
  assert.equal(spokenLifetime(86400), "1 day");
  assert.equal(spokenLifetime(3600), "1 hour");
});
