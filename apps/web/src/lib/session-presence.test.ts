/**
 * Who was last seen when.
 *
 * The rules here are small and every one of them is easy to get wrong in a way nothing would
 * report: a clock read off the browser instead of the server, seconds shown as milliseconds, a
 * peer who opted out still showing their last position. None of them could be checked at all
 * while this lived on `Session`.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { PresenceTracker, type PresenceSource } from "./session-presence.ts";

/** Records what was asked, answers what it was told to. */
function source(
  answer: { now: number; accounts: { handle: string; last_seen: number }[] },
): PresenceSource & { asked: string[][] } {
  const asked: string[][] = [];
  return {
    asked,
    presence(handles) {
      asked.push(handles);
      return Promise.resolve(answer);
    },
  };
}

test("nothing is known before the first poll", () => {
  const tracker = new PresenceTracker();

  assert.equal(tracker.lastSeen("bob"), undefined);
  assert.equal(tracker.clock, 0);
});

test("the server's clock is kept, and seconds become milliseconds", async () => {
  const tracker = new PresenceTracker();

  // Both sides converted, and both from the server. Freshness is judged by comparing the two, so
  // taking either one from the browser would make the comparison meaningless on a skewed clock.
  await tracker.refresh(source({ now: 1_700, accounts: [{ handle: "bob", last_seen: 1_640 }] }), [
    "bob",
  ]);

  assert.equal(tracker.clock, 1_700_000);
  assert.equal(tracker.lastSeen("bob"), 1_640_000);
});

test("an account the server stops answering about is forgotten", async () => {
  const tracker = new PresenceTracker();

  await tracker.refresh(
    source({
      now: 10,
      accounts: [
        { handle: "bob", last_seen: 9 },
        { handle: "carol", last_seen: 8 },
      ],
    }),
    ["bob", "carol"],
  );
  assert.equal(tracker.lastSeen("carol"), 8_000);

  // Carol opted out. Merging would leave her last known position on screen for good — the one
  // state the setting exists to remove.
  await tracker.refresh(source({ now: 20, accounts: [{ handle: "bob", last_seen: 19 }] }), [
    "bob",
    "carol",
  ]);

  assert.equal(tracker.lastSeen("carol"), undefined);
  assert.equal(tracker.lastSeen("bob"), 19_000);
});

test("no more than sixty-four accounts are asked about at once", async () => {
  const tracker = new PresenceTracker();
  const many = Array.from({ length: 100 }, (_, i) => `peer${i}`);
  const server = source({ now: 1, accounts: [] });

  await tracker.refresh(server, many);

  // The server caps there. Polling the first ones is a visible limit; the alternative is a silent
  // 400 that shows everybody offline.
  assert.equal(server.asked[0]?.length, 64);
  assert.equal(server.asked[0]?.[0], "peer0");
});

test("asking about nobody makes no request at all", async () => {
  const tracker = new PresenceTracker();
  const server = source({ now: 5, accounts: [] });

  await tracker.refresh(server, []);

  assert.equal(server.asked.length, 0);
  // And the clock does not move: an answer nobody asked for cannot have arrived.
  assert.equal(tracker.clock, 0);
});

test("clearing forgets the peers but keeps the clock", async () => {
  const tracker = new PresenceTracker();
  await tracker.refresh(source({ now: 30, accounts: [{ handle: "bob", last_seen: 29 }] }), ["bob"]);

  tracker.clear();

  assert.equal(tracker.lastSeen("bob"), undefined);
  // The clock is not a fact about a person, so opting out does not make it wrong. Resetting it
  // would only make the next comparison read against zero.
  assert.equal(tracker.clock, 30_000);
});
