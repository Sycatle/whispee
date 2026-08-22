import assert from "node:assert/strict";
import { test } from "node:test";

import { byPinnedThenRecent, type Ordered } from "./ordering.ts";

const at = (activity: number, pinned = false): Ordered => ({ pinned, activity });

test("a pinned conversation stays first however long it has been quiet", () => {
  // The property the obvious implementation gets wrong. Adding a large constant to a pinned
  // conversation's activity and sorting once is a bet on how far apart two timestamps can be, and
  // a thread quiet for longer than the bet drops back among the rest — weeks later, silently.
  const quiet = at(0, true);
  const busy = at(Number.MAX_SAFE_INTEGER);

  assert.deepEqual([busy, quiet].sort(byPinnedThenRecent), [quiet, busy]);
});

test("among pinned conversations, the most recent is first", () => {
  const older = at(100, true);
  const newer = at(200, true);

  assert.deepEqual([older, newer].sort(byPinnedThenRecent), [newer, older]);
});

test("among the rest, the most recent is first", () => {
  const older = at(100);
  const newer = at(200);

  assert.deepEqual([older, newer].sort(byPinnedThenRecent), [newer, older]);
});

test("equal conversations keep the order they arrived in", () => {
  // Two conversations with the same timestamp are two nobody can tell apart. Shuffling them
  // between renders would be motion carrying no information.
  const first = at(100);
  const second = at(100);

  assert.deepEqual([first, second].sort(byPinnedThenRecent), [first, second]);
});

test("the whole list sorts into two blocks", () => {
  const list = [at(300), at(100, true), at(400), at(200, true)];

  assert.deepEqual(
    list.sort(byPinnedThenRecent).map((entry) => [entry.pinned, entry.activity]),
    [
      [true, 200],
      [true, 100],
      [false, 400],
      [false, 300],
    ],
  );
});
