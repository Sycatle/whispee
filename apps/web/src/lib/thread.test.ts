import assert from "node:assert/strict";
import { test } from "node:test";

import { GROUPING_WINDOW_MS } from "./datetime.ts";
import { layout, type Placed, textOf, unblocked } from "./thread.ts";

/** A day the tests can be precise about, well away from any local midnight. */
const NOON = new Date("2024-03-04T12:00:00Z").getTime();
const DAY = 24 * 60 * 60 * 1000;

interface Line extends Placed {
  sender: string | null;
}

/** A message from somebody, at a moment. `seq` is positional, the way the server assigns it. */
function line(seq: number, sender: string | null, sentAt: number | undefined): Line {
  return { seq, sender, mine: sender === "alice", sentAt };
}

/** The seams, with our own handle folded onto one identity the way the thread does it. */
function seams(readCursor = -1) {
  return { authorOf: (message: Line) => message.sender, readCursor };
}

test("an empty thread lays out to no rows at all", () => {
  assert.deepEqual(layout([], seams()), []);
});

test("a run of messages from one author collapses into a single group", () => {
  const rows = layout(
    [line(1, "bob", NOON), line(2, "bob", NOON + 1000), line(3, "bob", NOON + 2000)],
    seams(),
  );

  assert.deepEqual(
    rows.map((row) => row.continues),
    [false, true, true],
  );
});

test("a message from somebody else breaks the group open", () => {
  const rows = layout(
    [line(1, "bob", NOON), line(2, "carol", NOON + 1000), line(3, "bob", NOON + 2000)],
    seams(),
  );

  assert.deepEqual(
    rows.map((row) => row.continues),
    [false, false, false],
  );
});

test("a long enough silence breaks the group even from the same author", () => {
  const rows = layout(
    [line(1, "bob", NOON), line(2, "bob", NOON + GROUPING_WINDOW_MS)],
    seams(),
  );

  assert.deepEqual(
    rows.map((row) => row.continues),
    [false, false],
  );
});

test("two messages from an unknown sender are not known to share an author", () => {
  // The regression this guards: `null === null` is true, and grouping on it would collapse an
  // unattributed backlog into one turn by somebody who does not exist.
  const rows = layout([line(1, null, NOON), line(2, null, NOON + 1000)], seams());

  assert.deepEqual(
    rows.map((row) => row.continues),
    [false, false],
  );
});

test("the first message of a thread opens a day, and carries its own stamp to label it", () => {
  const rows = layout([line(1, "bob", NOON)], seams());

  assert.deepEqual(rows[0]?.opensDay, NOON);
});

test("a message that opens a new day always opens a group too", () => {
  const rows = layout([line(1, "bob", NOON), line(2, "bob", NOON + DAY)], seams());

  assert.deepEqual(rows[1]?.opensDay, NOON + DAY);
  assert.equal(rows[1]?.continues, false);
});

test("a message nobody stamped opens no day and names no date", () => {
  const rows = layout([line(1, "bob", undefined), line(2, "bob", NOON)], seams());

  assert.equal(rows[0]?.opensDay, undefined);
  // The second one is the first stamped message in the thread, so it is the one that heads a day.
  assert.equal(rows[1]?.opensDay, NOON);
});

test("the unread line falls before the first message past the boundary and never at the top", () => {
  const rows = layout(
    [line(1, "bob", NOON), line(2, "bob", NOON + 1000), line(3, "bob", NOON + 2000)],
    seams(1),
  );

  assert.deepEqual(
    rows.map((row) => row.opensUnread),
    [false, true, false],
  );
});

test("a thread that is unread from its very first message gets no line above it", () => {
  const rows = layout([line(1, "bob", NOON), line(2, "bob", NOON + 1000)], seams(0));

  assert.deepEqual(
    rows.map((row) => row.opensUnread),
    [false, false],
  );
});

test("our own message never opens the unread line, whatever the cursor says", () => {
  const rows = layout(
    [line(1, "bob", NOON), line(2, "alice", NOON + 1000), line(3, "bob", NOON + 2000)],
    seams(1),
  );

  assert.deepEqual(
    rows.map((row) => row.opensUnread),
    [false, false, false],
  );
});

test("a thread with nothing unread carries no line anywhere", () => {
  const rows = layout([line(1, "bob", NOON), line(2, "bob", NOON + 1000)], seams(9));

  assert.deepEqual(
    rows.map((row) => row.opensUnread),
    [false, false],
  );
});

test("all our own devices count as one author, when the caller says so", () => {
  const messages = [
    { seq: 1, sender: "alice", mine: true, sentAt: NOON },
    { seq: 2, sender: null, mine: true, sentAt: NOON + 1000 },
  ];
  const rows = layout(messages, {
    authorOf: (message) => (message.mine ? "alice" : message.sender),
    readCursor: -1,
  });

  assert.equal(rows[1]?.continues, true);
});

test("a stable key survives the session mutating the message in place", () => {
  const before = layout([line(7, "bob", NOON)], seams());

  // The session rewrites its messages where they lie and hands back a fresh array around them.
  const rewritten = line(7, "bob", NOON);
  const after = layout([rewritten], seams());

  assert.equal(before[0]?.key, after[0]?.key);
  assert.notEqual(before[0]?.message, after[0]?.message);
});

test("keys tell two lines apart even when everything else about them matches", () => {
  const rows = layout([line(1, "bob", NOON), line(2, "bob", NOON)], seams());

  assert.notEqual(rows[0]?.key, rows[1]?.key);
});

test("a quote of a text message shows the text", () => {
  const messages = [{ seq: 1, content: { kind: "text", text: "on my way" } as const }];

  assert.equal(textOf(messages, 1), "on my way");
});

test("a quote of an attachment shows the file name", () => {
  const messages = [
    {
      seq: 4,
      content: {
        kind: "attachment",
        ref: { id: "x", key: "k", iv: "v", name: "map.png", mime: "image/png", size: 12 },
      } as const,
    },
  ];

  assert.equal(textOf(messages, 4), "map.png");
});

test("a quote of a message we do not hold says so rather than showing a blank", () => {
  assert.equal(textOf([], 12), "message unavailable");
});

test("a blocked account's messages leave the thread, with no trace that they did", () => {
  // No gap, no count, no "3 hidden". A counter of what one has declined to read is an invitation
  // to read it, and it hands anybody who suspects they are blocked a way to keep score.
  const messages = [
    { seq: 1, mine: false, sender: "alice" },
    { seq: 2, mine: false, sender: "mallory" },
    { seq: 3, mine: false, sender: "alice" },
  ];

  assert.deepEqual(
    unblocked(messages, new Set(["mallory"])).map((message) => message.seq),
    [1, 3],
  );
});

test("our own messages survive a list that somehow names us", () => {
  // Blocking oneself is not a state the interface can produce. A thread that silently lost its
  // own half would be a bug nobody could explain from the screen.
  const messages = [{ seq: 1, mine: true, sender: "me" }];

  assert.deepEqual(unblocked(messages, new Set(["me"])), messages);
});

test("a message nobody can be attributed to is not blocked", () => {
  // Sealed sender means some arrivals have no author to decline. Declining what cannot be named
  // would hide precisely the messages nobody can account for.
  const messages = [{ seq: 1, mine: false, sender: null }];

  assert.deepEqual(unblocked(messages, new Set(["mallory"])), messages);
});

test("an empty block list changes nothing and still hands back a copy", () => {
  // A copy, because the caller sorts and folds in place downstream, and a filter that sometimes
  // aliases its input is a bug that only shows up on the accounts that block nobody.
  const messages = [{ seq: 1, mine: false, sender: "alice" }];
  const result = unblocked(messages, new Set());

  assert.deepEqual(result, messages);
  assert.notEqual(result, messages);
});

test("filtering happens before layout, so no day heading is left over nothing", () => {
  // The reason this function lives next to `layout` rather than in the component. Filtering after
  // it leaves a date above an empty day, or a turn that kept its avatar and lost its message.
  const day = 24 * 60 * 60 * 1000;
  const messages = [
    { seq: 1, mine: false, sender: "alice", sentAt: day },
    { seq: 2, mine: false, sender: "mallory", sentAt: day * 2 },
  ];

  const rows = layout(unblocked(messages, new Set(["mallory"])), {
    authorOf: (message) => message.sender,
    readCursor: 0,
  });

  assert.equal(rows.length, 1);
  assert.equal(rows[0].message.seq, 1);
});
