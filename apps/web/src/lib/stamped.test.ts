import assert from "node:assert/strict";
import { test } from "node:test";

import { decide, merge, patchOf, type Stamps } from "./stamped.ts";

const T0 = 1_700_000_000_000;

test("two devices editing different keys both keep their edit", () => {
  // The whole reason this module exists. A single stamp over the collection would make one of
  // these two blocks vanish, and nothing anywhere would report it.
  const laptop = decide<boolean>({}, {}, "bob", true, T0);
  const phone = decide<boolean>({}, {}, "carol", true, T0 + 1);

  const merged = merge(laptop.values, laptop.stamps, patchOf(phone.values, phone.stamps));

  assert.deepEqual(merged.values, { bob: true, carol: true });
  assert.equal(merged.changed, true);
});

test("the later edit of one key wins", () => {
  const early = decide<string>({}, {}, "bob", "Robert", T0);
  const late = decide<string>({}, {}, "bob", "Bobby", T0 + 1000);

  assert.equal(merge(early.values, early.stamps, patchOf(late.values, late.stamps)).values.bob, "Bobby");
  assert.equal(merge(late.values, late.stamps, patchOf(early.values, early.stamps)).values.bob, "Bobby");
});

test("a removal travels, and beats the earlier decision that put it there", () => {
  // The direction that matters most: an unblock that failed to propagate brings somebody back.
  const blocked = decide<boolean>({}, {}, "bob", true, T0);
  const unblocked = decide(blocked.values, blocked.stamps, "bob", null, T0 + 1000);

  const merged = merge(blocked.values, blocked.stamps, patchOf(unblocked.values, unblocked.stamps));

  assert.deepEqual(merged.values, {});
  assert.equal(merged.changed, true);
});

test("a removal does not resurrect on the next announcement", () => {
  // The stamp map is the tombstone set. Without it the device still holding the value would
  // re-assert it at every epoch, and the unblock would undo itself on a timer.
  const stillBlocked = decide<boolean>({}, {}, "bob", true, T0);
  const unblocked = decide(stillBlocked.values, stillBlocked.stamps, "bob", null, T0 + 1000);

  const merged = merge(
    unblocked.values,
    unblocked.stamps,
    patchOf(stillBlocked.values, stillBlocked.stamps),
  );

  assert.deepEqual(merged.values, {});
  assert.equal(merged.changed, false, "an older assertion counted as a change");
});

test("re-hearing what we already hold decides nothing", () => {
  // Every device re-announces once per epoch of every conversation. If that counted as a change,
  // the session would be re-encrypted and rewritten on each of them, for ever.
  const held = decide<boolean>({}, {}, "bob", true, T0);

  assert.equal(merge(held.values, held.stamps, patchOf(held.values, held.stamps)).changed, false);
});

test("an older patch cannot overwrite a newer decision", () => {
  const newer = decide<string>({}, {}, "bob", "Bobby", T0 + 1000);
  const older: Stamps = { bob: T0 };

  const merged = merge(newer.values, newer.stamps, patchOf({ bob: "Robert" }, older));

  assert.equal(merged.values.bob, "Bobby");
  assert.equal(merged.changed, false);
});

test("merging is order-independent for distinct keys", () => {
  // Three devices, three edits, any arrival order: they must land on the same state, or two
  // phones that saw the same messages in a different order would disagree for ever.
  const a = decide<boolean>({}, {}, "bob", true, T0);
  const b = decide<boolean>({}, {}, "carol", true, T0 + 1);
  const c = decide<boolean>({}, {}, "dave", true, T0 + 2);

  const forward = merge(
    merge(a.values, a.stamps, patchOf(b.values, b.stamps)).values,
    merge(a.values, a.stamps, patchOf(b.values, b.stamps)).stamps,
    patchOf(c.values, c.stamps),
  );
  const backward = merge(
    merge(c.values, c.stamps, patchOf(b.values, b.stamps)).values,
    merge(c.values, c.stamps, patchOf(b.values, b.stamps)).stamps,
    patchOf(a.values, a.stamps),
  );

  assert.deepEqual(forward.values, backward.values);
  assert.deepEqual(forward.stamps, backward.stamps);
});

test("a patch carries removals, so a full snapshot catches a device up in one message", () => {
  const held = decide<boolean>({}, {}, "bob", true, T0);
  const after = decide(held.values, held.stamps, "bob", null, T0 + 1);

  assert.deepEqual(patchOf(after.values, after.stamps), { bob: { at: T0 + 1, v: null } });
});

test("deciding returns new objects rather than mutating", () => {
  // The caller holds these inside a session that persists itself. A mutation the persistence
  // layer cannot see is exactly the failure this module is meant to rule out.
  const values = { bob: true };
  const stamps = { bob: T0 };

  const next = decide(values, stamps, "carol", true, T0 + 1);

  assert.deepEqual(values, { bob: true });
  assert.deepEqual(stamps, { bob: T0 });
  assert.deepEqual(next.values, { bob: true, carol: true });
});
