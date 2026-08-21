import assert from "node:assert/strict";
import { test } from "node:test";

import { Revision } from "./revision.ts";

test("bumping the revision notifies every subscriber", () => {
  const revision = new Revision();
  const seen: string[] = [];

  revision.subscribe(() => seen.push("first"));
  revision.subscribe(() => seen.push("second"));
  revision.bump();

  assert.deepEqual(seen, ["first", "second"]);
});

test("an unsubscribed listener stops being notified", () => {
  const revision = new Revision();
  let calls = 0;

  const unsubscribe = revision.subscribe(() => {
    calls += 1;
  });
  revision.bump();
  unsubscribe();
  revision.bump();

  assert.equal(calls, 1);
});

/**
 * The reason this class exists. `session` is the same reference before and after a mutation, so
 * the only thing React can compare is this number — and it has to differ every single time, not
 * merely eventually.
 */
test("the snapshot changes on every bump so react can tell something moved", () => {
  const revision = new Revision();
  const seen = new Set<number>();

  seen.add(revision.getSnapshot());
  for (let index = 0; index < 5; index += 1) {
    revision.bump();
    seen.add(revision.getSnapshot());
  }

  assert.equal(seen.size, 6);
});

/**
 * Two components subscribe, one unmounts. If the set were keyed on anything but the listener
 * itself, the survivor would go silent — a stale pane with no error anywhere to explain it.
 */
test("subscribing twice and unsubscribing once leaves the other listener alone", () => {
  const revision = new Revision();
  let leaving = 0;
  let staying = 0;

  const unsubscribe = revision.subscribe(() => {
    leaving += 1;
  });
  revision.subscribe(() => {
    staying += 1;
  });

  revision.bump();
  unsubscribe();
  revision.bump();

  assert.equal(leaving, 1);
  assert.equal(staying, 2);
});

/**
 * A component that unmounts on the news it just received removes itself from the set mid-notify.
 * Iterating the live set would skip whoever was next in it, and that listener would keep a stale
 * view until something unrelated happened to bump again.
 */
test("a listener that unsubscribes while being notified does not silence the next one", () => {
  const revision = new Revision();
  let later = 0;

  const unsubscribe = revision.subscribe(() => unsubscribe());
  revision.subscribe(() => {
    later += 1;
  });

  revision.bump();

  assert.equal(later, 1);
});

/** Both are handed straight to `useSyncExternalStore`, which re-subscribes if either moves. */
test("subscribe and getSnapshot survive being destructured off the instance", () => {
  const revision = new Revision();
  const { subscribe, getSnapshot, bump } = revision;
  let calls = 0;

  subscribe(() => {
    calls += 1;
  });
  bump();

  assert.equal(calls, 1);
  assert.equal(getSnapshot(), 1);
});
