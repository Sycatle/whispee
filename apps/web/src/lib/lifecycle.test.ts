/**
 * The idle lock is the kind of code nobody notices when it is broken: too eager and it is turned
 * off, too lax and it protects nothing, and neither shows up in normal use.
 *
 * `observeIdle` takes its target and its clock, so the whole thing runs without a DOM. What is
 * left uncovered is the wiring in `App.tsx` and the real events — `node --test` reaches neither.
 */
import assert from "node:assert/strict";
import { type TestContext, test } from "node:test";
import { RELOCK_MS, observeIdle } from "./lifecycle.ts";

/** A clock the test moves by hand, so the delay is verified rather than waited out. */
function scenario(t: TestContext) {
  t.mock.timers.enable({ apis: ["setInterval"] });

  let clock = 0;
  const target = new EventTarget();
  const fired: number[] = [];
  const stop = observeIdle(() => fired.push(clock), target, () => clock);

  return {
    fired,
    stop,
    touch: () => target.dispatchEvent(new Event("keydown")),
    /** Advances the clock, then lets every tick that fits in the interval run. */
    wait(ms: number) {
      for (let step = 0; step < ms; step += 1_000) {
        clock += 1_000;
        t.mock.timers.tick(1_000);
      }
    },
  };
}

test("an untouched session locks once the delay is up", (t) => {
  const idle = scenario(t);
  t.after(idle.stop);

  idle.wait(RELOCK_MS - 60_000);
  assert.deepEqual(idle.fired, [], "locked before the delay was up");

  idle.wait(120_000);
  assert.equal(idle.fired.length, 1);
});

/** A lock that fires while somebody is typing gets removed by that somebody. */
test("using the app keeps it open", (t) => {
  const idle = scenario(t);
  t.after(idle.stop);

  for (let round = 0; round < 5; round += 1) {
    idle.wait(RELOCK_MS - 60_000);
    idle.touch();
  }

  assert.deepEqual(idle.fired, []);
});

/**
 * The caller may decide it has nothing to lock. It must not then be asked again every tick — the
 * reason the clock is restarted before the callback.
 */
test("it does not fire again every tick once it has fired", (t) => {
  const idle = scenario(t);
  t.after(idle.stop);

  idle.wait(RELOCK_MS * 3);
  assert.equal(idle.fired.length, 3);
});

test("nothing fires after unsubscribing", (t) => {
  const idle = scenario(t);

  idle.stop();
  idle.wait(RELOCK_MS * 2);
  assert.deepEqual(idle.fired, []);
});
