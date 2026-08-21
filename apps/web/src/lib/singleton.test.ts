import assert from "node:assert/strict";
import { test } from "node:test";

import { type Locks, claim } from "./singleton.ts";

/** A lock manager holding one name at a time, which is all `claim` asks of the real one. */
function manager(): Locks & { taken: Set<string> } {
  const taken = new Set<string>();
  return {
    taken,
    request(name, options, callback) {
      if (taken.has(name) && options.ifAvailable) return Promise.resolve(callback(null));

      taken.add(name);
      return Promise.resolve(callback({ name })).then(() => {
        taken.delete(name);
      });
    },
  };
}

test("the first tab holds the session", async () => {
  const locks = manager();
  const first = await claim("session", locks);

  assert.equal(first.held, true);
  assert.deepEqual([...locks.taken], ["session"]);
});

test("a second tab is refused rather than queued", async () => {
  // Queued, it would sit on a blank screen for as long as the other tab lives, which reads as a
  // hang. "Another tab has it" is the only answer somebody can act on.
  const locks = manager();
  await claim("session", locks);

  assert.equal((await claim("session", locks)).held, false);
});

test("releasing hands the session to the next tab", async () => {
  const locks = manager();
  const first = await claim("session", locks);
  first.release();
  // The release settles the callback's promise, which the manager awaits before letting go.
  await Promise.resolve();

  assert.equal((await claim("session", locks)).held, true);
});

test("releasing twice is not an error", async () => {
  // The browser releases the lock on unload regardless, so a caller that also releases explicitly
  // must not be punished for the overlap.
  const first = await claim("session", manager());
  first.release();
  first.release();
});

test("two different names do not contend", async () => {
  const locks = manager();
  assert.equal((await claim("one", locks)).held, true);
  assert.equal((await claim("two", locks)).held, true);
});

test("a browser with no lock manager runs unguarded", async () => {
  // Fails open on purpose: refusing to start a messenger because a lock could not be taken is a
  // worse failure than the one being defended against, and it comes from the environment rather
  // than from anything the user did.
  assert.equal((await claim("session", undefined)).held, true);
});

test("a lock manager that throws runs unguarded too", async () => {
  const broken: Locks = {
    request: () => Promise.reject(new Error("no")),
  };

  assert.equal((await claim("session", broken)).held, true);
});
