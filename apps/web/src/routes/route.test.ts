import assert from "node:assert/strict";
import { test } from "node:test";

import { type Route, SETTINGS_SECTIONS, format, parse, same } from "./route.ts";

/** A plausible `toHex(groupId)`: 32 bytes, lowercase. */
const KEY = "9a3f".repeat(16);

/** The seven shapes of the scheme, each paired with the hash it must produce. */
const CANONICAL: [Route, string][] = [
  [{ kind: "home" }, "#/"],
  [{ kind: "new" }, "#/new"],
  [{ kind: "conversation", key: KEY }, `#/c/${KEY}`],
  [{ kind: "settings", section: null }, "#/settings"],
  [{ kind: "settings", section: "devices" }, "#/settings/devices"],
];

test("every shape of the scheme survives a round trip in both directions", () => {
  for (const [route, hash] of CANONICAL) {
    assert.equal(format(route), hash, `formatting ${hash}`);
    assert.deepEqual(parse(hash), route, `parsing ${hash}`);
    assert.equal(format(parse(hash)), hash, `re-formatting ${hash}`);
  }
});

test("all seven settings sections are routable, and each one names itself", () => {
  for (const section of SETTINGS_SECTIONS) {
    assert.equal(format({ kind: "settings", section }), `#/settings/${section}`);
    assert.deepEqual(parse(`#/settings/${section}`), { kind: "settings", section });
  }
});

test("an empty hash and a bare # are both the home screen", () => {
  assert.deepEqual(parse(""), { kind: "home" });
  assert.deepEqual(parse("#"), { kind: "home" });
  assert.deepEqual(parse("#/"), { kind: "home" });
  assert.deepEqual(parse("/"), { kind: "home" });
});

/**
 * A stale bookmark or a typed URL is the only way to get here, and both are better served by the
 * list of conversations than by an error screen.
 */
test("a hash that matches nothing falls back to the home screen", () => {
  for (const hash of ["#/nowhere", "#/c", "#/new/again", "#/c/" + KEY + "/details", "#//"]) {
    assert.deepEqual(parse(hash), { kind: "home" }, hash);
  }
});

/**
 * The failure this prevents is not a crash: a conversation route built on a key that no
 * `toHex(groupId)` could ever produce renders an empty panel with no way back except the address
 * bar.
 */
test("a malformed conversation key is rejected rather than carried into a dead route", () => {
  const malformed = [
    "#/c/xyz", // not hexadecimal
    "#/c/9A3F", // uppercase: `toHex` emits lowercase, and two URLs for one place is one too many
    "#/c/9a3", // odd length, so not a byte string
    "#/c/", // empty
    "#/c/9a3f%20", // escaped, therefore not what `toHex` wrote
  ];

  for (const hash of malformed) assert.deepEqual(parse(hash), { kind: "home" }, hash);
});

test("a well-formed key is accepted without being checked against any conversation", () => {
  // `parse` has no session and must not acquire one; existence is the shell's question.
  assert.deepEqual(parse("#/c/00"), { kind: "conversation", key: "00" });
});

/**
 * The detail column stopped being a route — see `state/detail.tsx`. What is checked here is that
 * the URLs it used to own are still *answered*, because they are in people's history and in their
 * open tabs. An address this application minted itself should not be met with the home screen.
 */
test("the urls the detail column used to own still open their conversation", () => {
  assert.deepEqual(parse(`#/c/${KEY}/info`), { kind: "conversation", key: KEY });
  assert.deepEqual(parse(`#/c/${KEY}/info/alice`), { kind: "conversation", key: KEY });
  assert.deepEqual(parse(`#/c/${KEY}/info/`), { kind: "conversation", key: KEY });
  // A handle that never decoded is no worse off than one that did: both name a column that is no
  // longer addressable, and both land in the conversation.
  assert.deepEqual(parse(`#/c/${KEY}/info/%zz`), { kind: "conversation", key: KEY });
});

/** Anything past the old two levels is still nonsense, and still goes home. */
test("a conversation url with more after it than info is not a place", () => {
  assert.deepEqual(parse(`#/c/${KEY}/info/alice/extra`), { kind: "home" });
  assert.deepEqual(parse(`#/c/${KEY}/details`), { kind: "home" });
});

/** A conversation now has exactly one spelling, which is what makes the round trip total. */
test("a conversation formats to one url and nothing else", () => {
  assert.equal(format({ kind: "conversation", key: KEY }), `#/c/${KEY}`);
});

test("two routes naming the same place compare equal whatever their identity", () => {
  assert.ok(same({ kind: "conversation", key: KEY }, { kind: "conversation", key: KEY }));
  assert.ok(same(parse(""), parse("#/")));
  // Two conversations differ only by their key now: the detail column is no longer part of what
  // a route says, so there is no second field left for `same` to disagree about.
  assert.ok(!same({ kind: "conversation", key: KEY }, { kind: "conversation", key: "00ff" }));
  assert.ok(!same({ kind: "settings", section: null }, { kind: "settings", section: "lock" }));
});
