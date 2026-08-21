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
  [{ kind: "conversation", key: KEY, detail: {} }, `#/c/${KEY}/info`],
  [{ kind: "conversation", key: KEY, detail: { handle: "bob" } }, `#/c/${KEY}/info/bob`],
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

test("the detail column is a route with and without a member expanded", () => {
  assert.deepEqual(parse(`#/c/${KEY}/info`), { kind: "conversation", key: KEY, detail: {} });
  assert.deepEqual(parse(`#/c/${KEY}/info/alice`), {
    kind: "conversation",
    key: KEY,
    detail: { handle: "alice" },
  });
});

/** The server accepts any non-empty string of up to 64 bytes as a handle (`routes.rs:306`). */
test("a handle containing URL punctuation round trips through escaping", () => {
  const handle = "a b/c%d#e?f";
  const hash = format({ kind: "conversation", key: KEY, detail: { handle } });

  assert.ok(!hash.includes(" "), "the space must be escaped");
  assert.deepEqual(parse(hash), { kind: "conversation", key: KEY, detail: { handle } });
});

/**
 * The key parsed cleanly. Dropping the user on the home screen to punish a broken escape further
 * to the right would throw away the part of the URL that was right.
 */
test("a broken escape in the handle opens the detail column with nobody expanded", () => {
  assert.deepEqual(parse(`#/c/${KEY}/info/%zz`), {
    kind: "conversation",
    key: KEY,
    detail: {},
  });
  assert.deepEqual(parse(`#/c/${KEY}/info/`), { kind: "conversation", key: KEY, detail: {} });
});

/**
 * The prefix was recognised; answering a half-wrong URL by ignoring the half that was right
 * would be a worse guess than showing the settings index.
 */
test("an unknown settings section falls back to the settings index, not to home", () => {
  assert.deepEqual(parse("#/settings/telemetry"), { kind: "settings", section: null });
  assert.deepEqual(parse("#/settings/"), { kind: "settings", section: null });
});

test("a hash written without its leading # parses the same way", () => {
  assert.deepEqual(parse("/settings/lock"), { kind: "settings", section: "lock" });
  assert.deepEqual(parse("settings/lock"), { kind: "settings", section: "lock" });
});

/** What stops the shell pushing a second history entry for the place it is already on. */
test("two routes naming the same place compare equal whatever their identity", () => {
  assert.ok(same({ kind: "conversation", key: KEY }, { kind: "conversation", key: KEY }));
  assert.ok(same(parse(""), parse("#/")));
  assert.ok(!same({ kind: "conversation", key: KEY }, { kind: "conversation", key: KEY, detail: {} }));
  assert.ok(!same({ kind: "settings", section: null }, { kind: "settings", section: "lock" }));
});
