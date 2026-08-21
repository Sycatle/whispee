import assert from "node:assert/strict";
import { test } from "node:test";

import { type NameSources, compactNameOf, nameMatches, nameOf } from "./naming.ts";

/** Builds the two records `Session` holds, from a terser description. */
function sources(
  petnames: Record<string, string> = {},
  profiles: Record<string, string> = {},
): NameSources {
  const asserted: Record<string, { name: string }> = {};
  for (const [handle, name] of Object.entries(profiles)) asserted[handle] = { name };
  return { petnames, profiles: asserted };
}

test("somebody who has asserted nothing is shown by their handle alone", () => {
  const name = nameOf("charlie8295", sources());
  assert.deepEqual(name, { primary: "@charlie8295", secondary: null, isHandle: true });
});

test("the handle is still shown beside a display name", () => {
  const name = nameOf("charlie8295", sources({}, { charlie8295: "Charlie" }));
  assert.deepEqual(name, { primary: "Charlie", secondary: "@charlie8295", isHandle: false });
});

test("a local petname wins over a self-asserted display name", () => {
  const name = nameOf("charlie8295", sources({ charlie8295: "Charlie at work" }, { charlie8295: "Charlie" }));
  assert.equal(name.primary, "Charlie at work");
  assert.equal(name.secondary, "@charlie8295");
});

test("a display name that is only whitespace is ignored in favour of the handle", () => {
  const name = nameOf("charlie8295", sources({}, { charlie8295: "   " }));
  assert.equal(name.primary, "@charlie8295");
  assert.equal(name.isHandle, true);
});

test("two members claiming the same display name both fall back to their handle in compact mode", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { charlie8295: "Charlie", mallory1721: "charlie " });

  assert.equal(compactNameOf("charlie8295", claims, among), "@charlie8295");
  assert.equal(compactNameOf("mallory1721", claims, among), "@mallory1721");
});

test("a display name that is another member's handle is refused in compact mode", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { mallory1721: "charlie8295" });

  assert.equal(compactNameOf("mallory1721", claims, among), "@mallory1721");
});

test("a display name that is another member's handle with its sigil is refused too", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { mallory1721: "@charlie8295" });

  assert.equal(compactNameOf("mallory1721", claims, among), "@mallory1721");
});

test("a rival wearing the same name behind a sigil is caught too", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { charlie8295: "Charlie", mallory1721: "@charlie" });

  assert.equal(compactNameOf("charlie8295", claims, among), "@charlie8295");
  assert.equal(compactNameOf("mallory1721", claims, among), "@mallory1721");
});

test("a petname collision is the reader's own doing and is left alone", () => {
  const among = ["charlie8295", "mallory1721"];
  const chosen = sources({ charlie8295: "Charlie", mallory1721: "Charlie" });

  assert.equal(compactNameOf("charlie8295", chosen, among), "Charlie");
  assert.equal(compactNameOf("mallory1721", chosen, among), "Charlie");
});

test("an uncontested display name survives the compact form", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { charlie8295: "Charlie", mallory1721: "Mallory" });

  assert.equal(compactNameOf("charlie8295", claims, among), "Charlie");
});

test("a display name equal to one's own handle is kept as its owner wrote it", () => {
  const claims = sources({}, { charlie8295: "Charlie8295" });
  assert.equal(compactNameOf("charlie8295", claims, ["charlie8295"]), "Charlie8295");
});

test("a search term matches the handle, the display name and the petname alike", () => {
  const both = sources({ bob4410: "Bobby" }, { charlie8295: "Charlie" });

  assert.equal(nameMatches("charlie8295", both, "charlie"), true);
  assert.equal(nameMatches("charlie8295", both, "@charlie82"), true);
  assert.equal(nameMatches("bob4410", both, "bobby"), true);
  assert.equal(nameMatches("bob4410", both, "charlie"), false);
});

test("an empty search term matches everyone", () => {
  assert.equal(nameMatches("charlie8295", sources(), "  "), true);
});
