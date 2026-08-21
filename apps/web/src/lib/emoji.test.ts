import assert from "node:assert/strict";
import { test } from "node:test";

import { applyTone, fileOf, onlyEmoji, search, segment, withoutTone } from "./emoji.ts";
import type { Catalogue } from "./emoji.ts";

test("the variation selector is dropped from the filename", () => {
  // `❤️` is U+2764 U+FE0F. The generated tree names it `2764.svg`, because Fluent's metadata
  // omits the selector. If the two ever disagree the emoji renders for the sender and not for
  // the receiver, which is the one failure mode nobody notices in their own window.
  assert.equal(fileOf("❤️"), "/emoji/2764.svg");
  assert.equal(fileOf("❤"), "/emoji/2764.svg");
});

test("joiners and skin tone modifiers are kept in the filename", () => {
  assert.equal(fileOf("👨‍💻"), "/emoji/1f468-200d-1f4bb.svg");
  assert.equal(fileOf("👍🏽"), "/emoji/1f44d-1f3fd.svg");
  assert.equal(fileOf("🇫🇷"), "/emoji/1f1eb-1f1f7.svg");
});

test("a multi-codepoint emoji is one run, not several", () => {
  assert.deepEqual(segment("👨‍💻"), [{ emoji: "👨‍💻" }]);
  assert.deepEqual(segment("👍🏽"), [{ emoji: "👍🏽" }]);
  assert.deepEqual(segment("🇫🇷"), [{ emoji: "🇫🇷" }]);
});

test("prose and emoji alternate, and prose stays coalesced", () => {
  assert.deepEqual(segment("hello 👋 world"), [
    { text: "hello " },
    { emoji: "👋" },
    { text: " world" },
  ]);
});

test("consecutive emoji are separate runs", () => {
  assert.deepEqual(segment("👍👎"), [{ emoji: "👍" }, { emoji: "👎" }]);
});

test("digits are not emoji", () => {
  // `7` is pictographic only inside a keycap sequence. Treating it as an emoji on its own turns
  // every phone number in a conversation into a row of pictures.
  assert.deepEqual(segment("call 0612345678"), [{ text: "call 0612345678" }]);
  assert.deepEqual(segment("#whispee"), [{ text: "#whispee" }]);
});

test("an empty message segments to nothing", () => {
  assert.deepEqual(segment(""), []);
});

test("onlyEmoji tells a reaction-sized message from a sentence", () => {
  assert.equal(onlyEmoji("👍"), true);
  assert.equal(onlyEmoji(" 👍 👎 "), true);
  assert.equal(onlyEmoji("👍 ok"), false);
  assert.equal(onlyEmoji(""), false);
});

const CATALOGUE: Catalogue = {
  groups: ["Smileys & Emotion", "People & Body"],
  entries: [
    { char: "😀", label: "grinning face", keywords: ["face", "grin"], group: 0 },
    { char: "😊", label: "smile", keywords: ["blush", "happy"], group: 0 },
    { char: "😄", label: "smiling face", keywords: ["face", "happy"], group: 0 },
    { char: "🧑‍🏭", label: "factory worker", keywords: ["blacksmith", "worker"], group: 1 },
    { char: "☕", label: "café", keywords: ["coffee"], group: 0 },
    {
      char: "👍",
      label: "thumbs up",
      keywords: ["+1"],
      group: 1,
      tones: ["👍🏻", "👍🏼", "👍🏽", "👍🏾", "👍🏿"],
    },
  ],
};

test("search ranks an exact name, then a prefix, then anything else", () => {
  assert.deepEqual(
    search(CATALOGUE, "smil").map((entry) => entry.label),
    ["smile", "smiling face"],
  );
  assert.deepEqual(
    search(CATALOGUE, "smile").map((entry) => entry.label),
    ["smile"],
  );
  // A keyword match must come after every name match, or "blacksmith" outranks "smile".
  assert.deepEqual(
    search(CATALOGUE, "smith").map((entry) => entry.label),
    ["factory worker"],
  );
});

test("search ignores case and diacritics in both directions", () => {
  assert.deepEqual(
    search(CATALOGUE, "CAFE").map((entry) => entry.char),
    ["☕"],
  );
  assert.deepEqual(
    search(CATALOGUE, "café").map((entry) => entry.char),
    ["☕"],
  );
});

test("an empty query matches nothing rather than everything", () => {
  assert.deepEqual(search(CATALOGUE, "   "), []);
});

test("a tone applies only where there is artwork for one", () => {
  const thumb = CATALOGUE.entries[5];
  const coffee = CATALOGUE.entries[4];

  assert.equal(applyTone(thumb, 0), "👍");
  assert.equal(applyTone(thumb, 3), "👍🏽");
  // A preference about hands says nothing about a cup: rendering the neutral glyph is right,
  // refusing to render one is not.
  assert.equal(applyTone(coffee, 3), "☕");
});

test("the tone is stripped before an emoji is remembered", () => {
  // Otherwise five variants of the same thumb crowd out the rest of the recents list.
  assert.equal(withoutTone("👍🏽"), "👍");
  assert.equal(withoutTone("👍"), "👍");
  assert.equal(withoutTone("👨‍💻"), "👨‍💻");
});
