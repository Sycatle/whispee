import assert from "node:assert/strict";
import { test } from "node:test";

import { applyTone, keyOf, onlyEmoji, search, segment, withoutTone } from "./emoji.ts";
import type { Catalogue } from "./emoji.ts";
import catalogue from "./generated/emoji-index.json" with { type: "json" };

test("the variation selector goes when nothing is joined", () => {
  // `❤️` is U+2764 U+FE0F, and the sheet files it under `2764`. If the two ever disagree the
  // emoji renders for the sender and not for the receiver, which is the one failure mode nobody
  // notices in their own window.
  assert.equal(keyOf("❤️"), "2764");
  assert.equal(keyOf("❤"), "2764");
  assert.equal(keyOf("1️⃣"), "31-20e3");
  assert.equal(keyOf("©️"), "a9");
});

test("the variation selector stays when a joiner is present", () => {
  // Upstream's own rule, and the reverse of the line above. Getting this wrong loses the pirate
  // flag, the rainbow flag, and every gendered person.
  assert.equal(keyOf("🏴‍☠️"), "1f3f4-200d-2620-fe0f");
  assert.equal(keyOf("🏳️‍🌈"), "1f3f3-fe0f-200d-1f308");
  assert.equal(keyOf("🏃‍♀️"), "1f3c3-200d-2640-fe0f");
});

test("the eye in speech bubble is upstream's own exception", () => {
  // It carries a joiner, so by the rule above it should keep both selectors. Twemoji files it
  // with neither. One sequence, hard-coded, and this test is what stops someone tidying it away.
  assert.equal(keyOf("👁️‍🗨️"), "1f441-200d-1f5e8");
});

test("joiners and skin tone modifiers are kept in the key", () => {
  assert.equal(keyOf("👨‍💻"), "1f468-200d-1f4bb");
  assert.equal(keyOf("👍🏽"), "1f44d-1f3fd");
  assert.equal(keyOf("🇫🇷"), "1f1eb-1f1f7");
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

test("every emoji in the catalogue segments as exactly one emoji run", () => {
  // The check that would have caught the keycaps. `1️⃣` is `31 FE0F 20E3` and not one of those
  // three codepoints is `Extended_Pictographic`, so all twelve of them fell through to prose and
  // were drawn by the platform font. Nobody saw it, because the previous artwork had no keycaps
  // either — the bug and the thing that would have revealed it were introduced and removed
  // together.
  //
  // Reading the generated catalogue rather than a hand-written list, because a hand-written list
  // is exactly what would have missed them a second time.
  const missed = catalogue.entries
    .filter((entry) => {
      const runs = segment(entry.char);
      return runs.length !== 1 || !("emoji" in runs[0]) || runs[0].emoji !== entry.char;
    })
    .map((entry) => entry.label);

  assert.deepEqual(missed, []);
});

test("every emoji in the catalogue has a key, and no two share one", () => {
  const keys = new Set(catalogue.entries.map((entry) => keyOf(entry.char)));
  assert.equal(keys.size, catalogue.entries.length);
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
