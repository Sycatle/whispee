import assert from "node:assert/strict";
import { test } from "node:test";

import type { Catalogue } from "./emoji.ts";
import { closed, completions, typed } from "./shortcode.ts";
import real from "./generated/emoji-index.json" with { type: "json" };

const CATALOGUE: Catalogue = {
  groups: ["Smileys & Emotion"],
  entries: [
    { char: "😀", label: "grinning face", keywords: [], group: 0, codes: ["grinning"] },
    { char: "😄", label: "smiling face", keywords: [], group: 0, codes: ["smile", "happy"] },
    { char: "😊", label: "blush", keywords: [], group: 0, codes: ["smiling_face", "blush"] },
    { char: "👍️", label: "thumbs up", keywords: [], group: 0, codes: ["+1", "thumbsup"] },
    { char: "🍉", label: "watermelon", keywords: [], group: 0 },
  ],
};

test("a colon opening a token starts a shortcode", () => {
  assert.deepEqual(typed(":sm", 3), { from: 0, to: 3, query: "sm" });
  assert.deepEqual(typed("hello :sm", 9), { from: 6, to: 9, query: "sm" });
  assert.deepEqual(typed("(:sm", 4), { from: 1, to: 4, query: "sm" });
});

test("a colon inside a word does not", () => {
  // The three cases that would otherwise put a menu over the composer on ordinary text.
  assert.equal(typed("https://ex", 10), null);
  assert.equal(typed("at 10:30", 8), null);
  assert.equal(typed("note:this", 9), null);
});

test("the menu waits for two characters", () => {
  // `:` and `:)` are a colon and a smiley, not the start of a name. One character would match
  // several hundred sequences anyway.
  assert.equal(typed(":", 1), null);
  assert.equal(typed(":s", 2), null);
  assert.equal(typed(":sm", 3)?.query, "sm");
});

test("the token is read from the caret, not from the end of the line", () => {
  const text = "say :sm and stop";
  assert.deepEqual(typed(text, 7), { from: 4, to: 7, query: "sm" });
  // Caret past the token: the space closed it.
  assert.equal(typed(text, 9), null);
});

test("completions put an exact name first, then a prefix, then a substring", () => {
  assert.deepEqual(
    completions(CATALOGUE, "smil").map((hit) => hit.entry.char),
    ["😄", "😊"],
  );
  // `smiling_face` is not a prefix of `smile` — they diverge at the fifth character — so the
  // longer query narrows to one. That is the point of typing more of a name.
  assert.deepEqual(
    completions(CATALOGUE, "smile").map((hit) => hit.entry.char),
    ["😄"],
  );
  assert.equal(completions(CATALOGUE, "smile")[0]?.code, "smile");
});

test("an emoji is offered once, however many of its names match", () => {
  // `👍️` answers to both `+1` and `thumbsup`. Two rows inserting the same character is two ways
  // to do one thing, presented as a choice.
  const hits = completions(CATALOGUE, "1");
  assert.equal(hits.filter((hit) => hit.entry.char === "👍️").length, 1);
});

test("completions are capped", () => {
  assert.ok(completions(real as Catalogue, "a", 8).length <= 8);
  assert.ok(completions(real as Catalogue, "a", 8).length > 0);
});

test("a closing colon completes only an exact name", () => {
  assert.deepEqual(closed(CATALOGUE, ":smile:", 7), {
    from: 0,
    to: 7,
    query: "smile",
    char: "😄",
  });
  // A prefix must not be silently substituted: picking a row off a visible list is a choice, this
  // would be a guess.
  assert.equal(closed(CATALOGUE, ":smil:", 6), null);
  assert.equal(closed(CATALOGUE, ":nonsense:", 10), null);
});

test("the real catalogue answers the shortcodes people actually type", () => {
  const catalogue = real as Catalogue;
  for (const [code, char] of [
    ["joy", "😂"],
    ["heart", "❤️"],
    ["thumbsup", "👍️"],
    ["france", "🇫🇷"],
  ] as const) {
    assert.equal(closed(catalogue, `:${code}:`, code.length + 2)?.char, char, code);
  }
});
