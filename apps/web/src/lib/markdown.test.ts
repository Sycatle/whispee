import assert from "node:assert/strict";
import { test } from "node:test";

import { MAX_SOURCE, type Inline, parse, parseInline, plain, prose } from "./markdown.ts";

/**
 * What is not covered here: what any of this looks like. The tree is the contract — `RichText.tsx`
 * turns it into elements and that mapping is checked by eye. What these pin is the reading, which
 * is where a message quietly loses a character.
 */

/** Flattens a tree back to the characters it carries, ignoring which node they sit in. */
function chars(nodes: Inline[]): string {
  return nodes
    .map((n) =>
      n.kind === "text" || n.kind === "code"
        ? n.text
        : n.kind === "link"
          ? n.raw
          : chars([...n.children]),
    )
    .join("");
}

/**
 * The invariant worth more than every case below it.
 *
 * A parser that drops a newline at a block boundary, or an escape it did not recognise, fails
 * here and nowhere else — the rendering still looks plausible.
 */
test("text with no markup survives the round trip exactly", () => {
  for (const text of [
    "hello",
    "two\nlines",
    "trailing newline\n",
    "\nleading newline",
    "blank\n\nline between",
    "  leading and trailing spaces  ",
    "a message with @alice and :joy: in it",
    "unicode: éàü 漢字 🇫🇷 👍🏽",
    "2 * 3 = 6",
    "",
  ]) {
    assert.equal(plain(text), text, `round trip changed ${JSON.stringify(text)}`);
  }
});

test("bold, italic, strike, code and spoiler are read", () => {
  assert.deepEqual(parseInline("**a**"), [{ kind: "strong", children: [{ kind: "text", text: "a" }] }]);
  assert.deepEqual(parseInline("*a*"), [{ kind: "em", children: [{ kind: "text", text: "a" }] }]);
  assert.deepEqual(parseInline("~~a~~"), [{ kind: "strike", children: [{ kind: "text", text: "a" }] }]);
  assert.deepEqual(parseInline("`a`"), [{ kind: "code", text: "a" }]);
  assert.deepEqual(parseInline("||a||"), [
    { kind: "spoiler", children: [{ kind: "text", text: "a" }] },
  ]);
});

/**
 * The whole isolation argument, asserted rather than trusted: a fenced block carries a `string`,
 * so nothing inside it can be found by any other layer. If this ever fails, mentions are being
 * resolved inside code samples.
 */
test("a fenced block is opaque to every other layer", () => {
  const source = "```py\n@alice :joy: **x** ||y|| https://evil.tld\n```";
  const [block] = parse(source);

  assert.equal(block?.kind, "code");
  assert.equal(block?.kind === "code" && block.lang, "py");
  assert.equal(
    block?.kind === "code" && block.code,
    "@alice :joy: **x** ||y|| https://evil.tld",
  );
});

test("a fence with no language, and one that never closes", () => {
  const [none] = parse("```\nplain\n```");
  assert.equal(none?.kind === "code" && none.lang, null);

  // Somebody pressed send early. Running to the end beats scattering the rest with backticks.
  const [open] = parse("```\nstill code\nand this too");
  assert.equal(open?.kind === "code" && open.code, "still code\nand this too");
});

test("inline code outranks everything inside it", () => {
  assert.deepEqual(parseInline("`**a**`"), [{ kind: "code", text: "**a**" }]);
  assert.deepEqual(parseInline("`@alice`"), [{ kind: "code", text: "@alice" }]);
});

/**
 * Emphasis carries children, so a mention inside bold is reachable — that is the other half of
 * the isolation rule and the reason the tree nests at all.
 */
test("a span carries its contents as children, so prose inside it stays prose", () => {
  const [node] = parseInline("**bold @alice here**");
  assert.equal(node?.kind, "strong");
  assert.equal(node?.kind === "strong" && chars([...node.children]), "bold @alice here");
});

/**
 * The reason `_` is not a marker at all. Every one of these is ordinary text in a conversation
 * about code, and no flanking rule saves them.
 */
test("underscores are never emphasis", () => {
  for (const text of ["snake_case", "__init__", "MY_CONST", "a _b_ c", "__dunder__ name"]) {
    assert.equal(plain(text), text);
    assert.ok(
      parseInline(text).every((n) => n.kind === "text"),
      `${text} was read as markup`,
    );
  }
});

/** The flanking rule, stated by the cases it exists for. */
test("an asterisk with a space after it does not open a span", () => {
  for (const text of ["2 * 3", "a * b * c", "**", "***", "* item", "a * b"]) {
    assert.equal(plain(text), text, `${text} lost characters`);
  }
});

test("an unclosed delimiter is prose", () => {
  for (const text of ["**a", "*a", "~~a", "||a", "`a", "a **b"]) {
    assert.equal(plain(text), text, `${text} lost its marker`);
  }
});

test("a backslash neutralises a marker and nothing else", () => {
  assert.equal(chars(parseInline("\\*not italic\\*")), "*not italic*");
  assert.deepEqual(parseInline("\\*a\\*"), [{ kind: "text", text: "*a*" }]);
  // Anything not escapable keeps its backslash, which is what saves a path and a regex.
  assert.equal(chars(parseInline("C:\\Users\\me")), "C:\\Users\\me");
  assert.equal(chars(parseInline("\\d+")), "\\d+");
  assert.equal(chars(parseInline("ends with a backslash \\")), "ends with a backslash \\");
});

test("a url is one opaque node, whatever punctuation it carries", () => {
  const [node] = parseInline("https://x.com/a_b*c");
  assert.equal(node?.kind, "link");
  assert.equal(node?.kind === "link" && node.raw, "https://x.com/a_b*c");
});

test("quotes fold consecutive lines into one block", () => {
  const blocks = parse("> first\n> second\nplain");
  assert.equal(blocks[0]?.kind, "quote");
  assert.equal(blocks[0]?.kind === "quote" && chars([...blocks[0].children]), "first\nsecond");
  assert.equal(blocks[1]?.kind, "paragraph");
});

test("a greater-than sign inside a line is not a quote", () => {
  const [block] = parse("if a > b then");
  assert.equal(block?.kind, "paragraph");
  assert.equal(plain("if a > b then"), "if a > b then");
});

/**
 * The bounds are the defence, and hostile input is what they are for. Both of these used to be
 * the shapes that hang a tokeniser rather than the shapes that overflow it.
 */
test("pathological input returns promptly and loses nothing", () => {
  const stars = "*".repeat(10_000);
  assert.equal(plain(stars), stars);

  const nested = "**".repeat(500) + "x";
  assert.equal(typeof plain(nested), "string");

  const huge = "a".repeat(MAX_SOURCE + 1);
  const [block] = parse(huge);
  assert.equal(block?.kind, "paragraph");
  assert.equal(plain(huge), huge);
});

test("plain drops the markers and keeps the words", () => {
  assert.equal(plain("**bold** and *italic*"), "bold and italic");
  assert.equal(plain("`code` stays"), "code stays");
  assert.equal(plain("> quoted"), "quoted");
});

/**
 * The failure this option exists to prevent: `Conversation.tsx` reads the last message into an
 * `aria-live` region. A spoiler announced aloud reaches somebody who did not ask for it.
 */
test("masking never lets a spoiler through", () => {
  const masked = plain("the answer is ||42||", { spoilers: "mask" });
  assert.ok(!masked.includes("42"), masked);
  assert.equal(plain("the answer is ||42||"), "the answer is 42");
});

/**
 * `prose` is what stops `resolve()` rewriting a handle inside a code sample into an account id —
 * which happens on the way out, to the message that is actually sent, and cannot be undone.
 */
test("prose excludes fenced blocks and inline code", () => {
  const text = "before `@a` middle\n```\n@b\n```\nafter";
  const kept = prose(text)
    .map((r) => text.slice(r.from, r.to))
    .join("");

  assert.ok(kept.includes("before "));
  assert.ok(kept.includes("after"));
  assert.ok(!kept.includes("@a"), "inline code leaked into prose");
  assert.ok(!kept.includes("@b"), "a fenced block leaked into prose");
});

test("prose ranges are ordered and never overlap", () => {
  const text = "a `b` c `d` e\n```\nf\n```\ng";
  const ranges = prose(text);

  for (let i = 1; i < ranges.length; i += 1) {
    assert.ok(ranges[i]!.from >= ranges[i - 1]!.to, "ranges overlap");
  }
  for (const range of ranges) assert.ok(range.from < range.to, "empty range");
});

test("text with no code at all is entirely prose", () => {
  const text = "just a sentence with @alice in it";
  assert.deepEqual(prose(text), [{ from: 0, to: text.length }]);
});
