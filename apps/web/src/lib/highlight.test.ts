import assert from "node:assert/strict";
import { test } from "node:test";

import { MAX_HIGHLIGHT, type Kind, grammarFor, tokenize } from "./highlight.ts";

/**
 * What is not covered here: whether the colours are *right*. This tokeniser is approximate by
 * design — it has no notion of scope and cannot tell a type from a variable — so asserting a kind
 * for every token would pin the approximation rather than the contract.
 *
 * What is covered is the contract: not one character is lost, nothing hangs, and nothing is
 * guessed for a language with no grammar.
 */

const SAMPLES: ReadonlyArray<readonly [string, string]> = [
  ["ts", 'const x: number = 1; // note\nfunction f() { return `a${x}b`; }'],
  ["rust", 'pub fn main() {\n    let s = "hi\\n"; /* block */\n    println!("{s}");\n}'],
  ["python", '# comment\ndef f(a, b=1):\n    return """triple\nquoted""" if a else None'],
  ["go", 'package main\n\nfunc main() {\n\tx := `raw`\n\t_ = x // done\n}'],
  ["json", '{"a": [1, 2.5, true, null], "b": "text with \\" quote"}'],
  ["sql", "-- pick\nSELECT * FROM t WHERE a = 'x' AND b IS NOT NULL;"],
  ["bash", '#!/bin/bash\nfor f in *.txt; do echo "$f"; done'],
  ["css", ".a { color: red; /* why */ }\n@media (min-width: 1px) { .b { top: 0 } }"],
  ["yaml", "# config\nkey: value\nlist:\n  - true\n  - 'quoted'"],
  ["html", "<!-- note -->\n<div class=\"a\">text</div>"],
];

/**
 * The invariant worth more than every other test in this file.
 *
 * A scanner that loses or duplicates a character silently rewrites somebody's code sample. That is
 * strictly worse than colouring it wrongly, and it is invisible in a screenshot.
 */
test("the tokens reassemble into exactly the input", () => {
  for (const [lang, code] of SAMPLES) {
    const joined = tokenize(code, lang)
      .map((t) => t.text)
      .join("");
    assert.equal(joined, code, `${lang} did not round trip`);
  }
});

/**
 * The shapes that break a scanner written for well-formed input: line endings it did not expect,
 * a lone surrogate, a NUL, and every construct left open at the end.
 */
test("the round trip holds for input nobody meant to be valid", () => {
  const nasty = [
    "",
    "\n",
    "\r\n\r\n",
    " ",
    "\u0000",
    "\ud800",
    "text with \ud800 lone surrogate",
    '"unterminated string',
    "/* unterminated block",
    "'''unterminated triple",
    "\\",
    "a\\",
    "`",
    "0x",
    "1..2",
    "...",
    "\t\t  ",
    "é".repeat(100),
    "🇫🇷👍🏽",
  ];

  for (const [lang] of SAMPLES) {
    for (const code of nasty) {
      const joined = tokenize(code, lang)
        .map((t) => t.text)
        .join("");
      assert.equal(joined, code, `${lang} lost characters on ${JSON.stringify(code)}`);
    }
  }
});

/** Deterministic pseudo-random source: a seeded walk, so a failure can be reproduced. */
function fuzz(seed: number, length: number): string {
  const alphabet = "abc {}()[];:,.<>+-*/%=!&|^~?@#\"'`\\\n\t 019_$";
  let state = seed;
  let out = "";
  for (let i = 0; i < length; i += 1) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    out += alphabet[state % alphabet.length];
  }
  return out;
}

test("the round trip holds under fuzzing, and the scan always terminates", () => {
  for (let seed = 1; seed <= 40; seed += 1) {
    const code = fuzz(seed, 400);
    for (const lang of ["ts", "rust", "python", "sql", "html"]) {
      const joined = tokenize(code, lang)
        .map((t) => t.text)
        .join("");
      assert.equal(joined, code, `seed ${seed} lost characters in ${lang}`);
    }
  }
});

/**
 * Nothing is guessed. A neutral fallback grammar applied to a language that does not use `//` or
 * `#` greys out half a message, and no colour is never wrong where a wrong colour is.
 */
test("a language with no grammar gets one plain token and no guesses", () => {
  for (const lang of [null, "", "brainfuck", "cobol", "not-a-language"]) {
    const tokens = tokenize("// looks like a comment\n# and so does this", lang);
    assert.equal(tokens.length, 1);
    assert.equal(tokens[0]?.kind, "plain");
  }
  assert.equal(grammarFor("cobol"), null);
  assert.equal(grammarFor(null), null);
});

test("an empty block produces no tokens at all", () => {
  assert.deepEqual(tokenize("", "ts"), []);
  assert.deepEqual(tokenize("", null), []);
});

test("aliases reach the grammar they name", () => {
  for (const [alias, sample] of [
    ["typescript", "const"],
    ["tsx", "const"],
    ["js", "const"],
    ["rs", "fn"],
    ["py", "def"],
    ["sh", "done"],
    ["yml", "true"],
  ] as const) {
    const kinds = tokenize(sample, alias).map((t) => t.kind);
    assert.ok(kinds.includes("keyword"), `${alias} did not resolve to a grammar`);
  }
});

/** A keyword must be the whole identifier. This is the mistake a prefix match makes. */
test("a word that merely starts with a keyword is not one", () => {
  for (const word of ["iffy", "forEach", "returnValue", "classify", "constant", "news"]) {
    const kinds = tokenize(word, "ts").map((t) => t.kind);
    assert.ok(!kinds.includes("keyword"), `${word} was read as a keyword`);
  }
  assert.deepEqual(tokenize("if", "ts"), [{ kind: "keyword", text: "if" }]);
});

test("comments run to their end and no further", () => {
  const [comment, rest] = tokenize("// note\ncode", "ts");
  assert.deepEqual(comment, { kind: "comment", text: "// note" });
  assert.ok(rest !== undefined && rest.text.startsWith("\n"));

  const [block] = tokenize("/* a */ b", "ts");
  assert.deepEqual(block, { kind: "comment", text: "/* a */" });
});

test("an escaped quote does not close its string", () => {
  const [token] = tokenize('"a\\"b" c', "ts");
  assert.equal(token?.kind, "string");
  assert.equal(token?.text, '"a\\"b"');
});

/** Longest opener first, or `"""` is read as an empty string followed by a quote. */
test("a triple-quoted python string is one token", () => {
  const [token] = tokenize('"""a\nb"""', "python");
  assert.equal(token?.kind, "string");
  assert.equal(token?.text, '"""a\nb"""');
});

test("a block past the ceiling is left uncoloured rather than dropped", () => {
  const huge = "const x = 1;\n".repeat(Math.ceil(MAX_HIGHLIGHT / 12) + 10);
  const tokens = tokenize(huge, "ts");

  assert.equal(tokens.length, 1);
  assert.equal(tokens[0]?.kind, "plain");
  assert.equal(tokens[0]?.text, huge);
});

test("every token carries a known kind", () => {
  const known: ReadonlySet<Kind> = new Set<Kind>([
    "comment",
    "string",
    "keyword",
    "number",
    "punct",
    "plain",
  ]);

  for (const [lang, code] of SAMPLES) {
    for (const token of tokenize(code, lang)) {
      assert.ok(known.has(token.kind), `${lang} produced ${token.kind}`);
      assert.ok(token.text.length > 0, `${lang} produced an empty token`);
    }
  }
});
