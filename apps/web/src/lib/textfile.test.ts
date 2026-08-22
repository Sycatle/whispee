import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MAX_LINE_CHARS,
  MAX_TEXT_LINES,
  decodeText,
  langOf,
  prepare,
} from "./textfile.ts";

/**
 * What is not covered: `readText`, which needs a `Blob`. Everything it decides beyond the size
 * test is `decodeText` and `prepare`, both of which are here.
 */

const bytes = (...values: number[]) => new Uint8Array(values).buffer;
const utf8 = (text: string) => new TextEncoder().encode(text).buffer as ArrayBuffer;

test("ordinary text decodes", () => {
  assert.equal(decodeText(utf8("hello")), "hello");
  assert.equal(decodeText(utf8("accents: éàü")), "accents: éàü");
  assert.equal(decodeText(utf8("outside the BMP: 𝄞 🇫🇷")), "outside the BMP: 𝄞 🇫🇷");
  assert.equal(decodeText(utf8("")), "");
});

/**
 * The whole point of `fatal: true`, asserted through the byte sequences that a lenient decoder
 * turns into U+FFFD and returns as if nothing happened.
 */
test("bytes that are not utf-8 are refused rather than patched", () => {
  assert.equal(decodeText(bytes(0xff, 0xfe, 0x00, 0x41)), null, "a UTF-16 BOM");
  assert.equal(decodeText(bytes(0xc3)), null, "a lead byte with no continuation");
  assert.equal(decodeText(bytes(0xed, 0xa0, 0x80)), null, "an encoded surrogate");
  assert.equal(decodeText(bytes(0xc0, 0x80)), null, "an overlong NUL");
  assert.equal(decodeText(bytes(0xf0, 0x82, 0x82, 0xac)), null, "an overlong euro sign");
  assert.equal(decodeText(bytes(0x80)), null, "a bare continuation byte");
});

/** A byte-for-byte valid file that is still not a document. */
test("valid utf-8 made of control characters is refused", () => {
  assert.equal(decodeText(utf8("text\u0000with a NUL")), null);
  assert.equal(decodeText(utf8("bell \u0007 here")), null);
  assert.equal(decodeText(utf8("escape \u001b[31m red")), null);
  assert.equal(decodeText(utf8("delete \u007f here")), null);
});

/**
 * The overrides matter more than the rest: they do not garble a line, they reverse it, so a file
 * can print something other than what it contains.
 */
test("bidirectional overrides are refused", () => {
  assert.equal(decodeText(utf8("innocent \u202e evil")), null);
  assert.equal(decodeText(utf8("isolate \u2066 here")), null);
});

test("the whitespace that belongs in a file survives", () => {
  assert.equal(decodeText(utf8("tab\there")), "tab\there");
  assert.equal(decodeText(utf8("line\nbreak")), "line\nbreak");
  assert.equal(decodeText(utf8("crlf\r\nhere")), "crlf\r\nhere");
});

/** A BOM is consumed rather than left at the head of the first line. */
test("a utf-8 bom does not survive into the text", () => {
  assert.equal(decodeText(utf8("\ufeffconst x = 1")), "const x = 1");
});

test("lines are split on every ending, including the mixed ones", () => {
  assert.deepEqual(prepare("a\nb\r\nc\rd", "f.txt").lines, ["a", "b", "c", "d"]);
  assert.deepEqual(prepare("", "f.txt").lines, [""]);
  assert.deepEqual(prepare("trailing\n", "f.txt").lines, ["trailing", ""]);
});

test("the line ceiling is inclusive and reported", () => {
  const exact = prepare("x\n".repeat(MAX_TEXT_LINES - 1) + "x", "f.txt");
  assert.equal(exact.lines.length, MAX_TEXT_LINES);
  assert.equal(exact.truncatedLines, false);

  const over = prepare("x\n".repeat(MAX_TEXT_LINES), "f.txt");
  assert.equal(over.lines.length, MAX_TEXT_LINES);
  assert.equal(over.truncatedLines, true);
});

/** The minified-bundle case: one line, past every other ceiling. */
test("a single enormous line is truncated and reported", () => {
  const exact = prepare("x".repeat(MAX_LINE_CHARS), "f.js");
  assert.equal(exact.truncatedColumns, false);

  const over = prepare("x".repeat(MAX_LINE_CHARS + 1), "f.js");
  assert.equal(over.lines[0]!.length, MAX_LINE_CHARS);
  assert.equal(over.truncatedColumns, true);
  assert.equal(over.truncatedLines, false);
});

test("the language is the extension, lowercased", () => {
  assert.equal(langOf("main.rs"), "rs");
  assert.equal(langOf("Main.TS"), "ts");
  assert.equal(langOf("archive.tar.gz"), "gz");
});

/** The three shapes that carry no extension, and are routinely read as if they did. */
test("names with no extension report none", () => {
  assert.equal(langOf("README"), null);
  assert.equal(langOf("Makefile"), null);
  assert.equal(langOf(".gitignore"), null, "a leading dot names a hidden file");
  assert.equal(langOf(""), null);
});

/** The name is never a path, so the answer must not depend on the directory part. */
test("only the last segment is read", () => {
  assert.equal(langOf("../../etc/passwd.txt"), "txt");
  assert.equal(langOf("C:\\Users\\me\\notes.md"), "md");
  assert.equal(langOf("a.b/c"), null);
});
