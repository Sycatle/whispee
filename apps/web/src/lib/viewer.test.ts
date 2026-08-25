import assert from "node:assert/strict";
import { test } from "node:test";

import { chooseViewer, extensionOf, looksLikeAudio, looksLikeText } from "./viewer.ts";

/**
 * What is not covered here: whether any of these files actually decodes. That is the decoders'
 * question and it is asked of real bytes — `preview.test.ts` for images, `textfile.test.ts` for
 * UTF-8. This file only pins which decoder gets the attempt, which is a pure function of two
 * strings a sender wrote.
 */

test("extensionOf takes everything after the last dot", () => {
  assert.equal(extensionOf("notes.txt"), "txt");
  assert.equal(extensionOf("Notes.TXT"), "txt");
  assert.equal(extensionOf("archive.tar.gz"), "gz");
});

/**
 * The three shapes that have no extension and are routinely read as if they had one. A leading dot
 * names a hidden file; it does not open an extension.
 */
test("extensionOf reports nothing for names that carry none", () => {
  assert.equal(extensionOf("README"), "");
  assert.equal(extensionOf("Makefile"), "");
  assert.equal(extensionOf(".gitignore"), "");
  assert.equal(extensionOf(""), "");
  assert.equal(extensionOf("."), "");
});

/**
 * The name is never a path — `Attachment.tsx` states that rule and this keeps it true here. What
 * matters is that the answer does not depend on where the dots fell in the directory part.
 */
test("extensionOf reads the last segment, never the path around it", () => {
  assert.equal(extensionOf("../../etc/passwd.txt"), "txt");
  assert.equal(extensionOf("a.b/c"), "");
  assert.equal(extensionOf("C:\\Users\\me\\notes.md"), "md");
});

test("a declared text type is enough, with no extension at all", () => {
  assert.ok(looksLikeText("text/plain", "dump"));
  assert.ok(looksLikeText("text/plain; charset=utf-8", "dump"));
  assert.ok(looksLikeText("TEXT/PLAIN", "dump"));
});

/**
 * The case the union exists for: source almost always arrives as `application/octet-stream`, so
 * requiring the MIME to agree would lose every code snippet anybody sends.
 */
test("a known source extension is enough, whatever the type claims", () => {
  assert.ok(looksLikeText("application/octet-stream", "main.rs"));
  assert.ok(looksLikeText("application/octet-stream", "Cargo.toml"));
  assert.ok(looksLikeText("", "notes.md"));
});

test("structured syntax suffixes are text without being listed", () => {
  assert.ok(looksLikeText("application/ld+json", "thing"));
  assert.ok(looksLikeText("application/rss+xml", "feed"));
});

test("names that are their own type are recognised", () => {
  assert.ok(looksLikeText("application/octet-stream", "Makefile"));
  assert.ok(looksLikeText("application/octet-stream", ".gitignore"));
  assert.ok(looksLikeText("application/octet-stream", "LICENSE"));
});

test("an opaque binary is not text", () => {
  assert.ok(!looksLikeText("application/octet-stream", "installer.exe"));
  assert.ok(!looksLikeText("application/zip", "bundle.zip"));
});

test("audio is recognised from either hint", () => {
  assert.ok(looksLikeAudio("audio/mpeg", "clip"));
  assert.ok(looksLikeAudio("application/octet-stream", "voice.opus"));
  assert.ok(!looksLikeAudio("application/octet-stream", "voice.txt"));
});

/**
 * The branch worth pinning above all the others. A file carrying markup must be shown as source
 * and must never reach anything that could treat it as a document.
 */
test("markup goes to the text viewer, however it is announced", () => {
  assert.equal(chooseViewer("text/html", "page.html"), "text");
  assert.equal(chooseViewer("application/octet-stream", "page.html"), "text");
  assert.equal(chooseViewer("application/xml", "data.xml"), "text");
  assert.equal(chooseViewer("application/octet-stream", "drawing.svg"), "text");
});

/**
 * The deliberate exception, and the one that reads like a contradiction until the reason is said:
 * a declared SVG is rasterised by `createImageBitmap` into pixels this code drew, which is a
 * stronger answer than showing its markup. An `.svg` nobody called a picture gets the text
 * treatment instead — the case just above.
 */
test("a declared svg is rasterised rather than read", () => {
  assert.equal(chooseViewer("image/svg+xml", "drawing.svg"), "image");
});

test("each viewer is reached by the files that belong to it", () => {
  assert.equal(chooseViewer("application/pdf", "report.pdf"), "pdf");
  assert.equal(chooseViewer("application/octet-stream", "report.pdf"), "pdf");
  assert.equal(chooseViewer("audio/mpeg", "voice.mp3"), "audio");
  assert.equal(chooseViewer("image/png", "photo.png"), "image");
  assert.equal(chooseViewer("text/plain", "notes.txt"), "text");
});

/**
 * A lying MIME wins the routing and loses at the decoder, which is the whole design: routing is
 * cheap and reversible, decoding is where the refusal lives.
 */
test("a lie routes the file and does not survive it", () => {
  assert.equal(chooseViewer("application/pdf", "photo.png"), "pdf");
  assert.equal(chooseViewer("audio/mpeg", "installer.exe"), "audio");
});

test("anything unrecognised is offered no viewer at all", () => {
  assert.equal(chooseViewer("application/zip", "bundle.zip"), null);
  assert.equal(chooseViewer("application/octet-stream", "installer.exe"), null);
  assert.equal(chooseViewer("", ""), null);
});
