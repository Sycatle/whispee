/**
 * The comparison, driven without a browser.
 *
 * An extension whose only evidence is "the icon went green when I clicked it" verifies nothing —
 * it is the same claim as an unaudited check, made by the thing doing the checking. What can be
 * tested here is everything that decides an answer: the parsing, the path mapping, and above all
 * that the failure cases fail.
 *
 * Run: `node --test extension/`
 */
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { test } from "node:test";

import {
  ALTERED,
  FOREIGN,
  MATCHED,
  UNLISTED,
  digest,
  parseManifest,
  pathOf,
  verdict,
  verifyResources,
} from "./verify.js";

const ORIGIN = "https://whispee.example";
const bytes = (text) => new TextEncoder().encode(text);

async function manifestFor(files) {
  const lines = [];
  for (const [path, content] of Object.entries(files)) {
    lines.push(`${await digest(bytes(content), webcrypto.subtle)}  ${path}`);
  }
  return parseManifest(lines.join("\n"));
}

function served(files) {
  return async (url) => {
    const path = url.slice(ORIGIN.length + 1).split(/[?#]/)[0];
    if (!(path in files)) throw new Error("404");
    return bytes(files[path]);
  };
}

test("a manifest in sha256sum format parses, and a header line does not break it", () => {
  const entries = parseManifest(
    ["# whispee", `${"a".repeat(64)}  index.html`, `${"b".repeat(64)}  assets/app.js`, ""].join(
      "\n",
    ),
  );

  assert.equal(entries.size, 2);
  assert.equal(entries.get("index.html"), "a".repeat(64));
  assert.equal(entries.get("assets/app.js"), "b".repeat(64));
});

test("a query string is not part of the path a manifest lists", () => {
  assert.equal(pathOf(`${ORIGIN}/assets/app.js?v=2`, ORIGIN), "assets/app.js");
  assert.equal(pathOf(`${ORIGIN}/index.html#top`, ORIGIN), "index.html");
});

test("a resource from another origin has no path here", () => {
  assert.equal(pathOf("https://cdn.example/app.js", ORIGIN), null);
  // The prefix check is on the origin plus a slash, so a lookalike host does not pass.
  assert.equal(pathOf("https://whispee.example.evil/app.js", ORIGIN), null);
});

test("an untouched deployment matches every file", async () => {
  const files = { "index.html": "<!doctype html>", "assets/app.js": "console.log(1)" };

  const findings = await verifyResources({
    urls: Object.keys(files).map((path) => `${ORIGIN}/${path}`),
    origin: ORIGIN,
    manifest: await manifestFor(files),
    fetchBytes: served(files),
    subtle: webcrypto.subtle,
  });

  assert.deepEqual(
    findings.map((finding) => finding.state),
    [MATCHED, MATCHED],
  );
  assert.equal(verdict(findings), "ok");
});

/** **The test the extension exists for.** One byte, and the answer has to change. */
test("one altered byte fails the whole page", async () => {
  const published = { "index.html": "<!doctype html>", "assets/app.js": "console.log(1)" };
  const actuallyServed = { ...published, "assets/app.js": "console.log(1);evil()" };

  const findings = await verifyResources({
    urls: Object.keys(published).map((path) => `${ORIGIN}/${path}`),
    origin: ORIGIN,
    manifest: await manifestFor(published),
    fetchBytes: served(actuallyServed),
    subtle: webcrypto.subtle,
  });

  assert.equal(findings.find((finding) => finding.path === "assets/app.js").state, ALTERED);
  assert.equal(verdict(findings), "failed");
});

/**
 * The obvious way past a hash check: do not touch the listed files, add one.
 *
 * A verifier that walked the manifest and stopped there would report a clean page while an
 * injected script ran beside it. This walks what the page **loaded**, so an extra file is a
 * finding rather than an absence.
 */
test("a script the manifest never described is a failure, not a silence", async () => {
  const published = { "index.html": "<!doctype html>" };
  const actuallyServed = { ...published, "assets/injected.js": "exfiltrate()" };

  const findings = await verifyResources({
    urls: [`${ORIGIN}/index.html`, `${ORIGIN}/assets/injected.js`],
    origin: ORIGIN,
    manifest: await manifestFor(published),
    fetchBytes: served(actuallyServed),
    subtle: webcrypto.subtle,
  });

  assert.equal(findings.find((finding) => finding.path === "assets/injected.js").state, UNLISTED);
  assert.equal(verdict(findings), "failed");
});

/** The other way round: keep the files, load the payload from somewhere else. */
test("a resource pulled from another origin fails too", async () => {
  const published = { "index.html": "<!doctype html>" };

  const findings = await verifyResources({
    urls: [`${ORIGIN}/index.html`, "https://cdn.evil/payload.js"],
    origin: ORIGIN,
    manifest: await manifestFor(published),
    fetchBytes: served(published),
    subtle: webcrypto.subtle,
  });

  assert.equal(findings.find((finding) => finding.url.includes("evil")).state, FOREIGN);
  assert.equal(verdict(findings), "failed");
});

/** Unreachable is not innocent: the page ran it, so something served it. */
test("a resource that cannot be re-fetched counts against the verdict", async () => {
  const published = { "index.html": "<!doctype html>", "assets/app.js": "console.log(1)" };

  const findings = await verifyResources({
    urls: Object.keys(published).map((path) => `${ORIGIN}/${path}`),
    origin: ORIGIN,
    manifest: await manifestFor(published),
    fetchBytes: served({ "index.html": published["index.html"] }),
    subtle: webcrypto.subtle,
  });

  assert.equal(findings.find((finding) => finding.path === "assets/app.js").state, ALTERED);
  assert.equal(verdict(findings), "failed");
});

/**
 * Nothing checked is not the same as nothing wrong.
 *
 * A verdict of `ok` on an empty list would paint the icon green for a page the extension never
 * looked at, which is the single most dangerous thing it could display.
 */
test("checking nothing answers unknown rather than ok", () => {
  assert.equal(verdict([]), "unknown");
});
