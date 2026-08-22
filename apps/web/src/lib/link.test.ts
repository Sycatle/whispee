import assert from "node:assert/strict";
import { test } from "node:test";

import { classify, mixesScripts, scan, trimTrailing } from "./link.ts";

/**
 * What is not covered here: whether refusing to link a deceptive URL actually stops anybody. It
 * does not, on its own — the text is still there to be copied, and that is deliberate. What these
 * pin is the classification, which is the part a component can only get wrong once.
 */

test("a url is found with either opener", () => {
  assert.equal(scan("see https://example.com/a")[0]?.raw, "https://example.com/a");
  assert.equal(scan("see http://example.com")[0]?.raw, "http://example.com");
  assert.equal(scan("see www.example.com")[0]?.href, "https://www.example.com/");
});

/**
 * Bare domains are not scanned, and the reason is that the false positives are ordinary writing
 * rather than exotic input. Every one of these appears in a normal sentence about code.
 */
test("things that merely contain a dot are left as prose", () => {
  assert.deepEqual(scan("open main.js and index.ts"), []);
  assert.deepEqual(scan("we shipped v1.2 yesterday"), []);
  assert.deepEqual(scan("e.g. this one"), []);
  assert.deepEqual(scan("Acme Corp.Ltd"), []);
});

test("punctuation that ends a sentence is not part of the url", () => {
  assert.equal(trimTrailing("https://x.com/a."), "https://x.com/a");
  assert.equal(trimTrailing("https://x.com/a,"), "https://x.com/a");
  assert.equal(trimTrailing("https://x.com/a?!"), "https://x.com/a");
  assert.equal(scan("look at https://x.com/a. Then stop.")[0]?.raw, "https://x.com/a");
});

/**
 * The pair that has to be told apart, and the reason `trimTrailing` counts rather than strips.
 * Both spellings are common enough that getting either wrong is noticed the same day.
 */
test("a closing bracket is trimmed only when it has no opener inside the url", () => {
  // What the scanner actually hands over: the run starts at the scheme, so an opening bracket
  // written before the URL is never part of it and the closer is unbalanced.
  assert.equal(trimTrailing("https://x.com/a)"), "https://x.com/a");
  assert.equal(
    trimTrailing("https://en.wikipedia.org/wiki/A_(b)"),
    "https://en.wikipedia.org/wiki/A_(b)",
  );
  assert.equal(scan("(see https://x.com/a)")[0]?.raw, "https://x.com/a");
});

test("trimming a bracket exposes the full stop behind it", () => {
  assert.equal(trimTrailing("https://x.com/a)."), "https://x.com/a");
});

/**
 * The load-bearing rule of the module. A blacklist would have to be kept complete; this asserts
 * the whitelist by trying the three spellings of the same hole plus the two that would reach the
 * local machine.
 */
test("no scheme but http and https is ever offered as a link", () => {
  for (const raw of [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "blob:https://example.com/uuid",
    "file:///etc/passwd",
    "vbscript:msgbox(1)",
    "ftp://example.com/x",
    "mailto:a@b.com",
  ]) {
    assert.equal(classify(raw), null, `${raw} was accepted`);
  }
});

/**
 * `https://` alone does not parse, so it never reaches the host check. `http:///path` does parse,
 * and the WHATWG parser absorbs the extra slash and reads `path` as the *hostname* — so this is
 * not a URL without a host, it is a URL to a host called `path`.
 *
 * Left to link rather than refused. Requiring a dot would be the way to reject it, and that would
 * also reject `localhost` and every intranet name, which are legitimate things to send. A
 * hostname that resolves nowhere is a broken link, and a broken link is not a security problem.
 */
test("a url with no parseable host is refused, and a one-label host is not", () => {
  assert.equal(classify("https://"), null);
  assert.equal(classify("http:///path")?.host, "path");
});

/**
 * The most effective spelling there is: a human reads it left to right and stops at the first
 * dot-com, a browser reads the authority after the `@`.
 */
test("credentials in the authority are the strongest signal, and outrank the others", () => {
  const link = classify("https://paypal.com@evil.tld/login");
  assert.equal(link?.deception, "userinfo");
  assert.equal(link?.host, "evil.tld");
});

test("a non-ascii hostname is reported by its punycode name", () => {
  const link = classify("https://xn--80ak6aa92e.com/");
  assert.equal(link?.deception, "punycode");
  assert.equal(link?.host, "xn--80ak6aa92e.com");
});

/**
 * `аpple.com` with a Cyrillic first letter. The check runs on the written form because parsing is
 * what destroys the evidence — by the time `URL` is done, this is just another `xn--`.
 */
test("one label mixing latin with a lookalike script is deceptive", () => {
  assert.ok(mixesScripts("аpple.com"));
  assert.equal(classify("https://аpple.com/")?.deception, "mixed-script");
});

/**
 * The case a whole-hostname test would flag wrongly. A domain written entirely in one script
 * imitates nothing; it is somebody's actual address.
 */
test("a hostname honestly in one non-latin script is not mixed", () => {
  assert.ok(!mixesScripts("москва.рф"));
  // It still normalises to punycode, which is what a reader is shown, and that is reported.
  assert.equal(classify("https://москва.рф/")?.deception, "punycode");
});

test("an ordinary url carries no accusation", () => {
  const link = classify("https://example.com/a/b?c=1#d");
  assert.equal(link?.deception, null);
  assert.equal(link?.host, "example.com");
});

test("a port and a path survive untouched", () => {
  assert.equal(classify("https://example.com:8443/x")?.host, "example.com");
  assert.equal(classify("https://example.com/a_b-c~d")?.deception, null);
});

test("several urls in one message come back in order", () => {
  const found = scan("first https://a.example second https://b.example done");
  assert.deepEqual(
    found.map((f) => f.host),
    ["a.example", "b.example"],
  );
  assert.ok(found[0]!.to <= found[1]!.from);
});

/** The offsets have to name the trimmed run, or a renderer would slice the sentence wrongly. */
test("the reported span covers exactly the url", () => {
  const text = "go to https://x.com/a. now";
  const [found] = scan(text);
  assert.equal(text.slice(found!.from, found!.to), "https://x.com/a");
});

/**
 * Bidirectional overrides inside a URL are how a hostname is made to print in an order it does
 * not have. The scanner stops at them rather than swallowing them into the run.
 */
test("the scan stops at a bidi override", () => {
  const found = scan("https://example.com/‮gnp.exe");
  assert.equal(found[0]?.raw, "https://example.com/");
});

test("a lone scheme is not a link", () => {
  assert.deepEqual(scan("https://"), []);
  assert.deepEqual(scan("see https:// then"), []);
});
