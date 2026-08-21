import assert from "node:assert/strict";
import { test } from "node:test";

import { pick, say } from "./i18n.ts";

test("a phrase is filled from its named holes", () => {
  assert.equal(
    say("membership.joined", { actor: "@alice", subject: "@bob" }, ["en"]),
    "@alice added @bob",
  );
});

test("a translation may put the holes in another order", () => {
  // The reason phrases are whole sentences rather than pieces glued together: word order is one
  // of the things that changes between languages, and a template can be reordered where a
  // concatenation cannot.
  assert.equal(
    say("membership.removed", { actor: "@alice", subject: "@bob" }, ["fr"]),
    "@alice a retiré @bob",
  );
});

test("a language is matched on its primary subtag", () => {
  // Somebody asking for fr-CA is better served French than English, even with no regional
  // catalogue.
  assert.equal(pick(["fr-CA"]), "fr");
  assert.equal(pick(["FR-ca"]), "fr");
});

test("the preference list is read in order", () => {
  // A reader who prefers Breton and accepts French gets French, not the fallback.
  assert.equal(pick(["br", "fr", "en"]), "fr");
  assert.equal(pick(["br", "en", "fr"]), "en");
});

test("an unknown language falls back to English", () => {
  assert.equal(pick(["br"]), "en");
  assert.equal(pick([]), "en");
  assert.equal(say("membership.left", { subject: "@bob" }, ["br"]), "@bob left");
});

test("a phrase missing from a catalogue falls back rather than disappearing", () => {
  // French is deliberately partial: a sentence in the wrong language is a poor result, a blank
  // line where a sentence belongs is a worse one. This asserts the fallback exists rather than
  // asserting which keys happen to be missing today.
  for (const phrase of ["membership.joined", "membership.left"] as const) {
    assert.notEqual(say(phrase, { actor: "@a", subject: "@b" }, ["fr"]), "");
  }
});

test("a hole with no value is left visible", () => {
  // The catalogue and the call site disagree. Showing `{subject}` is how that gets noticed;
  // an empty space reads as a sentence somebody wrote badly.
  assert.equal(say("membership.left", {}, ["en"]), "{subject} left");
});

test("values are substituted literally, including braces", () => {
  // A handle is somebody else's string. It must not be re-scanned for placeholders, or a peer
  // could name themselves `{actor}` and have their name replaced by somebody else's.
  assert.equal(
    say("membership.joined", { actor: "@alice", subject: "{actor}" }, ["en"]),
    "@alice added {actor}",
  );
});
