/**
 * The handle format is duplicated in three places — this module, `crates/server/src/handle.rs`
 * and `crates/server/migrations/0013_handle_format.sql` — with nothing mechanical keeping them
 * aligned. These tests pin the same cases the Rust ones pin, which is the only thing that would
 * notice a drift before a user did.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { MAX_LENGTH, normalize, suggest, validate } from "./handle.ts";

test("a handle is lowercased and stripped of its leading at", () => {
  assert.equal(normalize("@Alice"), "alice");
  assert.equal(normalize("  ALICE  "), "alice");
  assert.equal(normalize("@alice"), "alice");
});

/** NFKC has to run before the lowercasing, or a fullwidth capital survives the fold. */
test("compatibility lookalikes are folded to their plain form", () => {
  assert.equal(normalize("Ａlice"), "alice");
  assert.equal(normalize("𝐚lice"), "alice");
});

/** Only the sigil, and only at the front: an at-sign elsewhere is not one. */
test("only a leading at-sign is a sigil", () => {
  assert.equal(normalize("@@alice"), "@alice");
  assert.equal(normalize("al@ice"), "al@ice");
  assert.ok(validate(normalize("al@ice")) !== null);
});

/** Normalisation never repairs: deciding which account was meant is not its job. */
test("a space in the middle survives normalisation and is then refused", () => {
  assert.equal(normalize("alice smith"), "alice smith");
  assert.equal(validate("alice smith"), "bad-characters");
});

test("a handle with a colon is refused because it would split a device id", () => {
  assert.equal(validate("alice:phone"), "bad-characters");
  assert.equal(validate(normalize("@Alice:phone")), "bad-characters");
});

test("a capital letter is refused because case would fork an identity", () => {
  assert.equal(validate("Alice"), "bad-characters");
  assert.equal(validate(normalize("Alice")), null);
});

test("anything outside ascii is refused whatever it looks like", () => {
  // A Cyrillic `а`, indistinguishable from the Latin one in most faces.
  assert.equal(validate("аlice"), "bad-characters");
  assert.equal(validate("alicé"), "bad-characters");
  // A right-to-left override reverses everything drawn after it.
  assert.equal(validate("alice‮bob"), "bad-characters");
  // A zero-width joiner is not visible at all.
  assert.equal(validate("ali‍ce"), "bad-characters");
});

test("the length bounds are inclusive at both ends", () => {
  assert.equal(validate("ab"), "too-short");
  assert.equal(validate("abc"), null);
  assert.equal(validate("a".repeat(MAX_LENGTH)), null);
  assert.equal(validate("a".repeat(MAX_LENGTH + 1)), "too-long");
});

test("underscores and digits are the only company letters keep", () => {
  assert.equal(validate("alice_smith"), null);
  assert.equal(validate("alice2"), null);
  assert.equal(validate("2alice"), null);
  assert.equal(validate("alice-smith"), "bad-characters");
  assert.equal(validate("alice.smith"), "bad-characters");
});

/**
 * The point of drawing the digits instead of counting them. A counter would answer the question
 * "how many people already wanted this name?" to anybody who asked, unauthenticated.
 */
test("a suggestion never reveals how many accounts already took the base", () => {
  const first = suggest("charlie", () => 0.4242);
  const second = suggest("charlie", () => 0.9137);

  assert.notEqual(first, second);
  // Neither is an increment of the base, and neither is a small ordinal.
  for (const proposal of [first, second]) {
    assert.match(proposal, /^charlie\d{4}$/);
    assert.ok(!/^charlie[1-9]$/.test(proposal));
  }

  // The whole draw is used, low values included, and they stay four digits wide so that a
  // small number is not mistakable for a position in a queue.
  assert.equal(suggest("charlie", () => 0), "charlie0000");
  assert.equal(suggest("charlie", () => 0.99999), "charlie9999");
});

test("a suggestion normalises its base and stays inside the length ceiling", () => {
  assert.equal(suggest("@Alice", () => 0.1234), "alice1234");

  const proposal = suggest("a".repeat(60), () => 0.5);
  assert.equal(proposal.length, MAX_LENGTH);
  assert.equal(validate(proposal), null);
});
