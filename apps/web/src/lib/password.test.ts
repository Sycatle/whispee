/**
 * A password check is only worth what it refuses. These cases are the ones the old length-plus-
 * short-list rule waved through, and each of them is a password someone would actually pick.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { MIN_LENGTH, check } from "./password.ts";

test("too short is refused before anything is loaded", async () => {
  const verdict = await check("a".repeat(MIN_LENGTH - 1));
  assert.equal(verdict.ok, false);
  assert.equal(verdict.guessesLog10, null, "no estimate should be claimed here");
});

/**
 * The whole reason for the dependency: these clear twelve characters, and several of them clear
 * the "uppercase, digit, symbol" rules too.
 */
test("guessable passwords are refused however they are dressed up", async () => {
  for (const password of [
    "password1234",
    "P@ssw0rd2024!",
    "qwertyuiop12",
    "januarysunshine",
    "aaaaaaaaaaaa",
    "Monkey123456",
  ]) {
    const verdict = await check(password);
    assert.equal(verdict.ok, false, `accepted ${password}`);
    assert.ok(verdict.reason.length > 0, `refused ${password} without saying why`);
  }
});

/** A password made of the account's own handle is a word list of one, and only we hold it. */
test("the account's handle counts as a dictionary", async () => {
  const withoutContext = await check("sycatle-marble-lantern");
  assert.equal(withoutContext.ok, true);

  const withContext = await check("sycatle-marble-lantern", ["sycatle"]);
  assert.ok(
    withContext.guessesLog10! < withoutContext.guessesLog10!,
    "knowing the handle should not make the password look stronger",
  );
});

test("a passphrase is accepted and reported with its order of magnitude", async () => {
  const verdict = await check("correct horse battery staple");
  assert.equal(verdict.ok, true);
  assert.equal(verdict.reason, "");
  assert.ok(verdict.guessesLog10! > 15, `only 10^${verdict.guessesLog10} guesses`);
});

/**
 * The case the old character-class arithmetic got backwards. Swapping letters for digits added a
 * whole class to it, so it credited `tr0ub4dor…` with several orders of magnitude it does not
 * have. An attacker applies the same swaps to the same word list; they are worth almost nothing,
 * and "almost" is the honest word — here, a factor of four.
 */
test("leet substitutions barely count as strength", async () => {
  const plain = await check("troubadorlantern");
  const leet = await check("tr0ub4dorl4nt3rn");
  assert.ok(
    leet.guessesLog10! - plain.guessesLog10! < 1,
    `substitutions bought ${leet.guessesLog10! - plain.guessesLog10!} orders of magnitude`,
  );
});
