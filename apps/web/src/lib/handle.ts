/**
 * The canonical form of a handle, on the client side.
 *
 * # Why handles have a shape at all
 *
 * Two defects, both of them real and both of them fixed by the same rule.
 *
 * **The roster compares handles to decide who administers a group.** The Rust side
 * (`crates/crypto-core/src/roles.rs`) matches the string found in the roster against the string
 * a member presents, and nothing normalises either. With case free, `Alice` and `alice` are two
 * accounts that draw identically in every list on every screen, and the second one can be
 * registered deliberately after the first. That is an impersonation primitive aimed straight at
 * an authorisation check, not a display nuisance.
 *
 * **A colon in a handle makes a device id ambiguous.** Device ids are `handle:name`, and the
 * server used to check the prefix with a `startsWith`. If `alice:phone` may be a handle, then the
 * id `alice:phone:laptop` is prefixed by two different accounts. Forbidding `:` is what lets
 * `routes::register_device` split on the first colon and compare for equality.
 *
 * # What the rule does not solve
 *
 * `^[a-z0-9_]{3,32}$` kills the wide classes — case, whitespace, bidi overrides, invisible
 * joiners, the entirety of non-ASCII. It does **not** kill typographic confusion. `_` is a quiet
 * separator, so `alice_smith` and `alicesmith` are two accounts a hurried eye reads as one; `rn`
 * still resolves to `m` at body size; `0`, `o` and `O` are three glyphs and only two of them are
 * admitted, which helps and does not finish the job.
 *
 * Nothing about a naming rule ever finishes that job. What does is elsewhere and already exists:
 * the `@handle` shown in full and permanently next to every message, and the fingerprint in the
 * detail panel. This module removes the confusions a rule can remove so the remaining ones stay
 * visible instead of hiding behind an invisible character.
 *
 * # Why this file duplicates `crates/server/src/handle.rs`
 *
 * Because the two answer different questions. The server's copy decides what is *stored*; this
 * one decides what the field shows red before anything is sent, and what `suggest` proposes when
 * a handle is taken. A client that had to ask the server whether a keystroke was legal would be
 * a round trip per character.
 *
 * They are a duplicated rule with no mechanism keeping them aligned — the Rust function is the
 * authority, and if the two ever disagree this file is the bug. The tests here pin the same
 * cases the Rust tests pin, which is the only thing that would catch a drift.
 *
 * # Why the errors are tokens and not sentences
 *
 * `validate` returns `"too-short"`, not "Handle must be at least 3 characters". Translation
 * happens at the display boundary, and a module that returns English prose has decided, on
 * behalf of every caller, that the product is English. These functions are pure and carry no
 * presentation; the component that renders the field owns the words.
 */

/** Shortest accepted handle. Two-character handles are a land grab, not a name. */
export const MIN_LENGTH = 3;

/** Longest accepted handle. It is shown in full everywhere, so it has to fit. */
export const MAX_LENGTH = 32;

/** What is wrong with a handle, as a token for the display layer to translate. */
export type HandleError = "too-short" | "too-long" | "bad-characters";

/**
 * Puts a typed handle into the form the server will accept, where that is possible without
 * guessing.
 *
 * Four steps, each for its own reason:
 *
 * **NFKC first**, before anything else looks at the string. It folds the compatibility forms — a
 * fullwidth `ａ` becomes `a`, a mathematical bold `𝐚` becomes `a` — so the subsequent checks see
 * one representation instead of a family of lookalikes. Doing it after the lowercasing would let
 * a fullwidth capital survive the fold it was supposed to be caught by.
 *
 * **`trim()`**, because a handle pasted from anywhere arrives with whitespace and refusing it
 * would be pedantry: there is exactly one thing the user meant.
 *
 * **A leading `@` removed**, for the same reason. The product prints `@alice` everywhere, so
 * people type `@alice` back. Only one, and only at the front: an `@` anywhere else is not a
 * sigil, it is a character that has no business in a handle, and silently deleting it would
 * change which account the user is addressing.
 *
 * **Lowercased last**, once the string is otherwise settled.
 *
 * What it does not do: it never removes a character to make an invalid handle valid. A space in
 * the middle stays a space and `validate` refuses it. Normalisation that repairs is
 * normalisation that decides for the user which account they meant.
 */
export function normalize(input: string): string {
  return input.normalize("NFKC").trim().replace(/^@/, "").toLowerCase();
}

/**
 * Accepts a handle, or names in one token what is wrong with it. `null` means valid.
 *
 * The length is counted in UTF-16 code units, which is what `.length` gives. For every handle
 * this function *accepts* that is exact: the alphabet is pure ASCII, so code units, characters
 * and bytes are the same number, and the mirror of this rule in `crates/server/src/handle.rs`
 * counts characters and lands on the same answer.
 *
 * The checks run length-first, and that ordering is a choice about which message a person reads.
 * The floor and the ceiling are the two limits someone meets by accident, typing a nickname that
 * happens to be two letters; the alphabet is the one they meet on purpose. Reporting
 * `"too-short"` for `ab` is worth more than a single undifferentiated complaint.
 *
 * What the ordering costs, on rejected input only: surrogate pairs make `.length` overcount by
 * one per astral character, so a string of seventeen emoji is reported `"too-long"` when
 * `"bad-characters"` is the truer answer. It is the wrong reason attached to a value that is
 * refused either way, and it is the acceptable half of the trade.
 *
 * This function does **not** normalise. It is the predicate, and a predicate that quietly fixed
 * its input could never be used to tell the user their input needs fixing. Callers normalise
 * first; the input field does it on every keystroke.
 */
export function validate(handle: string): HandleError | null {
  if (handle.length < MIN_LENGTH) return "too-short";
  if (handle.length > MAX_LENGTH) return "too-long";
  if (!/^[a-z0-9_]+$/.test(handle)) return "bad-characters";
  return null;
}

/** Where the suggested digits are cut from, so the result always fits `MAX_LENGTH`. */
const SUGGESTION_STEM = MAX_LENGTH - 4;

/**
 * Proposes a free-looking variant of a taken handle: the stem, then four digits.
 *
 * # The digits are drawn, never counted
 *
 * This is the whole reason the function exists rather than being a one-line template. The
 * obvious implementation appends the first unused integer — `charlie2`, then `charlie3` — and
 * that number is a **population count published to whoever asked**. Being offered `charlie2`
 * tells you `charlie1` exists; being offered `charlie47` tells you a great deal more, and it
 * tells it to an unauthenticated caller, since account creation is open by construction.
 *
 * Four random digits say nothing. They collide sometimes, and the collision costs one more
 * round trip through the same 409 the caller was already handling — which is the correct price
 * for a suggestion that carries no information about anybody else.
 *
 * # Why the generator is a parameter
 *
 * So this module stays pure and the test can pin the output. The caller supplies the randomness,
 * and it must supply real randomness: `crypto.getRandomValues`, not `Math.random`. That is not
 * ceremony about unpredictability — nobody attacks a suggestion by predicting it — it is that
 * `Math.random` is seeded per context in ways that make two fresh tabs propose the same handle,
 * which turns a collision-avoidance mechanism into a collision generator.
 *
 * # What it does not do
 *
 * It does not check availability: it has no network and should not grow one. It proposes, the
 * caller submits, and the server is the only thing that knows. And it does not guarantee the
 * result is valid — if `base` normalises to something empty or unusable, the digits alone are
 * not a handle anyone asked for. Callers validate what comes back, as they would validate what
 * the user typed.
 *
 * @param random Returns a float in [0, 1), as `Math.random` does — the shape, not the source.
 */
export function suggest(base: string, random: () => number): string {
  const stem = normalize(base).slice(0, SUGGESTION_STEM);
  const digits = Math.floor(random() * 10000)
    .toString()
    .padStart(4, "0");
  return `${stem}${digits}`;
}
