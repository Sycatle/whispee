/**
 * The one string in this client that a person chooses for themselves, and that another person's
 * screen then has to render.
 *
 * A handle is minted by the server, constrained by its own grammar, and immutable in practice —
 * it is the identity bytes of the MLS credential, the prefix of every `device_id`, a key in
 * several persisted records. A display name is none of that: it is free text, changed as often
 * as its owner likes, and it arrives **from a peer**, decrypted out of a group message. Nothing
 * upstream of this module constrains it.
 *
 * # The contract, which is the whole point of the module
 *
 * `sanitize` applies **on input and on receipt, never one without the other**. Cleaning only what
 * is typed locally protects nobody: the hostile name is the one that comes over the wire, written
 * by someone who chose every code point on purpose. Cleaning only what arrives leaves this
 * device's own name to be carried, in its raw form, into everyone else's interface. Both sides,
 * every time.
 *
 * # What it does not solve
 *
 * **Homoglyphs.** Nothing here stops someone calling themselves "Alicе" with a Cyrillic е, and no
 * amount of normalisation would: the code points are legitimate, distinct, and rendered
 * identically. That is why the display name is never the identity — the handle is, it is always
 * shown next to the name, and the fingerprint is what actually settles the question. A name is a
 * convenience, and this module keeps it from becoming a weapon; it cannot make it evidence.
 */

/**
 * Why a name was refused, as a code and not a sentence.
 *
 * These are pure modules with no notion of a locale. Turning a code into words is the business of
 * the display boundary, which knows what language the person reads; a sentence returned from here
 * would either be English for everybody or drag a translation table into a string validator.
 */
export type DisplayNameError = "too-long" | "empty";

/**
 * Two ceilings, both enforced, because they bound different things.
 *
 * Code points bound legibility: thirty-two of them is already a long name in a list of
 * conversations. Bytes bound the wire format, whose length field the encoder and every decoder
 * have to agree on. Neither implies the other — thirty-two emoji are well past sixty-four bytes,
 * and sixty-four bytes of Latin text are well under thirty-two code points.
 */
export const MAX_CODE_POINTS = 32;
export const MAX_BYTES = 64;

/**
 * Controls, replaced by a space rather than deleted.
 *
 * C0 and C1, including newline and tab. A name is one line: a name that holds two would break out
 * of the row it is drawn in. They become a space instead of vanishing because deleting them welds
 * the words on either side together — "Charlie\nthe second" would come back as one word nobody
 * wrote, which is a different name rather than a cleaner one. The collapse below then absorbs the
 * space if there was already one.
 */
const CONTROLS = /[\u0000-\u001F\u007F-\u009F]/gu;

/**
 * Invisible formatting, deleted outright.
 *
 * The bidi marks, embeddings, overrides and isolates — `U+200E`, `U+200F`, `U+202A`-`U+202E`,
 * `U+2066`-`U+2069` — reorder the text **around** them: a right-to-left override in a name
 * reverses the handle rendered after it, which is exactly how a peer makes "@charlie8295" read as
 * somebody else. And `U+FEFF`, invisible by construction, which lets two distinct names look
 * identical.
 *
 * Deleted and not spaced, unlike the controls above: these occupy no width, so a space in their
 * place would be a space the author never typed.
 */
const INVISIBLE = /[\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/gu;

/**
 * Cleans a name, whoever it came from.
 *
 * NFC first, so that a name typed with combining marks compares and measures the same as the one
 * typed with precomposed characters — otherwise two identical-looking names occupy different byte
 * counts and only one of them fits.
 *
 * Whitespace runs collapse to a single space and the ends are trimmed. That covers the ordinary
 * accident, a double space from a fast keyboard, and the deliberate one: a name padded with
 * thirty spaces to push the handle out of a fixed-width row.
 *
 * The result may be empty, and an empty name is a name that is **absent** — the display falls
 * back to `@handle`, which always exists. That is deliberate: refusing to store the empty string
 * would leave no way to take a name back off.
 */
export function sanitize(input: string): string {
  return input
    .normalize("NFC")
    .replace(CONTROLS, " ")
    .replace(INVISIBLE, "")
    .replace(/\s+/gu, " ")
    .trim();
}

/**
 * Judges a name that has **already** been through `sanitize`.
 *
 * Validation is separate from cleaning because they answer to different people. Cleaning is
 * silent and always applies; validation produces a refusal somebody has to be shown, and the
 * caller decides how. Running them together would mean a name could be rejected for characters
 * the caller never typed and cannot see.
 *
 * Nothing here truncates. A name over the ceiling is refused and handed back, because silently
 * cutting it would change somebody's name without telling them — and the half that survived would
 * be the half that fits, not the half they meant.
 */
export function validate(name: string): DisplayNameError | null {
  if (name.length === 0) return "empty";
  if ([...name].length > MAX_CODE_POINTS) return "too-long";
  if (new TextEncoder().encode(name).length > MAX_BYTES) return "too-long";
  return null;
}
