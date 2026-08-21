/**
 * Password policy.
 *
 * # Why not "one uppercase, one digit, one symbol"
 *
 * Those rules create no entropy: they move the `A` to the front and the `1!` to the end. The
 * space of passwords a human produces under those constraints is smaller, not larger — and
 * attackers know it better than we do. NIST explicitly dropped them in SP 800-63B.
 *
 * What actually counts: **length**, and **not appearing in a known list**. That is what this
 * module checks.
 *
 * # What this password protects
 *
 * State at rest on this device, nothing else. It is not a recovery factor: forgetting it loses
 * nothing, the twelve-word phrase remains the only restore path.
 */

/** Minimum length. Twelve characters of everyday prose are worth ~40 bits — the floor below
 * which even Argon2id no longer makes an offline attack expensive. */
export const MIN_LENGTH = 12;

/**
 * The passwords and patterns most often seen in breaches.
 *
 * This list is deliberately short: it catches the obvious cases without weighing down the
 * bundle. **A real deployment would use the full list** — the first 10,000 of rockyou, or the
 * k-anonymous Have I Been Pwned API, which checks without revealing the password. That is noted
 * in the README's known limits rather than half-done in silence.
 */
const COMMON = [
  "motdepasse", "password", "azertyuiop", "qwertyuiop", "123456789", "1234567890",
  "administrateur", "changeme", "letmein", "welcome1", "iloveyou", "sunshine",
  "princesse", "football", "monkey123", "dragon123", "abc123456", "passw0rd",
  "motdepasse1", "password1", "azerty123", "qwerty123", "000000000", "111111111",
];

export interface Verdict {
  ok: boolean;
  /** Message to display. Empty when the password is fine. */
  reason: string;
}

export function check(password: string): Verdict {
  if (password.length < MIN_LENGTH) {
    return {
      ok: false,
      reason: `At least ${MIN_LENGTH} characters. Length is what actually protects you — not uppercase letters or digits.`,
    };
  }

  const normalized = password.toLowerCase();

  if (COMMON.some((known) => normalized.includes(known))) {
    return {
      ok: false,
      reason: "This password contains a sequence found in known breach lists.",
    };
  }

  // A single repeated character, or a keyboard run, clears the minimum length while being worth
  // nothing: "aaaaaaaaaaaa" is twelve characters and zero bits of entropy.
  if (new Set(password).size <= 4) {
    return {
      ok: false,
      reason: "Too few distinct characters: length alone is not enough.",
    };
  }

  return { ok: true, reason: "" };
}

/**
 * Rough entropy estimate, in bits, to display as an indication.
 *
 * Rough and **optimistic**: it assumes a password drawn at random from the observed alphabet,
 * which no human ever does. A real estimator (zxcvbn) recognises dictionary words, dates and
 * substitutions; it weighs 400 KB. The displayed value is therefore a ceiling, to be presented
 * as one — never as a guarantee.
 */
export function approximateBits(password: string): number {
  const classes = [
    /[a-z]/.test(password) ? 26 : 0,
    /[A-Z]/.test(password) ? 26 : 0,
    /[0-9]/.test(password) ? 10 : 0,
    /[^a-zA-Z0-9]/.test(password) ? 33 : 0,
  ].reduce((a, b) => a + b, 0);

  if (classes === 0) return 0;
  return Math.round(password.length * Math.log2(classes));
}
