//! The one shape a handle may take.
//!
//! # Why a handle needs a shape at all
//!
//! Two concrete defects, not a tidiness preference.
//!
//! **The roster compares handles to decide who administers a group.** `crypto_core::roles`
//! matches the string it finds in the roster against the string a member presents; nothing
//! normalises either side. So `Alice` and `alice` are two accounts, they look the same in every
//! list on every screen, and one of them can be created *after* the other precisely because it
//! is a distinct row. That is not a display nuisance, it is an impersonation primitive aimed at
//! an authorisation check.
//!
//! **A `:` in a handle makes a device id ambiguous.** Device ids are `handle:name`, and
//! `routes::register_device` used to check the prefix with `starts_with`. With `:` allowed in a
//! handle, `alice:phone` is a legal prefix of the device id `alice:phone:laptop`, which belongs
//! to whichever of the two accounts claims it first. Forbidding `:` is what turns the prefix
//! check into a parse.
//!
//! # The shape, and what it deliberately gives up
//!
//! `^[a-z0-9_]{3,32}$`. Lowercase because case-folding after the fact is a losing game across
//! scripts; ASCII because a handle that can carry bidi overrides or invisible joiners is a
//! handle that can be drawn as someone else's; a floor of three because two-character handles
//! are a land grab, and a ceiling of thirty-two because the handle is shown in full everywhere
//! it appears and a 64-character one would be truncated, which is its own confusion.
//!
//! What this does **not** solve, and nobody should read it as solving: `_` is a quiet separator
//! and `rn` still reads as `m` at small sizes. The rule kills the wide classes — case, bidi,
//! whitespace, the whole of non-ASCII Unicode — and leaves residual typographic confusion
//! exactly where it was. The answers to that remain the permanently displayed `@handle` and the
//! fingerprint, not this function.
//!
//! # Why no `regex`
//!
//! `crates/server/Cargo.toml` does not depend on `regex`, and this predicate does not justify
//! adding one to a server that handles other people's ciphertext. A `chars().all(…)` loop is
//! shorter than the pattern it would replace, and it needs no compilation step to memoise.
//!
//! This module is the **authority** on the format. `migrations/0013_handle_format.sql` carries
//! the same rule as a CHECK constraint, and that copy is a belt: if the two ever disagree, this
//! one is right and the migration is the bug.

/// Shortest accepted handle. See the module header for why two is not enough.
const MIN_CHARS: usize = 3;

/// Longest accepted handle.
const MAX_CHARS: usize = 32;

/// Accepts a handle, or says in one word what is wrong with it.
///
/// The error is a fixed string rather than a formatted one on purpose: it goes out over the wire
/// in a 400, and interpolating the offending handle into it would echo attacker-chosen bytes
/// back through the server's error path for no diagnostic gain — the caller already has the
/// value it sent.
///
/// # Characters, not bytes
///
/// The length is counted in `chars()`. Since the accepted alphabet is pure ASCII, every accepted
/// handle has as many bytes as characters, and the two counts can never disagree *on a value
/// this function accepts*. Counting characters is still the right thing to write: it is the
/// property being asserted, and it keeps the bound honest for the rejected values too — a
/// thirty-character string of four-byte emoji is refused for its alphabet, and is never
/// misreported as being too long.
pub fn validate(handle: &str) -> Result<(), &'static str> {
    let length = handle.chars().count();

    if length < MIN_CHARS {
        return Err("handle too short");
    }
    if length > MAX_CHARS {
        return Err("handle too long");
    }

    // Deliberately not `is_ascii_lowercase() || is_ascii_digit()` alone: `_` is the only
    // punctuation admitted, and listing it here rather than in a second condition keeps the whole
    // alphabet visible in one expression.
    if !handle.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return Err("handle must be lowercase letters, digits or underscores");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_lowercase_handle_is_accepted() {
        assert!(validate("alice").is_ok());
    }

    #[test]
    fn a_handle_with_a_capital_letter_is_refused_because_case_would_fork_an_identity() {
        assert!(validate("Alice").is_err());
    }

    #[test]
    fn a_handle_containing_a_colon_is_refused_because_it_would_split_a_device_id() {
        assert!(validate("alice:phone").is_err());
    }

    #[test]
    fn a_handle_containing_a_space_is_refused() {
        assert!(validate("alice smith").is_err());
        assert!(validate(" alice").is_err());
        assert!(validate("alice ").is_err());
    }

    #[test]
    fn a_handle_shorter_than_three_characters_is_refused() {
        assert!(validate("").is_err());
        assert!(validate("a").is_err());
        assert!(validate("ab").is_err());
        assert!(validate("abc").is_ok());
    }

    #[test]
    fn a_handle_longer_than_thirty_two_characters_is_refused() {
        assert!(validate(&"a".repeat(32)).is_ok());
        assert!(validate(&"a".repeat(33)).is_err());
    }

    #[test]
    fn a_handle_outside_ascii_is_refused_whatever_it_looks_like() {
        // A Cyrillic `а` renders identically to the Latin one in most faces.
        assert!(validate("аlice").is_err());
        assert!(validate("alicé").is_err());
        // A right-to-left override reverses everything drawn after it.
        assert!(validate("alice\u{202e}bob").is_err());
        assert!(validate("🙂🙂🙂").is_err());
    }

    #[test]
    fn an_underscore_is_the_one_admitted_separator() {
        assert!(validate("alice_smith").is_ok());
        assert!(validate("___").is_ok());
        assert!(validate("alice-smith").is_err());
        assert!(validate("alice.smith").is_err());
    }

    #[test]
    fn digits_are_accepted_anywhere_in_a_handle() {
        assert!(validate("alice2").is_ok());
        assert!(validate("2alice").is_ok());
        assert!(validate("123").is_ok());
    }

    #[test]
    fn a_long_non_ascii_string_is_refused_for_its_alphabet_and_not_for_its_length() {
        // Thirty characters, a hundred and twenty bytes. Counting bytes would report the wrong
        // reason; the test exists to keep that distinction from quietly regressing.
        assert_eq!(
            validate(&"é".repeat(30)),
            Err("handle must be lowercase letters, digits or underscores")
        );
    }
}
