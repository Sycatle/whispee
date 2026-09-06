//! One error type for every format in this crate.

/// Why a byte string could not be read.
///
/// Decoding failures are ordinary here, not exceptional: these bytes come off the network, and
/// even after MLS authenticates them they were written by a group member who may have sent
/// anything at all, by mistake or on purpose. Every variant names what was expected, because an
/// error that only says "malformed" sends the reader back to a hex dump.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// A length prefix promised more bytes than the buffer holds.
    #[error("{format}: {claimed} bytes claimed, {available} available")]
    Truncated {
        /// Which format was being read.
        format: &'static str,
        /// What the prefix said.
        claimed: usize,
        /// What was actually there.
        available: usize,
    },

    /// A buffer that must not be empty was.
    #[error("{0}: empty")]
    Empty(&'static str),

    /// A type byte this version does not know.
    ///
    /// Not always fatal: an envelope with an unknown type is refused, but unknown *content*
    /// is surfaced so a client can skip one message and carry on with the conversation.
    #[error("{format}: unknown type byte {byte}")]
    UnknownType {
        /// Which format was being read.
        format: &'static str,
        /// The byte that was not recognised.
        byte: u8,
    },

    /// A fixed-size layout was the wrong size.
    #[error("{format}: expected {expected} bytes, got {actual}")]
    BadLength {
        /// Which format was being read.
        format: &'static str,
        /// The size the layout requires.
        expected: usize,
        /// The size that arrived.
        actual: usize,
    },

    /// Padding that no correct sender produces.
    #[error("malformed padding")]
    MalformedPadding,

    /// A body that should have been UTF-8 was not.
    #[error("{0}: not valid UTF-8")]
    NotUtf8(&'static str),

    /// A caller asked to pad more bytes than its own ceiling allows.
    #[error("body of {length} bytes does not fit under a ceiling of {ceiling}")]
    AboveCeiling {
        /// What the caller handed over.
        length: usize,
        /// The ceiling it declared.
        ceiling: usize,
    },
}
