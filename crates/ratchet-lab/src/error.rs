use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RatchetError {
    #[error("invalid signed prekey signature")]
    BadPreKeySignature,

    #[error("decryption failed (wrong key, nonce or associated data)")]
    DecryptionFailed,

    #[error("message too old: the key has already been consumed and erased")]
    MessageKeyGone,

    #[error("skip of {0} messages refused (limit: {1})")]
    TooManySkipped(u32, u32),

    #[error("message received before the session was established")]
    NoSession,

    #[error("invalid encoding: {0}")]
    Malformed(&'static str),
}
