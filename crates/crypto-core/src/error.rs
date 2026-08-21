use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    /// Error surfaced by OpenMLS. Flattened to a string: OpenMLS has many error variants and
    /// they are unstable across minor versions, and telling them apart would gain the caller
    /// nothing — it can only reject the message either way.
    #[error("MLS operation refused: {0}")]
    Mls(String),

    #[error("malformed message: {0}")]
    Malformed(&'static str),

    /// Got one kind of MLS message where another was expected. May be benign (a late message)
    /// or hostile (a type-confusion attempt).
    #[error("unexpected message type")]
    UnexpectedMessage,

    #[error("unreadable session state: {0}")]
    Storage(String),

    /// The target member is not in the group tree.
    ///
    /// Common and benign: two members remove the same device at once, and the second commit
    /// arrives after the first has been applied. The caller must treat this as a success —
    /// the intended state holds — not as an error to retry.
    #[error("member not in group")]
    UnknownMember,

    /// The received commit is cryptographically valid but violates group policy.
    ///
    /// Distinct from [`CryptoError::Mls`] because it says something else: MLS accepted the
    /// message, it is **we** who refuse to apply it. The group is intact, and the sender is
    /// left alone on its own epoch. See `roles.rs`.
    #[error("commit refused by group policy: {0}")]
    PolicyViolation(&'static str),
}

pub(crate) fn mls<E: std::fmt::Display>(err: E) -> CryptoError {
    CryptoError::Mls(err.to_string())
}

pub type Result<T> = std::result::Result<T, CryptoError>;
