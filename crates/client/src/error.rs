//! What can go wrong between a client and a delivery server.

/// A failure on the way to, or back from, the server.
///
/// The variants separate what a caller can act on. A [`ClientError::Gap`] is the one that is not
/// a bug and not transient: the server has purged envelopes this device never read, its MLS
/// state can no longer be advanced, and the only way back into the conversation is to be added
/// to it again. A client that treats it as a retryable error will retry forever.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The request never completed.
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// The server answered, and said no.
    #[error("{method} {path}: {status}")]
    Status {
        /// HTTP method used.
        method: &'static str,
        /// Path requested.
        path: String,
        /// What came back.
        status: u16,
    },

    /// The server's answer did not have the shape this version expects.
    #[error("unexpected response to {path}: {reason}")]
    Malformed {
        /// Path requested.
        path: String,
        /// What was wrong with it.
        reason: String,
    },

    /// The gateway session could not be opened or was closed under us.
    #[error("gateway: {0}")]
    Gateway(String),

    /// Envelopes this device needed are gone.
    ///
    /// Not retryable, and not recoverable on its own: losing one envelope breaks the MLS
    /// application ratchet for everything that follows. The conversation must be rejoined.
    #[error("group {group}: envelopes below {oldest} have been purged; the group must be rejoined")]
    Gap {
        /// Which group, hex-encoded.
        group: String,
        /// The oldest sequence number the server still holds.
        oldest: i64,
    },

    /// A wire format could not be read.
    #[error("wire: {0}")]
    Wire(#[from] wire::WireError),

    /// The MLS layer refused something.
    #[error("crypto: {0}")]
    Crypto(#[from] crypto_core::CryptoError),

    /// State could not be read from, or written to, where the host keeps it.
    #[error("state store: {0}")]
    Storage(String),

    /// A canonical message could not be built.
    #[error("attest: a field was too long to encode")]
    Attest,
}

/// What every fallible call in this crate returns.
pub type Result<T> = std::result::Result<T, ClientError>;
