//! The wire formats a Whispee client speaks.
//!
//! Three layers sit between an application message and the opaque blob the server routes, and
//! a client that gets any of them wrong is not a client at all:
//!
//! ```text
//! content::encode  ->  padding::pad  ->  MLS encrypt  ->  envelope::encode_mls  ->  POST
//! ```
//!
//! and, coming back, the exact reverse. The order matters: padding wraps the encoded content,
//! not the ciphertext, because it is the *plaintext* length the server must not learn.
//!
//! # Why this is a crate and not a corner of the client
//!
//! These formats had one definition, in TypeScript, inside `apps/web`. That made them a private
//! detail of one client, which is a poor place for something every client must agree on byte for
//! byte — a second implementation would have had nothing to conform to but a reading of the
//! first. The formats are described here, tested against shared vectors, and documented for
//! anyone writing a third.

pub mod content;
pub mod envelope;
pub mod error;
pub mod expiry;
pub mod padding;

pub use error::WireError;

/// What every fallible decode in this crate returns.
pub type Result<T> = std::result::Result<T, WireError>;
