//! A Whispee client, without a browser.
//!
//! Everything needed to be a member of a conversation from a native binary: signed HTTP, the
//! gateway, the account and device lifecycle, and the wire formats from [`wire`]. The MLS work
//! itself stays in `crypto-core`, which this crate does not wrap — a caller holds its own
//! `Conversation` values and decides when to persist them.
//!
//! # The shape of a client's loop
//!
//! ```text
//! connect gateway with persisted cursors
//!   -> Event::Envelope { group, seq }      (no content — this is only a wake-up)
//!   -> api.envelopes_after(group, cursor)  (signed HTTP, this is where the bytes are)
//!   -> envelope::decode                    (mls, or a welcome to join from)
//!   -> conversation.process                (MLS)
//!   -> padding::unpad -> content::decode   (the message)
//!   -> persist the cursor                  (or be woken by your own welcome next time)
//! ```
//!
//! # What this crate deliberately does not do
//!
//! No vault, no recovery, no pairing, no presence, no calls. A headless client has no user to
//! recover an account for and no screen to show presence on. It also does not choose where MLS
//! state is stored: `crypto-core` exports and imports it, and the host decides what that lands
//! in — a file, a column, an encrypted blob.
//!
//! # Build in release
//!
//! OpenMLS 0.8.1 runs a `debug_assert!(false)` before returning its decryption error. In a debug
//! build a message altered in transit therefore panics the process instead of being rejected,
//! which for a long-running service is a denial of service any group member can trigger by
//! flipping one byte. In release the assertion disappears and the error propagates. See
//! `CONTRIBUTING.md`.

pub mod api;
pub mod enrolment;
pub mod error;
pub mod gateway;
pub mod store;
pub mod transport;

pub use api::{Api, ClaimedKeyPackage, Envelope, EnvelopePage};
pub use enrolment::Enrolled;
pub use error::{ClientError, Result};
pub use gateway::{Cursor, Event, Gateway, Poll};
pub use store::StateStore;
pub use transport::{Transport, unix_millis};
