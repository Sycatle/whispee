//! Whispee's production MLS core, built on OpenMLS 0.8.1.
//!
//! Everything a user's messages actually depend on lives here: device identities, account
//! root secrets, group state, the admin-role policy, and device pairing.
//!
//! INVARIANT — this crate must NEVER depend on `ratchet-lab`. That crate reimplements X3DH
//! and the Double Ratchet by hand as a learning exercise: unaudited, not side-channel
//! resistant, and never to be run by a user. Any PR adding the dependency must be rejected.

pub mod account;
pub mod conversation;
pub mod error;
pub mod escrow;
pub mod identity;
pub mod lifetime;
pub mod lock;
pub mod pairing;
pub mod provider;
pub mod roles;

pub use account::Account;
pub use conversation::{Conversation, Incoming, Invitation};
pub use error::CryptoError;
pub use pairing::{PairingOffer, seal};
pub use identity::{CIPHERSUITE, Identity, fingerprint};
pub use provider::Provider;
