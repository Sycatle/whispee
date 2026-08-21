//! # ratchet-lab
//!
//! Teaching reimplementation of X3DH and the Double Ratchet.
//!
//! ## Why this crate exists
//!
//! Understanding why a protocol is built the way it is means writing it. Each module
//! documents not what the code does — that much is readable — but which attack each step
//! rules out, and which it does not.
//!
//! ## Why it must NEVER run in production
//!
//! This code is **not audited**. Do not ship it. Do not import it from anything a user
//! runs. Specifically:
//!
//! * no audit, by anyone, ever;
//! * no side-channel resistance (non constant-time comparisons outside the underlying
//!   primitives, secret-dependent allocations);
//! * no multi-device, no groups, no post-quantum resistance;
//! * session state persistence — where most exploitable bugs live — is not handled at all.
//!
//! The project's production path goes exclusively through OpenMLS, in `crypto-core`.
//! Nothing here may be imported by that crate — and the absence of a `ratchet-lab`
//! dependency in `crypto-core`'s manifest is an invariant to preserve.
//!
//! ## What the protocol does not protect
//!
//! Even implemented correctly, it does **not** hide who talks to whom, when, how often, nor
//! the size of the messages. Those metadata are often more revealing than the content.

pub mod error;
pub mod kdf;
pub mod keys;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use error::RatchetError;
pub use keys::{IdentityKeyPair, IdentityPublic, PreKeyBundle, PreKeyStore};
pub use ratchet::{Header, Message};
pub use session::{Session, safety_number};
pub use x3dh::InitialMessage;
