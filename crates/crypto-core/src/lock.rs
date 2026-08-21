//! Local lock: deriving a key from a password.
//!
//! # What this lock protects, and what it does not
//!
//! It protects state at rest on **this device**: without the password, the MLS state and the
//! account seed stay unreadable bytes, including to whoever obtains the IndexedDB database or
//! the disk.
//!
//! It does **not** protect a device compromised while unlocked, and it is **not** a recovery
//! factor: forgetting it loses nothing, the twelve-word phrase remains the only restore path.
//! That is deliberate — making the password a second vault factor would double the surface for
//! loss with no gain against the server.
//!
//! # Why Argon2id rather than PBKDF2
//!
//! A human password rarely holds more than 40 bits of entropy. The only defence is to make
//! each attempt expensive — expensive **in memory**, or an attacker parallelises on GPUs for
//! pennies per billion attempts. PBKDF2, available in WebCrypto, costs only compute: exactly
//! what dedicated hardware does best.
//!
//! Argon2id forces 64 MiB per attempt, which brings a GPU back down to CPU level. It does not
//! exist in WebCrypto, hence this Rust-side derivation.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{CryptoError, Result};

/// Memory cost, in kibibytes. 64 MiB: the threshold beyond which a GPU attack loses its edge,
/// and still bearable on a low-end phone.
const MEMORY_KIB: u32 = 64 * 1024;

/// Number of passes. Three is RFC 9106's recommendation at this memory cost.
const ITERATIONS: u32 = 3;

/// Parallelism. A single lane: WebAssembly has no threads by default, and announcing several
/// would produce a derivation different from the one actually computed.
const LANES: u32 = 1;

/// Salt length. Random per device, stored in the clear next to the state: its job is to rule
/// out precomputed tables, not to stay secret.
pub const SALT_LEN: usize = 16;

/// Derives the unlock key from a password.
///
/// Costs roughly one second and 64 MiB. That is the point: the user pays it once per unlock,
/// an attacker pays it on every attempt.
pub fn derive_unlock_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::Malformed("unexpected salt length"));
    }

    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32))
        .map_err(|_| CryptoError::Malformed("invalid Argon2 parameters"))?;

    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::Malformed("lock derivation failed"))?;

    Ok(key)
}
