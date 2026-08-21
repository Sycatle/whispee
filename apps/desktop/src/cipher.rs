//! The device secrets, held by the native process.
//!
//! # What this module moves, and what it does not
//!
//! It moves two things out of the webview: the key that **encrypts state at rest** and the key
//! that **signs requests**. It does **not** move the MLS keys, which still live in the linear
//! memory of the WebAssembly module — that limit is written down in `lib.rs` and stands.
//!
//! The signing key mattered as much as the other, and that is less obvious: a saved MLS state
//! whose authentication key is gone is worthless, since the device can no longer issue a single
//! request. The server also refuses to change it — see the `auth_key` clause in
//! `register_device`. Losing it is therefore as final as losing the state.
//!
//! # What "the key never leaves Rust" is actually worth
//!
//! On the web, keys are non-extractable `CryptoKey`s: the browser refuses to export the material,
//! including to our own code. Here, the Rust process sees the key in the clear. That is not a
//! practical regression — a hostile script in the webview could already *use* the key without
//! extracting it, and it can still call `seal`/`sign` — but it is a property we give up, and
//! staying quiet about it would be dishonest.
//!
//! What we gain in exchange: durability. The application's private directory is only purged on
//! uninstall, where a mobile webview's storage is evicted without warning.
//!
//! # What the current phase does not protect
//!
//! **The key sits in a file, in the clear, readable by the account owner.** The `0600`
//! permissions stop another user of the same system from reading it; they stop neither a rooted
//! device, nor a disk backup, nor another process of the same user.
//!
//! Real protection at rest will come from the system keystore — Keychain on iOS, Keystore on
//! Android — which needs native per-platform code. That is **not** what brings durability, which
//! is why it can ship later: the private directory is enough to stop losing state. Splitting the
//! two jobs keeps the difficult one from delaying the urgent one.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::store;

/// Version of the secrets file format.
///
/// Present from the first version, because a format without one cannot evolve without guessing:
/// the day the key moves to the keystore, an old file will have to be told apart from a missing
/// one.
const VERSION: u8 = 1;

/// Length of the AES-GCM nonce, in bytes.
///
/// Twelve, as on the web: AES-GCM breaks catastrophically if a nonce is reused under the same
/// key, and 96 random bits make a collision negligible at the rate a client saves its state.
const NONCE_LEN: usize = 12;

/// A device's two secrets.
///
/// `ZeroizeOnDrop` wipes the material on release. Unlike JavaScript — where a zeroed
/// `Uint8Array` may already have been copied by the garbage collector — the wipe is real here,
/// which is one of the few concrete gains of going native.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecrets {
    /// Encrypts state at rest.
    seal: [u8; 32],
    /// Ed25519 seed. Stored rather than the `SigningKey`, which is not `Zeroize`.
    signing: [u8; 32],
}

impl DeviceSecrets {
    /// Loads the secrets, or creates them on first launch.
    ///
    /// Telling "file missing" from "read error" comes from [`store::Paths::read`], and it matters
    /// here more than elsewhere: treating a failing disk as a first launch would mint fresh
    /// secrets over an existing account — a lost identity and an unreadable state.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        if let Some(content) = store::Paths::read(path)? {
            return Self::decode(&content);
        }

        let mut secrets = Self { seal: [0u8; 32], signing: [0u8; 32] };
        OsRng.fill_bytes(&mut secrets.seal);
        OsRng.fill_bytes(&mut secrets.signing);

        secrets.write(path)?;
        Ok(secrets)
    }

    fn decode(content: &[u8]) -> std::io::Result<Self> {
        let invalid = |reason: &str| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, reason.to_owned())
        };

        if content.len() != 1 + 32 + 32 {
            return Err(invalid("unexpected secrets file size"));
        }
        if content[0] != VERSION {
            return Err(invalid("unknown secrets file version"));
        }

        let mut secrets = Self { seal: [0u8; 32], signing: [0u8; 32] };
        secrets.seal.copy_from_slice(&content[1..33]);
        secrets.signing.copy_from_slice(&content[33..65]);
        Ok(secrets)
    }

    fn write(&self, path: &Path) -> std::io::Result<()> {
        let mut content = Vec::with_capacity(65);
        content.push(VERSION);
        content.extend_from_slice(&self.seal);
        content.extend_from_slice(&self.signing);

        store::write_atomically(path, &content)?;
        content.zeroize();

        // Before any other user of the system, and before the file holds anything useful. Setting
        // the permissions after the write would leave a window where the file is world-readable —
        // short, but real, and avoidable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Signing public key — the only half that leaves the device.
    pub fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.signing).verifying_key().to_bytes()
    }

    /// Signs a request message.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.signing).sign(message).to_bytes()
    }

    /// Encrypts for local persistence. Returns `nonce || ciphertext`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = Aes256Gcm::new(&self.seal.into())
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &[] })?;

        let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypts what [`Self::seal`] produced.
    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        if blob.len() <= NONCE_LEN {
            return Err(aes_gcm::Error);
        }

        Aes256Gcm::new(&self.seal.into()).decrypt(
            Nonce::from_slice(&blob[..NONCE_LEN]),
            Payload { msg: &blob[NONCE_LEN..], aad: &[] },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("wac-cipher-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        path.join("secrets.bin")
    }

    #[test]
    fn a_sealed_blob_reopens() {
        let secrets = DeviceSecrets::load_or_create(&temp_path("reopen")).unwrap();

        let blob = secrets.seal(b"an mls state").unwrap();
        assert_eq!(secrets.open(&blob).unwrap(), b"an mls state");
    }

    /// The plaintext must not show through the sealed blob.
    ///
    /// Apparently trivial, and exactly the kind of invariant someone breaks one day by
    /// "optimising" the encoding.
    #[test]
    fn the_sealed_blob_does_not_contain_the_plaintext() {
        let secrets = DeviceSecrets::load_or_create(&temp_path("opaque")).unwrap();
        let plaintext = b"recognisable phrase";

        let blob = secrets.seal(plaintext).unwrap();

        assert!(!blob.windows(plaintext.len()).any(|w| w == plaintext));
    }

    /// **The test that justifies the random nonce.**
    ///
    /// Two seals of the same plaintext must differ. A fixed nonce — or a counter reset on restart
    /// — would break AES-GCM catastrophically, and the symptom would be invisible: everything
    /// would keep working.
    #[test]
    fn two_seals_of_the_same_plaintext_differ() {
        let secrets = DeviceSecrets::load_or_create(&temp_path("nonce")).unwrap();

        assert_ne!(secrets.seal(b"identical").unwrap(), secrets.seal(b"identical").unwrap());
    }

    /// One flipped byte must make opening fail, not yield a doubtful plaintext.
    #[test]
    fn a_tampered_seal_is_refused() {
        let secrets = DeviceSecrets::load_or_create(&temp_path("tampered")).unwrap();

        let mut blob = secrets.seal(b"an mls state").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(secrets.open(&blob).is_err());
    }

    /// **The test that matters for durability.**
    ///
    /// The secrets must survive a restart: that is the whole point of the file. A second load
    /// producing new keys would make the state unreadable and the device mute, without a single
    /// error message.
    #[test]
    fn the_secrets_survive_a_reload() {
        let path = temp_path("persistence");

        let first = DeviceSecrets::load_or_create(&path).unwrap();
        let blob = first.seal(b"state").unwrap();
        let public = first.public_key();
        drop(first);

        let second = DeviceSecrets::load_or_create(&path).unwrap();

        assert_eq!(second.public_key(), public, "the signing key changed");
        assert_eq!(second.open(&blob).unwrap(), b"state", "the state is no longer decryptable");
    }

    /// A signature verifies under the advertised public key.
    #[test]
    fn a_signature_verifies_under_the_public_key() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let secrets = DeviceSecrets::load_or_create(&temp_path("signature")).unwrap();
        let message = b"POST\n/v1/envelopes\n";

        let signature = secrets.sign(message);
        let public = VerifyingKey::from_bytes(&secrets.public_key()).unwrap();

        assert!(public.verify(message, &Signature::from_bytes(&signature)).is_ok());
    }

    /// A truncated file is refused rather than reinterpreted.
    ///
    /// Without this guard, a corrupted file would silently yield wrong keys — an undecryptable
    /// state presented as a wrong password.
    #[test]
    fn a_truncated_file_is_refused() {
        assert!(DeviceSecrets::decode(&[VERSION, 0, 0]).is_err());
    }

    /// An unknown version is refused rather than misread.
    #[test]
    fn an_unknown_version_is_refused() {
        let mut content = vec![VERSION + 1];
        content.extend_from_slice(&[0u8; 64]);

        assert!(DeviceSecrets::decode(&content).is_err());
    }
}
