//! Pseudonymous account, and its single root secret.
//!
//! An account is an Ed25519 key — the *account identity key*, AIK — plus a handle. The AIK
//! signs device attestations (see the [`attest`] crate), so it decides which devices may read
//! the account's conversations.
//!
//! # What this module does not do
//!
//! It stores nothing. The secret lives in memory for the length of a session and it is up to
//! the caller to decide where it goes — system keychain, encrypted IndexedDB, or nowhere.
//!
//! It does not know the account's devices either: that list comes from the server and is
//! re-verified on every read. An account is not a directory, it is a signing key.

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

/// Number of words in the recovery phrase.
///
/// Twelve words are 128 bits of entropy. Twenty-four would be 256, which protects against
/// nothing more: 128 bits are already out of reach, and the only measurable difference would
/// be how many users copy the phrase down wrong.
pub const PHRASE_WORDS: usize = 12;

/// The matching entropy, in bytes.
const ENTROPY_BYTES: usize = 16;

/// Derivation labels.
///
/// Two keys from the same seed must be independent: knowing the vault key must teach nothing
/// about the identity key. HKDF guarantees that **provided** the `info` values differ — hence
/// these constants rather than literals scattered around.
const INFO_IDENTITY: &[u8] = b"wac-account-identity-v1";
const INFO_VAULT: &[u8] = b"wac-vault-v1";

/// An account's root key.
///
/// `Zeroize` is manual rather than derived: `SigningKey` does not implement it, and leaving it
/// lying on the stack after a `drop` would undo everything else.
pub struct Account {
    signing: SigningKey,
    seed: [u8; 64],
}

impl Drop for Account {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Deliberately redacted. Deriving `Debug` would copy the private key into the first debug
/// `println!` that comes along, and from there into the logs.
impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account").field("identity_key", &self.fingerprint()).finish_non_exhaustive()
    }
}

impl Account {
    /// Creates an account and returns the recovery phrase that rebuilds it.
    ///
    /// **This is the only moment the phrase exists.** It is not kept: asking for it again later
    /// is impossible by construction, which is the intended behaviour — a phrase that can be
    /// shown again is a phrase an attacker holding the unlocked device can show again too.
    pub fn generate() -> Result<(Self, String)> {
        let mut entropy = [0u8; ENTROPY_BYTES];
        rand_core::OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| CryptoError::Malformed(leak(e)))?;
        entropy.zeroize();

        let phrase = mnemonic.to_string();
        Ok((Self::from_mnemonic(&mnemonic), phrase))
    }

    /// Rebuilds an account from its recovery phrase.
    ///
    /// The phrase carries its own checksum: a mistyped word is rejected here rather than
    /// silently producing a different, empty account.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase.trim())
            .map_err(|_| CryptoError::Malformed("invalid recovery phrase"))?;

        if mnemonic.word_count() != PHRASE_WORDS {
            return Err(CryptoError::Malformed("recovery phrase of unexpected length"));
        }

        Ok(Self::from_mnemonic(&mnemonic))
    }

    fn from_mnemonic(mnemonic: &Mnemonic) -> Self {
        // `to_seed` applies PBKDF2-HMAC-SHA512, 2048 iterations. That is no useful hardening
        // here — the seed already has 128 bits, there is nothing to brute-force — but it is
        // the standard format, and departing from it would buy nothing but incompatibility.
        let seed = mnemonic.to_seed_normalized("");

        let mut identity = [0u8; 32];
        Hkdf::<Sha256>::new(None, &seed)
            .expand(INFO_IDENTITY, &mut identity)
            .expect("32 bytes is a valid length for HKDF-SHA256");

        let signing = SigningKey::from_bytes(&identity);
        identity.zeroize();

        Self { signing, seed }
    }

    /// The account's public key: what others verify, and what the server publishes.
    pub fn identity_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Fingerprint to compare out of band with your peer.
    pub fn fingerprint(&self) -> String {
        attest::fingerprint(&self.identity_key())
    }

    /// The account id: what names this account everywhere a handle used to.
    ///
    /// # Why this is the key derived from the seed and not the current one
    ///
    /// [`Account::rotate`] moves the identity key, and an id that moved with it would put this
    /// design back where it started — an identifier that changes under people, in a rarer and
    /// therefore more confusing form. The anchor is the key the recovery phrase produces, which
    /// is the one thing about an account that cannot change without the account becoming a
    /// different account.
    ///
    /// This type only ever holds that key: it is derived from the seed at construction and
    /// `rotate` signs a *successor* rather than replacing it. A rotated account is a second
    /// `Account` whose genesis is elsewhere, and the chain is what ties the two together — see
    /// `docs/specs/2026-08-21-account-identity.md`.
    pub fn id(&self) -> String {
        attest::account_id(&self.identity_key())
    }

    /// Signs a device's membership of this account.
    ///
    /// The result is what stops the server inventing a device: it does not hold the AIK and so
    /// cannot produce this signature.
    pub fn attest(
        &self,
        account: &str,
        device_id: &str,
        auth_key: &[u8],
        mls_key: &[u8],
    ) -> Result<[u8; 64]> {
        let claim = attest::DeviceClaim { account, device_id, auth_key, mls_key };
        let message = attest::message(&claim).map_err(|_| CryptoError::Malformed("field too long"))?;
        Ok(self.signing.sign(&message).to_bytes())
    }

    /// Signs the revocation of a device of this account.
    ///
    /// Twin of [`Account::attest`] and its exact opposite: the attestation lets a device in,
    /// the revocation certificate puts it out. Both are verifiable by anyone holding the
    /// account's public key, which is what lets **another** group member commit the removal
    /// without taking the server's word for it.
    ///
    /// `revoked_at` is in Unix seconds and enters the signed message. The caller must put the
    /// current time there: the server uses it to reject certificates forged ahead of time, and
    /// other clients use it to order successive revocations of the same device.
    pub fn revoke(&self, account: &str, device_id: &str, revoked_at: u64) -> Result<[u8; 64]> {
        let claim = attest::RevocationClaim { account, device_id, revoked_at };
        let message =
            attest::revocation_message(&claim).map_err(|_| CryptoError::Malformed("field too long"))?;
        Ok(self.signing.sign(&message).to_bytes())
    }

    /// Signs this account's move to a new identity key.
    ///
    /// Call it on the **old** account: it is the one that names its successor. See
    /// [`attest::RotationClaim`] for what this signature proves, and above all what it does
    /// not.
    pub fn rotate(
        &self,
        account: &str,
        new_identity_key: &[u8],
        rotated_at: u64,
    ) -> Result<[u8; 64]> {
        let claim = attest::RotationClaim { account, new_identity_key, rotated_at };
        let message =
            attest::rotation_message(&claim).map_err(|_| CryptoError::Malformed("field too long"))?;
        Ok(self.signing.sign(&message).to_bytes())
    }

    /// Symmetric key of the backup vault.
    ///
    /// Derived on demand and never persisted: as long as the user does not turn the vault on,
    /// this key exists nowhere. Its mere existence would change the threat model — a vault
    /// encrypted under a long-term key is no longer protected by forward secrecy, and a leaked
    /// phrase becomes retroactively total.
    pub fn vault_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, &self.seed)
            .expand(INFO_VAULT, &mut key)
            .expect("32 bytes is a valid length for HKDF-SHA256");
        key
    }

    /// Exports the seed, to hand it to a device being paired.
    ///
    /// **These bytes are worth the whole account.** They must only cross an already encrypted
    /// and authenticated channel — in practice the pairing blob sealed under the X25519 secret
    /// shared by the QR code, never the server in the clear, never a log.
    ///
    /// It is the seed and not the phrase that travels: the paired device gains exactly the same
    /// power, without a human-readable — hence photographable — secret being reconstituted a
    /// second time.
    pub fn export_seed(&self) -> [u8; 64] {
        self.seed
    }

    /// Rebuilds an account from a seed received during pairing.
    pub fn from_seed(seed: [u8; 64]) -> Self {
        let mut identity = [0u8; 32];
        Hkdf::<Sha256>::new(None, &seed)
            .expand(INFO_IDENTITY, &mut identity)
            .expect("32 bytes is a valid length for HKDF-SHA256");

        let signing = SigningKey::from_bytes(&identity);
        identity.zeroize();

        Self { signing, seed }
    }
}

/// `bip39::Error` is not `'static` as a `&str`; we keep the category only.
fn leak(_: bip39::Error) -> &'static str {
    "invalid entropy for a recovery phrase"
}
