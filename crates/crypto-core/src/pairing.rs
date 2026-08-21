//! Pairing a new device, over a visual channel.
//!
//! # The problem
//!
//! A brand-new device needs the account root key to attest itself, and later to attest other
//! devices. That secret can neither travel in the clear through the server nor be shown on
//! screen a second time — a phrase read again is a phrase that can be photographed.
//!
//! # What the QR code means, and why it is not arbitrary
//!
//! The **new** device displays, the **old** one scans. So the QR holds no secret: only an
//! ephemeral public key and enough to identify the device. A QR is photographable by
//! construction; putting a secret in it would amount to publishing it.
//!
//! The old device then seals the packet under the shared X25519 secret and drops it on the
//! server, which sees only an opaque blob: it holds neither private half.
//!
//! # What this does not protect
//!
//! The channel's security is **physical**: it rests on the user scanning only the screen they
//! are holding. An attacker who shows them their own QR is paired, and no cryptography can
//! prevent it. This is the same model as WhatsApp and Signal.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

/// Length of the pairing identifier. Random, it serves as the drop address on the server.
pub const PAIRING_ID_LEN: usize = 16;

const NONCE_LEN: usize = 12;
const INFO_SEAL: &[u8] = b"wac-pairing-seal-v1";
const INFO_CONFIRM: &[u8] = b"wac-pairing-confirm-v1";

/// What the new device publishes in its QR code.
///
/// Nothing secret: the ephemeral key is public, and the pairing identifier is only a drop
/// address. A third party photographing this QR gains nothing — they cannot open the packet,
/// lacking the private half.
pub struct PairingOffer {
    secret: EphemeralSecret,
    public: PublicKey,
    id: [u8; PAIRING_ID_LEN],
}

impl PairingOffer {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);

        let mut id = [0u8; PAIRING_ID_LEN];
        rand_core::OsRng.fill_bytes(&mut id);

        Self { secret, public, id }
    }

    pub fn id(&self) -> [u8; PAIRING_ID_LEN] {
        self.id
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Opens the packet dropped by the originating device.
    ///
    /// Consumes the offer: the ephemeral secret is destroyed after a single use, which rules
    /// out replaying an old packet against the same key.
    pub fn open(self, sealed: &[u8]) -> Result<Opened> {
        if sealed.len() < 32 + NONCE_LEN {
            return Err(CryptoError::Malformed("truncated pairing packet"));
        }

        let mut peer = [0u8; 32];
        peer.copy_from_slice(&sealed[..32]);
        let peer = PublicKey::from(peer);

        let shared = self.secret.diffie_hellman(&peer);
        let (key, confirmation) = derive(shared.as_bytes(), &peer, &self.public, &self.id);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| CryptoError::Malformed("invalid pairing key"))?;
        let nonce = Nonce::from_slice(&sealed[32..32 + NONCE_LEN]);

        let plaintext = cipher
            .decrypt(nonce, Payload { msg: &sealed[32 + NONCE_LEN..], aad: &self.id })
            .map_err(|_| CryptoError::Malformed("unreadable or tampered pairing packet"))?;

        Ok(Opened { plaintext, confirmation })
    }
}

pub struct Opened {
    pub plaintext: Vec<u8>,
    /// Short code to compare by eye on both screens.
    pub confirmation: String,
}

/// Seals a packet for the new device.
///
/// `offer_public` and `offer_id` come from the QR code, hence from an out-of-band channel the
/// server does not see. That is what makes the drop safe despite a hostile server.
pub fn seal(
    offer_public: &[u8],
    offer_id: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, String)> {
    let offer_public: [u8; 32] = offer_public
        .try_into()
        .map_err(|_| CryptoError::Malformed("pairing key of invalid size"))?;
    let offer_public = PublicKey::from(offer_public);

    // `StaticSecret` rather than `EphemeralSecret`: we need the matching public key in the
    // message, and to derive twice from the same secret. It is wiped right after.
    let mut ours = StaticSecret::random_from_rng(rand_core::OsRng);
    let ours_public = PublicKey::from(&ours);
    let shared = ours.diffie_hellman(&offer_public);
    ours.zeroize();

    let (key, confirmation) = derive(shared.as_bytes(), &ours_public, &offer_public, offer_id);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| CryptoError::Malformed("invalid pairing key"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: offer_id })
        .map_err(|_| CryptoError::Malformed("pairing encryption failed"))?;

    let mut out = Vec::with_capacity(32 + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(ours_public.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok((out, confirmation))
}

/// Derives the sealing key and the confirmation code.
///
/// Both public keys enter the derivation **in a fixed order** — the originating device's, then
/// the new device's. Without that order the two sides would compute different values; without
/// including them at all, an attacker could replay a shared secret obtained in another
/// exchange.
fn derive(
    shared: &[u8],
    sender: &PublicKey,
    receiver: &PublicKey,
    pairing_id: &[u8],
) -> ([u8; 32], String) {
    let mut transcript = Vec::with_capacity(80);
    transcript.extend_from_slice(sender.as_bytes());
    transcript.extend_from_slice(receiver.as_bytes());
    transcript.extend_from_slice(pairing_id);

    let hkdf = Hkdf::<Sha256>::new(Some(&transcript), shared);

    let mut key = [0u8; 32];
    hkdf.expand(INFO_SEAL, &mut key).expect("32 bytes valid for HKDF-SHA256");

    let mut digest = [0u8; 4];
    hkdf.expand(INFO_CONFIRM, &mut digest).expect("4 bytes valid for HKDF-SHA256");

    // Six digits: long enough that an accidental collision is unlikely, short enough that a
    // human actually compares it instead of clicking "yes" without looking.
    let code = u32::from_be_bytes(digest) % 1_000_000;
    (key, format!("{code:06}"))
}
