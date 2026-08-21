//! Double Ratchet.
//!
//! Two ratchets are nested:
//!
//! * the **symmetric ratchet** advances one step per message and yields a unique key per
//!   message, destroyed after use → forward secrecy;
//! * the **DH ratchet** regenerates an ephemeral pair every time the conversation changes
//!   direction and reseeds the root key → post-compromise security.
//!
//! The second is what really sets the Double Ratchet apart: an attacker who stole the whole
//! state loses access as soon as one round trip escapes them.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use crate::error::RatchetError;
use crate::kdf::{ChainKey, MessageKey, RootKey, derive_message_keys, kdf_ck, kdf_rk};
use crate::keys::EphemeralKeyPair;

/// Cap on how many skipped messages are kept. Without a cap, a malicious peer announces
/// `n = u32::MAX` and forces the allocation of billions of keys: trivial denial of service.
const MAX_SKIP: u32 = 1_000;

/// In the clear inside the message: the recipient needs it before they can decrypt. The
/// header is authenticated by the AEAD, so it cannot be modified, but it is readable by the
/// server — it is part of the metadata E2EE does not protect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub dh: PublicKey,
    /// Length of the previous sending chain: tells the recipient how many keys to skip
    /// before turning the ratchet.
    pub pn: u32,
    /// Position in the current chain.
    pub n: u32,
}

impl Header {
    pub const LEN: usize = 40;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..32].copy_from_slice(self.dh.as_bytes());
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetError> {
        if bytes.len() != Self::LEN {
            return Err(RatchetError::Malformed("invalid header size"));
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[..32]);
        Ok(Self {
            dh: PublicKey::from(dh),
            pn: u32::from_be_bytes(bytes[32..36].try_into().unwrap()),
            n: u32::from_be_bytes(bytes[36..].try_into().unwrap()),
        })
    }
}

#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

pub struct DoubleRatchet {
    /// Our current ratchet pair.
    dhs: EphemeralKeyPair,
    /// The peer's. `None` until something has been received.
    dhr: Option<PublicKey>,
    rk: RootKey,
    cks: Option<ChainKey>,
    ckr: Option<ChainKey>,
    ns: u32,
    nr: u32,
    pn: u32,
    /// Keys for messages that arrived out of order or have not arrived yet. Indexed by
    /// (sender's ratchet key, index). Every entry is a live key: sensitive material whose
    /// lifetime must stay bounded.
    skipped: HashMap<([u8; 32], u32), MessageKey>,
    ad: Vec<u8>,
}

impl DoubleRatchet {
    /// Initiator side. Alice already knows Bob's ratchet public key — it is his signed
    /// prekey — so she can turn the DH ratchet immediately and write first.
    pub fn init_initiator<R: RngCore + CryptoRng>(
        rng: &mut R,
        shared_secret: RootKey,
        associated_data: Vec<u8>,
        responder_ratchet_key: PublicKey,
    ) -> Self {
        let dhs = EphemeralKeyPair::generate(rng);
        let dh_out = dhs.secret.diffie_hellman(&responder_ratchet_key).to_bytes();
        let (rk, cks) = kdf_rk(&shared_secret, &dh_out);

        Self {
            dhs,
            dhr: Some(responder_ratchet_key),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            ad: associated_data,
        }
    }

    /// Responder side. Bob has not seen a ratchet key from Alice yet: he has no sending
    /// chain and therefore cannot write before receiving. The first reception triggers the
    /// first DH ratchet.
    pub fn init_responder(
        shared_secret: RootKey,
        associated_data: Vec<u8>,
        signed_prekey: EphemeralKeyPair,
    ) -> Self {
        Self {
            dhs: signed_prekey,
            dhr: None,
            rk: shared_secret,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            ad: associated_data,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Message, RatchetError> {
        let cks = self.cks.as_ref().ok_or(RatchetError::NoSession)?;
        let (next_cks, mut mk) = kdf_ck(cks);
        self.cks = Some(next_cks);

        let header = Header {
            dh: self.dhs.public(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let ciphertext = aead_seal(&mk, plaintext, &self.aad_for(&header))?;
        mk.zeroize();

        Ok(Message { header, ciphertext })
    }

    pub fn decrypt<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<u8>, RatchetError> {
        // Case 1: the message had been skipped. Its key is waiting for us.
        if let Some(mut mk) = self.skipped.remove(&(*message.header.dh.as_bytes(), message.header.n))
        {
            let plaintext = aead_open(&mk, &message.ciphertext, &self.aad_for(&message.header))?;
            mk.zeroize();
            return Ok(plaintext);
        }

        // Case 2: the peer turned their ratchet. Settle the old chain before following.
        if self.dhr.as_ref().map(|k| k.as_bytes()) != Some(message.header.dh.as_bytes()) {
            self.skip_message_keys(message.header.pn)?;
            self.dh_ratchet(rng, &message.header);
        }

        // Case 3: current chain, possibly ahead of us.
        self.skip_message_keys(message.header.n)?;

        let ckr = self.ckr.as_ref().ok_or(RatchetError::NoSession)?;
        let (next_ckr, mut mk) = kdf_ck(ckr);
        self.ckr = Some(next_ckr);
        self.nr += 1;

        let plaintext = aead_open(&mk, &message.ciphertext, &self.aad_for(&message.header))?;
        mk.zeroize();
        Ok(plaintext)
    }

    /// Number of pending keys. Exposed so tests can check that skipped keys really are
    /// consumed and not accumulated indefinitely.
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Fingerprint of the current ratchet key. For debugging only: the fingerprint shown to
    /// the user must cover the long-term identity, not this one.
    pub fn ratchet_public(&self) -> PublicKey {
        self.dhs.public()
    }

    fn aad_for(&self, header: &Header) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.ad.len() + Header::LEN);
        aad.extend_from_slice(&self.ad);
        aad.extend_from_slice(&header.encode());
        aad
    }

    /// Advances the receiving chain up to `until`, setting the keys aside so late messages
    /// stay decryptable when they arrive.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        let Some(ckr) = self.ckr.as_ref() else {
            // No receiving chain yet: nothing to skip. This is only an error if the peer
            // claims we have already received messages.
            return if until == 0 {
                Ok(())
            } else {
                Err(RatchetError::NoSession)
            };
        };

        if until < self.nr {
            // The message predates the current position and was not pending: its key has
            // already been consumed and destroyed. Replay or duplicate.
            return Err(RatchetError::MessageKeyGone);
        }

        let to_skip = until - self.nr;
        if to_skip > MAX_SKIP {
            return Err(RatchetError::TooManySkipped(to_skip, MAX_SKIP));
        }

        let dhr = *self.dhr.as_ref().ok_or(RatchetError::NoSession)?.as_bytes();
        let mut chain = *ckr;
        for n in self.nr..until {
            let (next, mk) = kdf_ck(&chain);
            self.skipped.insert((dhr, n), mk);
            chain = next;
        }

        self.ckr = Some(chain);
        self.nr = until;
        Ok(())
    }

    /// The DH ratchet proper: two root derivations, one for the receiving chain (with the old
    /// pair), one for the sending chain (with the new one).
    fn dh_ratchet<R: RngCore + CryptoRng>(&mut self, rng: &mut R, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);

        let dh_out = self.dhs.secret.diffie_hellman(&header.dh).to_bytes();
        let (rk, ckr) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = EphemeralKeyPair::generate(rng);
        let dh_out = self.dhs.secret.diffie_hellman(&header.dh).to_bytes();
        let (rk, cks) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk;
        self.cks = Some(cks);
    }
}

fn aead_seal(mk: &MessageKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let (key, nonce) = derive_message_keys(mk);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| RatchetError::DecryptionFailed)
}

fn aead_open(mk: &MessageKey, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let (key, nonce) = derive_message_keys(mk);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| RatchetError::DecryptionFailed)
}

/// A `Debug` deliberately silent about the secret state.
///
/// Deriving `Debug` here would spit root keys, chain keys and message keys into the first
/// stray `dbg!` or log line. That is a mundane, quiet way to reduce the whole protocol to
/// nothing, and it passes code review because nobody looks at a derive.
impl std::fmt::Debug for DoubleRatchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoubleRatchet")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped", &self.skipped.len())
            .field("has_sending_chain", &self.cks.is_some())
            .field("has_receiving_chain", &self.ckr.is_some())
            .finish_non_exhaustive()
    }
}
