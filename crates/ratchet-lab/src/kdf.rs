//! Derivation functions. Every key in the protocol comes out of here.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// The `info` strings separate usage domains: two distinct derivations must never be able to
/// produce the same key, even from identical input.
const INFO_X3DH: &[u8] = b"ratchet-lab/x3dh/v1";
const INFO_ROOT: &[u8] = b"ratchet-lab/root/v1";
const INFO_MESSAGE: &[u8] = b"ratchet-lab/message/v1";

/// Constant bytes prefixing the X3DH input. For X25519, Signal uses 32 bytes of 0xFF. They
/// prevent confusion between the X3DH IKM and a raw DH output.
const X3DH_PREFIX: [u8; 32] = [0xFF; 32];

/// Root key of the Double Ratchet.
pub type RootKey = [u8; 32];
/// Chain key: advances one step per message sent or received.
pub type ChainKey = [u8; 32];
/// Key of a single message. Destroyed after use — that is what gives forward secrecy.
pub type MessageKey = [u8; 32];

/// X3DH's KDF: concatenates the DH outputs and derives the initial shared secret from them.
pub fn kdf_x3dh(dh_outputs: &[[u8; 32]]) -> RootKey {
    let mut ikm = Vec::with_capacity(32 + dh_outputs.len() * 32);
    ikm.extend_from_slice(&X3DH_PREFIX);
    for dh in dh_outputs {
        ikm.extend_from_slice(dh);
    }

    let mut sk = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm)
        .expand(INFO_X3DH, &mut sk)
        .expect("32 bytes is a valid length for HKDF-SHA256");

    ikm.zeroize();
    sk
}

/// DH ratchet: the current root key and a new DH output produce the next root and a fresh
/// chain. This is the step that gives post-compromise security: an attacker who stole the
/// state cannot keep up once a single round trip escapes them.
pub fn kdf_rk(rk: &RootKey, dh_out: &[u8; 32]) -> (RootKey, ChainKey) {
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(rk), dh_out)
        .expand(INFO_ROOT, &mut okm)
        .expect("64 bytes is a valid length for HKDF-SHA256");

    let mut next_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    next_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);

    okm.zeroize();
    (next_rk, ck)
}

/// Symmetric ratchet: one chain step produces a message key and the next chain. The 0x01/0x02
/// constants make the two outputs independent.
pub fn kdf_ck(ck: &ChainKey) -> (ChainKey, MessageKey) {
    let mk = hmac_once(ck, &[0x01]);
    let next_ck = hmac_once(ck, &[0x02]);
    (next_ck, mk)
}

/// Splits a message key into AEAD material. The nonce is derived rather than random: since
/// each message key is used exactly once, nonce reuse — fatal in GCM — is structurally
/// impossible.
pub fn derive_message_keys(mk: &MessageKey) -> ([u8; 32], [u8; 12]) {
    let mut okm = [0u8; 44];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk)
        .expand(INFO_MESSAGE, &mut okm)
        .expect("44 bytes is a valid length for HKDF-SHA256");

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);

    okm.zeroize();
    (key, nonce)
}

fn hmac_once(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
