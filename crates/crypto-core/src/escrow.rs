//! Recovery escrow: getting the account back with no device left.
//!
//! # What this is, stated before anything else
//!
//! The account **is** the seed ([`crate::Account`]). Until this module existed, the only way to
//! rebuild it was to retype the twelve words, and the server had never seen that phrase in any
//! form. This module deliberately gives that up: it seals the seed under a key derived from
//! something the user carries — a password, or a WebAuthn PRF secret — and hands the ciphertext
//! to the server.
//!
//! **Whoever obtains that ciphertext can attack the password offline.** The server operator, a
//! SQL dump, a backup tape. Argon2id makes each attempt expensive; it does not make a weak
//! password safe. And since `wac-vault-v1` derives from the same seed, winning that attack also
//! opens every archived message. That is the whole price, and it is why this is opt-in and off
//! by default. See `docs/specs/2026-08-22-recovery-escrow.md`.
//!
//! # The constraint that shapes the design: finding the blob
//!
//! A device recovering an account holds nothing — no device key, no seed. The route that serves
//! the blob is therefore unauthenticated, and indexing the escrow by handle would let anyone
//! download anyone's ciphertext. The offline attack would go from "the operator" to "everyone".
//!
//! So the lookup value is derived from the secret itself. One expensive derivation yields two
//! independent keys: one names the row, the other opens it. Presenting the lookup already
//! requires knowing the password, and the server learns nothing from a failure it can report —
//! a wrong password and a nonexistent escrow return the same answer.
//!
//! The consequence to own, rather than discover: a failed attempt names no account, so there is
//! nothing to lock out after N tries. Rate limiting is per-caller, not per-account.
//!
//! # Why the salt is not random
//!
//! It cannot be. Reading the stored parameters requires the lookup key, and computing the lookup
//! key requires the salt: a random salt held server-side is a circular dependency. The salt is
//! therefore `SHA-256("wac-escrow-salt-v1" ‖ handle)` — unique per account, so no single table
//! covers two users, but precomputable against one *named* target. Argon2id's memory cost is
//! what that target's password rests on, which is the honest statement rather than the
//! comfortable one.
//!
//! The cost parameters are constants here rather than server-supplied, for the same circular
//! reason. [`Params`] records what was used at sealing time so a future version can recognise an
//! older escrow and re-derive with the parameters it was made under.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

/// Format version. Covered by the AAD, so a downgrade is a decryption failure, not a weakening.
pub const VERSION: u8 = 1;

/// Memory cost, in kibibytes.
///
/// Four times the local lock's ([`crate::lock`]) 64 MiB, because the two are paid at different
/// rates. The lock runs on every unlock and its cost is a tax on the user; this runs once, on a
/// restore, and its cost is the only thing standing between a stolen database and the account.
///
/// 256 MiB is the ceiling a mobile webview tolerates without the tab being killed. It buys a
/// factor against commodity hardware. It does not buy an argument that a guessable password is
/// safe here.
const MEMORY_KIB: u32 = 256 * 1024;

/// Passes over the memory block.
const ITERATIONS: u32 = 4;

/// Lanes. One: WebAssembly has no threads by default, and announcing more than are used
/// produces a derivation different from the one actually computed.
const LANES: u32 = 1;

/// Derivation labels. Two keys out of one secret are independent only if the `info` differs —
/// hence constants rather than literals scattered across call sites.
const INFO_LOOKUP: &[u8] = b"wac-escrow-lookup-v1";
const INFO_SEAL: &[u8] = b"wac-escrow-seal-v1";

/// Salt domain for the password factor. Prefixed so the handle cannot collide with another
/// use of the same hash function elsewhere in the protocol.
const SALT_DOMAIN: &[u8] = b"wac-escrow-salt-v1";

const NONCE_LEN: usize = 12;

/// Length of the sealed seed, [`crate::Account::export_seed`]'s output.
const SEED_LEN: usize = 64;

/// Which secret opens an escrow.
///
/// Part of the AAD: two factors of the same account seal the same seed, and without this a
/// ciphertext could be presented as the other kind. It costs one byte and removes a class of
/// confusion nobody would otherwise test for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A password the user chose, stretched by Argon2id.
    Password,
    /// 32 bytes from a WebAuthn authenticator's PRF extension. Full entropy: there is nothing
    /// to grind, which is the entire reason this factor exists beside the other.
    Passkey,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Password => 1,
            Kind::Passkey => 2,
        }
    }

    /// The wire name, matching the `kind` column's check constraint in
    /// `migrations/0018_recovery_escrow.sql`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Password => "password",
            Kind::Passkey => "passkey",
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "password" => Ok(Kind::Password),
            "passkey" => Ok(Kind::Passkey),
            _ => Err(CryptoError::Malformed("unknown escrow kind")),
        }
    }
}

/// What the escrow was sealed under, recorded so a later version can recognise it.
///
/// Stored server-side and fed back at recovery. It is **not** trusted to drive the derivation —
/// the constants above do that — it is compared against them, and it is inside the AAD so a
/// server that rewrites it produces a clean failure instead of a quiet downgrade.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Params {
    pub version: u8,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl Params {
    /// The parameters this build seals with.
    pub fn current(kind: Kind) -> Self {
        match kind {
            Kind::Password => {
                Self { version: VERSION, memory_kib: MEMORY_KIB, iterations: ITERATIONS, lanes: LANES }
            }
            // A PRF secret is not stretched: there is no password to make expensive. Zeroes
            // rather than the Argon2 costs, so a passkey escrow cannot be replayed as a
            // password one with plausible-looking parameters.
            Kind::Passkey => Self { version: VERSION, memory_kib: 0, iterations: 0, lanes: 0 },
        }
    }

    pub fn encode(&self) -> [u8; 13] {
        let mut out = [0u8; 13];
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.memory_kib.to_be_bytes());
        out[5..9].copy_from_slice(&self.iterations.to_be_bytes());
        out[9..13].copy_from_slice(&self.lanes.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 13 {
            return Err(CryptoError::Malformed("escrow parameters of unexpected length"));
        }
        Ok(Self {
            version: bytes[0],
            memory_kib: u32::from_be_bytes(bytes[1..5].try_into().expect("4 bytes")),
            iterations: u32::from_be_bytes(bytes[5..9].try_into().expect("4 bytes")),
            lanes: u32::from_be_bytes(bytes[9..13].try_into().expect("4 bytes")),
        })
    }
}

/// The two keys one secret produces.
///
/// `lookup` names the row on a server that must not be able to enumerate rows; `seal` opens it.
/// They come out of the same HKDF with different `info`, so holding one teaches nothing about
/// the other — which matters, because `lookup` is deliberately handed to the server.
pub struct Factor {
    lookup: [u8; 32],
    seal: [u8; 32],
}

impl Drop for Factor {
    fn drop(&mut self) {
        self.lookup.zeroize();
        self.seal.zeroize();
    }
}

/// Redacted: deriving `Debug` would put the sealing key in the first log line that touches it.
impl std::fmt::Debug for Factor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Factor").finish_non_exhaustive()
    }
}

impl Factor {
    /// What the server stores and what the client presents: `SHA-256(lookup key)`.
    ///
    /// The pre-image never leaves the device. The server can compare, and cannot replay the
    /// value it holds against anything else, because nothing else accepts it.
    pub fn lookup_id(&self) -> [u8; 32] {
        Sha256::digest(self.lookup).into()
    }

    fn from_secret(secret: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, secret);

        let mut lookup = [0u8; 32];
        hkdf.expand(INFO_LOOKUP, &mut lookup).expect("32 bytes is valid for HKDF-SHA256");

        let mut seal = [0u8; 32];
        hkdf.expand(INFO_SEAL, &mut seal).expect("32 bytes is valid for HKDF-SHA256");

        Self { lookup, seal }
    }
}

/// The Argon2id salt for an account's password factor.
///
/// Derived from the handle rather than drawn at random — see the module header for why it
/// cannot be random, and what that concedes.
fn password_salt(handle: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SALT_DOMAIN);
    hasher.update(handle.as_bytes());
    hasher.finalize().into()
}

/// Stretches a password into a [`Factor`].
///
/// Costs [`MEMORY_KIB`] of memory and, measured in the shipped WebAssembly build on a desktop,
/// **1.1 seconds** per evaluation. The user pays it twice in the life of an account — setting
/// the password, and recovering with it. An attacker pays it on every guess.
///
/// That figure is what the password floor is set from rather than the other way round: at one
/// second an attempt, a hundred cores make ninety guesses a second, so the 10^14 that
/// `apps/web/src/lib/password.ts` requires of an escrow password is some thirty thousand years
/// of that machine. A floor chosen without the measurement would be a number with no argument
/// behind it.
///
/// `params` must be the ones the escrow was sealed under — [`Params::current`] when sealing,
/// the stored ones when opening. They are validated against a floor rather than trusted: a
/// server cannot make this cheap by asking.
pub fn derive_password_factor(handle: &str, password: &str, params: &Params) -> Result<Factor> {
    if params.version != VERSION {
        return Err(CryptoError::Malformed("unsupported escrow version"));
    }
    // A server that lowers the cost cannot make the derivation cheap: the client refuses
    // anything below what it would have chosen itself. The comparison is `<` rather than `!=`
    // so a future build raising the cost can still open escrows it made at the old one.
    if params.memory_kib < MEMORY_KIB || params.iterations < ITERATIONS || params.lanes != LANES {
        return Err(CryptoError::Malformed("escrow parameters below the accepted floor"));
    }

    let salt = password_salt(handle);

    let argon = Argon2Params::new(params.memory_kib, params.iterations, params.lanes, Some(64))
        .map_err(|_| CryptoError::Malformed("invalid Argon2 parameters"))?;

    let mut stretched = [0u8; 64];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon)
        .hash_password_into(password.as_bytes(), &salt, &mut stretched)
        .map_err(|_| CryptoError::Malformed("escrow derivation failed"))?;

    let factor = Factor::from_secret(&stretched);
    stretched.zeroize();
    Ok(factor)
}

/// Turns a WebAuthn PRF output into a [`Factor`].
///
/// No stretching, and none is wanted: these 32 bytes come from the authenticator, not from a
/// human. Argon2 over a uniform secret would cost seconds and buy nothing.
pub fn derive_prf_factor(prf_output: &[u8]) -> Result<Factor> {
    if prf_output.len() != 32 {
        return Err(CryptoError::Malformed("PRF output of unexpected length"));
    }
    Ok(Factor::from_secret(prf_output))
}

/// What the seal is bound to.
///
/// The account id stops a hostile server from serving one account's ciphertext under another's
/// lookup; the kind stops a passkey escrow being presented as a password one; the parameters
/// stop a silent downgrade. None of these are attacks the ciphertext alone would survive being
/// wrong about — they simply fail loudly instead of subtly.
fn aad(account: &str, kind: Kind, params: &Params) -> Vec<u8> {
    let mut out = Vec::with_capacity(account.len() + 1 + 1 + 13);
    out.extend_from_slice(account.as_bytes());
    out.push(0);
    out.push(kind.tag());
    out.extend_from_slice(&params.encode());
    out
}

/// Seals the account seed for recovery.
///
/// The plaintext is exactly the 64 bytes [`crate::Account::export_seed`] returns — the same
/// value the pairing packet carries, and worth the whole account.
pub fn seal(
    seed: &[u8; SEED_LEN],
    factor: &Factor,
    account: &str,
    kind: Kind,
    params: &Params,
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&factor.seal)
        .map_err(|_| CryptoError::Malformed("invalid escrow key"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: seed.as_slice(), aad: &aad(account, kind, params) })
        .map_err(|_| CryptoError::Malformed("escrow encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a sealed escrow.
///
/// A wrong password, a tampered ciphertext and a substituted account all land in the same
/// error. That is deliberate: distinguishing them would tell a caller which of the three it
/// got wrong, and the only caller who does not already know is an attacker.
pub fn open(
    sealed: &[u8],
    factor: &Factor,
    account: &str,
    kind: Kind,
    params: &Params,
) -> Result<[u8; SEED_LEN]> {
    if sealed.len() <= NONCE_LEN {
        return Err(CryptoError::Malformed("truncated escrow"));
    }

    let cipher = Aes256Gcm::new_from_slice(&factor.seal)
        .map_err(|_| CryptoError::Malformed("invalid escrow key"))?;
    let nonce = Nonce::from_slice(&sealed[..NONCE_LEN]);

    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload { msg: &sealed[NONCE_LEN..], aad: &aad(account, kind, params) },
        )
        .map_err(|_| CryptoError::Malformed("unreadable or tampered escrow"))?;

    if plaintext.len() != SEED_LEN {
        plaintext.zeroize();
        return Err(CryptoError::Malformed("escrow does not hold a seed"));
    }

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(seed)
}

/// Draws a passphrase from the BIP-39 English word list.
///
/// # Why this exists beside a password field
///
/// A recovery password is attacked offline, at the attacker's leisure, and it opens the account
/// and the whole archive with it. A password a person invents under those stakes is usually
/// worse than they believe — `apps/web/src/lib/password.ts` says why, and zxcvbn is there to
/// say so on screen. Offering a drawn phrase is the only way to hand somebody a secret whose
/// strength is a number rather than a hope.
///
/// Eleven bits a word, from the same 2048-word list the recovery phrase uses — so this adds no
/// dictionary to the binary and no second vocabulary for a user to learn. Six words is 66 bits,
/// which is the order Argon2id at [`MEMORY_KIB`] is worth defending.
///
/// **This is not a recovery phrase.** Twelve words from this list *are* an account; six are a
/// password that opens an escrow of one. Nothing distinguishes them on screen, so whatever
/// displays this has to.
///
/// `2^32 % 2048 == 0`, so the modulo below draws uniformly. Worth saying: the same line over a
/// list whose length is not a power of two would be biased, and would look exactly like this.
pub fn generate_passphrase(words: usize) -> Result<String> {
    use rand_core::RngCore;

    if !(4..=12).contains(&words) {
        return Err(CryptoError::Malformed("passphrase length out of range"));
    }

    let list = bip39::Language::English.word_list();
    let drawn: Vec<&str> = (0..words)
        .map(|_| list[(rand_core::OsRng.next_u32() % list.len() as u32) as usize])
        .collect();

    Ok(drawn.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped cost is 256 MiB and four passes. Paying it in every test would make the
    /// suite unusable for no gain: what these check is the wiring around Argon2, not Argon2.
    /// Only [`a_password_actually_stretches`] and the floor test run the real thing.
    fn factor(secret: &[u8]) -> Factor {
        Factor::from_secret(secret)
    }

    fn password_params() -> Params {
        Params::current(Kind::Password)
    }

    #[test]
    fn a_sealed_seed_comes_back_whole() {
        let seed = [7u8; SEED_LEN];
        let f = factor(b"a secret");
        let params = password_params();
        let sealed = seal(&seed, &f, "abcd", Kind::Password, &params).expect("seal");
        assert_eq!(open(&sealed, &f, "abcd", Kind::Password, &params).expect("open"), seed);
    }

    #[test]
    fn a_different_secret_opens_nothing() {
        let seed = [7u8; SEED_LEN];
        let params = password_params();
        let sealed = seal(&seed, &factor(b"a secret"), "abcd", Kind::Password, &params).expect("seal");
        assert!(open(&sealed, &factor(b"a secrat"), "abcd", Kind::Password, &params).is_err());
    }

    #[test]
    fn an_escrow_does_not_open_under_another_account() {
        let seed = [7u8; SEED_LEN];
        let f = factor(b"a secret");
        let params = password_params();
        let sealed = seal(&seed, &f, "abcd", Kind::Password, &params).expect("seal");
        assert!(open(&sealed, &f, "efgh", Kind::Password, &params).is_err());
    }

    #[test]
    fn a_password_escrow_does_not_open_as_a_passkey_one() {
        let seed = [7u8; SEED_LEN];
        let f = factor(b"a secret");
        let sealed = seal(&seed, &f, "abcd", Kind::Password, &password_params()).expect("seal");
        assert!(open(&sealed, &f, "abcd", Kind::Passkey, &Params::current(Kind::Passkey)).is_err());
    }

    #[test]
    fn tampered_parameters_are_a_failure_and_not_a_downgrade() {
        let seed = [7u8; SEED_LEN];
        let f = factor(b"a secret");
        let params = password_params();
        let sealed = seal(&seed, &f, "abcd", Kind::Password, &params).expect("seal");

        let lied = Params { iterations: params.iterations + 1, ..params };
        assert!(open(&sealed, &f, "abcd", Kind::Password, &lied).is_err());
    }

    /// The lookup value is handed to the server. If it leaked the sealing key, handing it over
    /// would hand over the account.
    #[test]
    fn the_lookup_value_is_not_the_sealing_key() {
        let f = factor(b"a secret");
        assert_ne!(f.lookup_id().as_slice(), f.seal.as_slice());
        assert_ne!(f.lookup.as_slice(), f.seal.as_slice());
    }

    #[test]
    fn a_truncated_escrow_is_refused_rather_than_panicking() {
        let f = factor(b"a secret");
        assert!(open(&[], &f, "abcd", Kind::Password, &password_params()).is_err());
        assert!(open(&[0u8; NONCE_LEN], &f, "abcd", Kind::Password, &password_params()).is_err());
    }

    #[test]
    fn a_prf_factor_needs_exactly_thirty_two_bytes() {
        assert!(derive_prf_factor(&[0u8; 32]).is_ok());
        assert!(derive_prf_factor(&[0u8; 31]).is_err());
        assert!(derive_prf_factor(&[0u8; 33]).is_err());
    }

    #[test]
    fn a_prf_escrow_round_trips() {
        let seed = [9u8; SEED_LEN];
        let f = derive_prf_factor(&[3u8; 32]).expect("prf factor");
        let params = Params::current(Kind::Passkey);
        let sealed = seal(&seed, &f, "abcd", Kind::Passkey, &params).expect("seal");
        assert_eq!(open(&sealed, &f, "abcd", Kind::Passkey, &params).expect("open"), seed);

        let other = derive_prf_factor(&[4u8; 32]).expect("prf factor");
        assert!(open(&sealed, &other, "abcd", Kind::Passkey, &params).is_err());
    }

    #[test]
    fn parameters_survive_a_round_trip() {
        for kind in [Kind::Password, Kind::Passkey] {
            let p = Params::current(kind);
            assert_eq!(Params::decode(&p.encode()).expect("decode"), p);
            assert_eq!(Kind::parse(kind.as_str()).expect("parse"), kind);
        }
        assert!(Params::decode(&[0u8; 12]).is_err());
        assert!(Kind::parse("phrase").is_err());
    }

    /// A server asking for a cheap derivation is refused **before** Argon2 runs, so it cannot
    /// make a stolen ciphertext cheaper to grind by serving weak parameters back.
    #[test]
    fn parameters_below_the_floor_are_refused() {
        let weak = Params { version: VERSION, memory_kib: 8, iterations: 1, lanes: LANES };
        assert!(derive_password_factor("bob", "correct horse battery staple", &weak).is_err());

        let wrong_version = Params { version: VERSION + 1, ..password_params() };
        assert!(derive_password_factor("bob", "x", &wrong_version).is_err());
    }

    /// The one test that pays the real cost, because the two properties it pins cannot be
    /// checked any other way: the derivation runs at the shipped parameters, and the handle is
    /// the salt — so the same password held by two accounts yields two unrelated escrows. Were
    /// it otherwise, a server could see that two users chose the same password and grind both
    /// at once.
    #[test]
    fn a_password_actually_stretches_and_the_handle_separates_two_accounts() {
        let params = password_params();
        let bob = derive_password_factor("bob", "correct horse battery staple", &params).expect("bob");
        let alice =
            derive_password_factor("alice", "correct horse battery staple", &params).expect("alice");
        assert_ne!(bob.lookup_id(), alice.lookup_id());

        let seed = [11u8; SEED_LEN];
        let sealed = seal(&seed, &bob, "abcd", Kind::Password, &params).expect("seal");
        assert!(open(&sealed, &alice, "abcd", Kind::Password, &params).is_err());

        let again = derive_password_factor("bob", "correct horse battery staple", &params).expect("again");
        assert_eq!(open(&sealed, &again, "abcd", Kind::Password, &params).expect("open"), seed);
    }
    #[test]
    fn a_drawn_passphrase_has_the_asked_for_number_of_words() {
        let phrase = generate_passphrase(6).expect("passphrase");
        assert_eq!(phrase.split(' ').count(), 6);
        assert!(generate_passphrase(3).is_err());
        assert!(generate_passphrase(13).is_err());
    }

    /// The modulo in `generate_passphrase` is unbiased only because the list is 2048 long.
    /// Pinned here so a word-list change that breaks the property fails a test rather than
    /// silently skewing every drawn passphrase.
    #[test]
    fn the_word_list_is_a_power_of_two() {
        assert_eq!(bip39::Language::English.word_list().len(), 2048);
    }
}
