//! Where a client's state lives between runs.
//!
//! Two things have to survive a restart, and losing either one is not recoverable by retrying:
//!
//! - **The MLS state.** Private keys, group secrets, epochs. Without it a client is not the
//!   member it was, and the only way back into a conversation is to be added again.
//! - **The cursors.** How far it had read in each mailbox. A client that resumes at zero is woken
//!   by its own Welcome and takes it for a message — the first bug anyone writing this loop hits,
//!   and a silent one.
//!
//! # The blob is monolithic, and that is a cost to plan for
//!
//! `Identity::export_state` serialises **everything, all groups together**. A client with five
//! hundred conversations rewrites all five hundred on every save. `crypto-core` names the durable
//! answer in `provider.rs` — `openmls_sqlite_storage`, which would touch only that file — and
//! until then a host with many conversations should shard across several identities rather than
//! grow one blob.
//!
//! # It must be encrypted at rest
//!
//! The exported state is in the clear and holds every private key a client has. [`SealedFile`]
//! is provided so that the obvious implementation is not the dangerous one; a host with a
//! keyring, a KMS or an encrypted column should write its own and is expected to.

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};

use crate::error::{ClientError, Result};
use crate::gateway::Cursor;

/// Everything needed to come back as the same device.
///
/// The MLS state alone is not enough, and that gap is easy to miss until a restarted client
/// finds it can hold a conversation but cannot sign a request. Four things travel together:
///
/// - the **account seed**, which is the power to attest and revoke devices;
/// - the **device id**, which the server knows and which is signed into every attestation;
/// - the **authentication key**, distinct from the MLS signature key — reusing one key for two
///   protocols is a classic mistake, and the two are attested together so that one device's
///   attestation cannot be recombined with another's MLS key;
/// - the **MLS state**: private keys, group secrets, epochs.
///
/// Encoded length-prefixed, the same shape `crypto-core` uses for its own exports.
pub struct DeviceState {
    /// The account's seed. Whoever holds this is the account.
    pub account_seed: [u8; 64],
    /// `{account_id}:{name}`.
    pub device_id: String,
    /// The Ed25519 key this device signs requests with.
    pub auth_key: [u8; 32],
    /// `Identity::export_state()`.
    pub mls_state: Vec<u8>,
}

impl DeviceState {
    /// Serialises the four parts.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.mls_state.len() + self.device_id.len() + 128);
        out.extend_from_slice(&self.account_seed);
        out.extend_from_slice(&self.auth_key);
        push_prefixed(&mut out, self.device_id.as_bytes());
        push_prefixed(&mut out, &self.mls_state);
        out
    }

    /// Reads them back.
    ///
    /// Every length is checked. A truncated blob is an error and never a partially restored
    /// device: one that came back with an identity but no auth key would look healthy until its
    /// first request, and the 401 would point at the server.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 96 {
            return Err(ClientError::Storage("device state is truncated".to_owned()));
        }
        let (account_seed, rest) = bytes.split_at(64);
        let (auth_key, rest) = rest.split_at(32);

        let (device_id, rest) = take_prefixed(rest)?;
        let (mls_state, _) = take_prefixed(rest)?;

        Ok(Self {
            account_seed: account_seed.try_into().expect("64 bytes"),
            auth_key: auth_key.try_into().expect("32 bytes"),
            device_id: String::from_utf8(device_id.to_vec())
                .map_err(|_| ClientError::Storage("device id is not UTF-8".to_owned()))?,
            mls_state: mls_state.to_vec(),
        })
    }
}

fn push_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_prefixed(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    if bytes.len() < 8 {
        return Err(ClientError::Storage("device state is truncated".to_owned()));
    }
    let (length, rest) = bytes.split_at(8);
    let length = u64::from_be_bytes(length.try_into().expect("8 bytes")) as usize;

    if length > rest.len() {
        return Err(ClientError::Storage("device state claims more bytes than it carries".to_owned()));
    }
    Ok(rest.split_at(length))
}

/// What a host must provide for a client to survive a restart.
///
/// Synchronous on purpose. These calls are small and infrequent — one save per batch of
/// envelopes, not one per message — and an async trait here would be dyn-incompatible without
/// boxing every future, which is a large cost imposed on every implementor to serve the few that
/// talk to a network-backed store. A host whose storage genuinely blocks should wrap its calls
/// in `spawn_blocking` rather than make everyone else pay.
pub trait StateStore: Send + Sync {
    /// The MLS state as last saved, or `None` on a first run.
    fn load_identity(&self) -> Result<Option<Vec<u8>>>;

    /// Replaces the saved MLS state.
    ///
    /// Implementations must be **atomic**: a client interrupted mid-write and left with a
    /// truncated blob has lost its membership in every conversation at once.
    fn save_identity(&self, state: &[u8]) -> Result<()>;

    /// Every cursor known, in no particular order.
    fn load_cursors(&self) -> Result<Vec<Cursor>>;

    /// Records how far this client has read in one group.
    fn save_cursor(&self, group_id: &[u8], seq: i64) -> Result<()>;
}

/// A store that keeps everything in memory. For tests, and for a client that is content to
/// re-join every time it starts.
#[derive(Default)]
pub struct Memory {
    identity: std::sync::Mutex<Option<Vec<u8>>>,
    cursors: std::sync::Mutex<std::collections::HashMap<Vec<u8>, i64>>,
}

impl Memory {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn poisoned<T>(_: T) -> ClientError {
    ClientError::Storage("a previous write panicked and poisoned the lock".to_owned())
}

impl StateStore for Memory {
    fn load_identity(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.identity.lock().map_err(poisoned)?.clone())
    }

    fn save_identity(&self, state: &[u8]) -> Result<()> {
        *self.identity.lock().map_err(poisoned)? = Some(state.to_vec());
        Ok(())
    }

    fn load_cursors(&self) -> Result<Vec<Cursor>> {
        Ok(self
            .cursors
            .lock()
            .map_err(poisoned)?
            .iter()
            .map(|(group_id, &seq)| Cursor { group_id: group_id.clone(), seq })
            .collect())
    }

    fn save_cursor(&self, group_id: &[u8], seq: i64) -> Result<()> {
        self.cursors.lock().map_err(poisoned)?.insert(group_id.to_vec(), seq);
        Ok(())
    }
}

/// Two files in a directory: the MLS state, encrypted, and the cursors, which are not secret.
///
/// The key is the host's to manage and is never written here. Losing it is the same as losing
/// the state.
pub struct SealedFile {
    directory: PathBuf,
    key: [u8; 32],
}

impl SealedFile {
    /// Points a store at a directory, creating it if needed.
    pub fn new(directory: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self> {
        let directory = directory.into();
        std::fs::create_dir_all(&directory)
            .map_err(|error| ClientError::Storage(format!("cannot create {}: {error}", directory.display())))?;
        Ok(Self { directory, key })
    }

    fn identity_path(&self) -> PathBuf {
        self.directory.join("identity.sealed")
    }

    fn cursors_path(&self) -> PathBuf {
        self.directory.join("cursors.tsv")
    }

    /// Writes through a temporary file and renames.
    ///
    /// `rename` within a directory is atomic, so a crash leaves either the old file or the new
    /// one — never the half-written blob that would cost every conversation at once.
    fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, bytes)
            .map_err(|error| ClientError::Storage(format!("cannot write {}: {error}", temporary.display())))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| ClientError::Storage(format!("cannot restrict permissions: {error}")))?;
        }

        std::fs::rename(&temporary, path)
            .map_err(|error| ClientError::Storage(format!("cannot replace {}: {error}", path.display())))
    }
}

impl StateStore for SealedFile {
    fn load_identity(&self) -> Result<Option<Vec<u8>>> {
        let sealed = match std::fs::read(self.identity_path()) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ClientError::Storage(format!("cannot read state: {error}"))),
        };

        if sealed.len() < 12 {
            return Err(ClientError::Storage("saved state is too short to hold a nonce".to_owned()));
        }
        let (nonce, ciphertext) = sealed.split_at(12);

        Aes256Gcm::new(&self.key.into())
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &[] })
            .map(Some)
            // The tag failing means the wrong key, or a blob that was altered. Both are worth
            // stopping for: carrying on would mean re-enrolling and silently abandoning every
            // conversation this client was a member of.
            .map_err(|_| {
                ClientError::Storage(
                    "saved state does not open with this key: wrong key, or the file was altered"
                        .to_owned(),
                )
            })
    }

    fn save_identity(&self, state: &[u8]) -> Result<()> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = Aes256Gcm::new(&self.key.into())
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: state, aad: &[] })
            .map_err(|_| ClientError::Storage("cannot seal state".to_owned()))?;

        let mut sealed = Vec::with_capacity(12 + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);

        Self::write_atomically(&self.identity_path(), &sealed)
    }

    fn load_cursors(&self) -> Result<Vec<Cursor>> {
        let text = match std::fs::read_to_string(self.cursors_path()) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(ClientError::Storage(format!("cannot read cursors: {error}"))),
        };

        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (group, seq) = line.split_once('\t').ok_or_else(|| {
                    ClientError::Storage(format!("malformed cursor line: {line}"))
                })?;
                Ok(Cursor {
                    group_id: hex::decode(group)
                        .map_err(|_| ClientError::Storage(format!("cursor group is not hex: {group}")))?,
                    seq: seq
                        .parse()
                        .map_err(|_| ClientError::Storage(format!("cursor seq is not a number: {seq}")))?,
                })
            })
            .collect()
    }

    fn save_cursor(&self, group_id: &[u8], seq: i64) -> Result<()> {
        let mut cursors: std::collections::HashMap<Vec<u8>, i64> = self
            .load_cursors()?
            .into_iter()
            .map(|cursor| (cursor.group_id, cursor.seq))
            .collect();
        cursors.insert(group_id.to_vec(), seq);

        let mut text = String::new();
        for (group, seq) in &cursors {
            text.push_str(&format!("{}\t{seq}\n", hex::encode(group)));
        }
        Self::write_atomically(&self.cursors_path(), text.as_bytes())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("whispee-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn a_device_state_round_trips() {
        let state = DeviceState {
            account_seed: [9u8; 64],
            device_id: "abc123:asap".to_owned(),
            auth_key: [4u8; 32],
            mls_state: b"group secrets".to_vec(),
        };

        let decoded = DeviceState::decode(&state.encode()).unwrap();
        assert_eq!(decoded.account_seed, state.account_seed);
        assert_eq!(decoded.auth_key, state.auth_key);
        assert_eq!(decoded.device_id, state.device_id);
        assert_eq!(decoded.mls_state, state.mls_state);
    }

    /// A partially restored device looks healthy until its first request, and the 401 points at
    /// the server rather than at the truncated blob it actually came from.
    #[test]
    fn a_truncated_device_state_is_refused_rather_than_partially_restored() {
        let encoded = DeviceState {
            account_seed: [1u8; 64],
            device_id: "a:b".to_owned(),
            auth_key: [2u8; 32],
            mls_state: b"x".to_vec(),
        }
        .encode();

        for cut in [0, 50, 95, 100, encoded.len() - 1] {
            assert!(
                DeviceState::decode(&encoded[..cut]).is_err(),
                "a blob cut at {cut} bytes must be refused"
            );
        }
        assert!(DeviceState::decode(&encoded).is_ok(), "the whole blob must still decode");
    }

    #[test]
    fn memory_round_trips() {
        let store = Memory::new();
        assert_eq!(store.load_identity().unwrap(), None, "a first run has nothing saved");

        store.save_identity(b"state").unwrap();
        assert_eq!(store.load_identity().unwrap(), Some(b"state".to_vec()));

        store.save_cursor(b"group", 12).unwrap();
        store.save_cursor(b"group", 13).unwrap();
        assert_eq!(
            store.load_cursors().unwrap(),
            vec![Cursor { group_id: b"group".to_vec(), seq: 13 }],
            "a cursor is replaced, not appended"
        );
    }

    #[test]
    fn a_sealed_file_round_trips() {
        let directory = scratch("roundtrip");
        let store = SealedFile::new(&directory, [7u8; 32]).unwrap();

        assert_eq!(store.load_identity().unwrap(), None);
        store.save_identity(b"private keys and group secrets").unwrap();
        assert_eq!(
            store.load_identity().unwrap(),
            Some(b"private keys and group secrets".to_vec())
        );

        store.save_cursor(&[0xab, 0xcd], 42).unwrap();
        store.save_cursor(&[0x01], 7).unwrap();
        let mut cursors = store.load_cursors().unwrap();
        cursors.sort_by_key(|cursor| cursor.group_id.clone());
        assert_eq!(
            cursors,
            vec![
                Cursor { group_id: vec![0x01], seq: 7 },
                Cursor { group_id: vec![0xab, 0xcd], seq: 42 },
            ]
        );

        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// The property the sealing exists for. Without this test the file could be written in the
    /// clear and every other test here would still pass.
    #[test]
    fn the_state_is_not_readable_on_disk() {
        let directory = scratch("sealed");
        let store = SealedFile::new(&directory, [3u8; 32]).unwrap();
        store.save_identity(b"the vault code is 4815162342").unwrap();

        let on_disk = std::fs::read(store.identity_path()).unwrap();
        assert!(
            !on_disk.windows(8).any(|window| window == b"the vaul"),
            "the state is readable on disk"
        );

        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_wrong_key_is_an_error_and_not_an_empty_store() {
        let directory = scratch("wrongkey");
        SealedFile::new(&directory, [1u8; 32]).unwrap().save_identity(b"state").unwrap();

        let error = SealedFile::new(&directory, [2u8; 32]).unwrap().load_identity();
        assert!(
            matches!(error, Err(ClientError::Storage(_))),
            "a wrong key must stop the client, not look like a first run: re-enrolling would \
             silently abandon every conversation it was a member of"
        );

        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn an_altered_file_is_refused() {
        let directory = scratch("altered");
        let store = SealedFile::new(&directory, [5u8; 32]).unwrap();
        store.save_identity(b"state").unwrap();

        let path = store.identity_path();
        let mut sealed = std::fs::read(&path).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        std::fs::write(&path, &sealed).unwrap();

        assert!(store.load_identity().is_err(), "the tag must catch a flipped byte");

        std::fs::remove_dir_all(&directory).unwrap();
    }
}
