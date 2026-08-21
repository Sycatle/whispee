//! OpenMLS provider: crypto primitives + state storage.
//!
//! `OpenMlsRustCrypto` would do, but it hides its `MemoryStorage` and offers no way to inject
//! a restored one — so no way to reload a session after a restart. We recompose the two
//! ourselves.
//!
//! This is also the switch point to durable storage: swapping `MemoryStorage` for
//! `openmls_sqlite_storage` will touch this file only.

use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

use crate::error::{CryptoError, Result};

#[derive(Default)]
pub struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl Provider {
    /// Serialises the whole state: private keys, group secrets, epochs.
    ///
    /// **This blob is in the clear.** It must be encrypted at rest by the platform's secure
    /// storage (Keychain, Keystore, OS keyring) before it reaches disk. Writing it as-is
    /// would undo the entire protocol.
    ///
    /// Implementation note: we serialise `MemoryStorage`'s public `HashMap` by hand. OpenMLS's
    /// helpers are either behind the `test-utils` feature or — for the `persistence` module —
    /// hardcoded to write cleartext JSON into the temp directory. This format may not survive
    /// an OpenMLS version bump; the durable path is `openmls_sqlite_storage`, and it will only
    /// change this file.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let values = self
            .storage
            .values
            .read()
            .map_err(|_| CryptoError::Storage("poisoned storage lock".into()))?;

        let mut out = Vec::new();
        out.extend_from_slice(&(values.len() as u64).to_be_bytes());
        for (key, value) in values.iter() {
            out.extend_from_slice(&(key.len() as u64).to_be_bytes());
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(key);
            out.extend_from_slice(value);
        }
        Ok(out)
    }

    /// Restores an exported state. The crypto provider itself is stateless.
    ///
    /// Careful: restoring an *old* state rolls the group back an epoch and replays keys that
    /// were already used, destroying forward secrecy. MLS state is not backed up like an
    /// ordinary file — only one live copy may exist.
    pub fn import_state(bytes: &[u8]) -> Result<Self> {
        let provider = Self::default();
        {
            let mut values = provider
                .storage
                .values
                .write()
                .map_err(|_| CryptoError::Storage("poisoned storage lock".into()))?;

            let mut cursor = Reader::new(bytes);
            let count = cursor.u64()?;
            for _ in 0..count {
                let key_len = cursor.u64()? as usize;
                let value_len = cursor.u64()? as usize;
                let key = cursor.bytes(key_len)?.to_vec();
                let value = cursor.bytes(value_len)?.to_vec();
                values.insert(key, value);
            }
        }
        Ok(provider)
    }
}

/// Length-prefixed reader. Any truncation or inconsistent length must produce an error, never
/// a panic: these bytes may come from a corrupted or tampered file.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| CryptoError::Storage("truncated state".into()))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into().unwrap()))
    }
}
