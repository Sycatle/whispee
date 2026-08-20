//! Provider OpenMLS : primitives cryptographiques + stockage d'état.
//!
//! `OpenMlsRustCrypto` conviendrait, mais il encapsule son `MemoryStorage` sans permettre
//! d'en injecter un restauré — donc sans permettre de recharger une session après
//! redémarrage. On recompose les deux nous-mêmes.
//!
//! C'est aussi le point de bascule vers un stockage durable : remplacer `MemoryStorage`
//! par `openmls_sqlite_storage` ne touchera que ce fichier.

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
    /// Sérialise l'intégralité de l'état : clés privées, secrets de groupe, epochs.
    ///
    /// **Ce blob est en clair.** Il doit être chiffré au repos par le stockage sécurisé de
    /// la plateforme (Keychain, Keystore, keyring OS) avant d'atteindre le disque. L'écrire
    /// tel quel reviendrait à annuler tout le protocole.
    ///
    /// Note d'implémentation : on sérialise à la main le `HashMap` public de `MemoryStorage`.
    /// Les helpers d'OpenMLS sont soit derrière la feature `test-utils`, soit — pour le module
    /// `persistence` — codés en dur pour écrire du JSON en clair dans le répertoire temporaire.
    /// Ce format ne survivra pas forcément à une montée de version d'OpenMLS ; le chemin
    /// durable est `openmls_sqlite_storage`, et il ne changera que ce fichier.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let values = self
            .storage
            .values
            .read()
            .map_err(|_| CryptoError::Storage("verrou de stockage empoisonné".into()))?;

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

    /// Restaure un état exporté. Le provider cryptographique, lui, est sans état.
    ///
    /// Attention : restaurer un état *ancien* fait reculer le groupe d'epoch et rejoue des
    /// clés déjà utilisées, ce qui détruit la forward secrecy. Un état MLS ne se sauvegarde
    /// pas comme un fichier ordinaire — il ne doit exister qu'une seule copie vivante.
    pub fn import_state(bytes: &[u8]) -> Result<Self> {
        let provider = Self::default();
        {
            let mut values = provider
                .storage
                .values
                .write()
                .map_err(|_| CryptoError::Storage("verrou de stockage empoisonné".into()))?;

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

/// Lecteur longueur-préfixée. Toute troncature ou longueur incohérente doit produire une
/// erreur, jamais une panique : ces octets peuvent venir d'un fichier corrompu ou modifié.
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
            .ok_or_else(|| CryptoError::Storage("état tronqué".into()))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into().unwrap()))
    }
}
