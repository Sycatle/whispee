//! Device identity and the material published to the server.
//!
//! In MLS the unit of group membership is the **device**, not the user. A user with three
//! devices is three members. That is what makes multi-device native here, where the Signal
//! stack needs a dedicated layer (Sesame).

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};

use crate::error::{CryptoError, Result, mls};
use crate::provider::Provider;

/// The project's ciphersuite: the only one RFC 9420 makes mandatory, hence the one every
/// implementation interoperates on.
///
/// ChaCha20-Poly1305 would be preferable in WASM, where the lack of AES-NI makes AES both
/// slower and harder to keep constant-time. Interoperability wins here, but the choice is
/// worth revisiting if the web becomes the primary platform.
/// Capabilities declared by every leaf in the tree.
///
/// They must cover `ROSTER_EXTENSION`, or MLS rejects any leaf in an administered group. Two
/// places consume them and must agree: KeyPackages, for members we add, and the creation
/// config, for the creator — who has no KeyPackage. Hence this function rather than two
/// literals.
///
/// KeyPackages published before this version do not carry it and must be republished.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::Unknown(crate::roles::ROSTER_EXTENSION)]),
        None,
        None,
    )
}

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub struct Identity {
    pub(crate) provider: Provider,
    pub(crate) credential: CredentialWithKey,
    pub(crate) signer: SignatureKeyPair,
    /// Kept explicitly: the name is needed to rebuild the credential on restore, and pulling
    /// it back out of the credential would mean taking the credential apart.
    name: String,
}

impl Identity {
    /// Creates a device identity.
    ///
    /// `name` is an opaque application identifier (device id, user id). It travels in the
    /// clear inside the credential and is visible to every group member **and** to the
    /// server: put nothing in it you would not want disclosed.
    pub fn create(name: &str) -> Result<Self> {
        let provider = Provider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(provider.storage()).map_err(mls)?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };

        Ok(Self { provider, credential, signer, name: name.to_owned() })
    }

    /// Produces a KeyPackage to publish on the server, serialised in TLS format.
    ///
    /// This is the MLS equivalent of X3DH's prekey bundle: it lets someone add us to a group
    /// while we are offline. **Each KeyPackage is single-use** — its init key is consumed on
    /// add. The server must keep a stock per device and report exhaustion, or nobody can
    /// reach us any more.
    pub fn publish_key_package(&self) -> Result<Vec<u8>> {
        // The `ROSTER_EXTENSION` capability must be declared here, in the leaf, and not only
        // set in the group context: MLS refuses to add a member that does not declare support
        // for the extensions the group requires. Without this line a device could join no
        // administered group — and the error would only show up at add time, far from here.
        //
        // KeyPackages published before this version do not carry it: they must be republished.
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(mls)?;

        MlsMessageOut::from(bundle.key_package().clone())
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Fingerprint of the signature key, to display for out-of-band verification.
    ///
    /// See [`crate::conversation::Conversation::verify_peer`] for what this fingerprint
    /// actually protects — and what it does not.
    pub fn fingerprint(&self) -> String {
        fingerprint(self.signer.public())
    }

    pub fn signature_key(&self) -> &[u8] {
        self.signer.public()
    }

    /// Serialises everything needed to rebuild this identity: the name, the public signature
    /// key, and the provider state.
    ///
    /// The name and public key are indispensable and cannot be recovered from the storage blob
    /// alone: `SignatureKeyPair::read` needs the public key to find the private one, and the
    /// credential needs the name.
    ///
    /// **This blob holds the private keys in the clear.** See [`Provider::export_state`].
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let name = self.name.as_bytes();
        let public_key = self.signer.public();
        let storage = self.provider.export_state()?;

        let mut out = Vec::with_capacity(name.len() + public_key.len() + storage.len() + 24);
        out.extend_from_slice(&(name.len() as u64).to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(public_key.len() as u64).to_be_bytes());
        out.extend_from_slice(public_key);
        out.extend_from_slice(&(storage.len() as u64).to_be_bytes());
        out.extend_from_slice(&storage);
        Ok(out)
    }

    /// Rebuilds an identity from [`Identity::export_state`].
    ///
    /// **Never** restore a state older than the last exported one: groups would roll back an
    /// epoch and replay keys already used, destroying forward secrecy. MLS state is not an
    /// ordinary backup — only one live copy may exist.
    pub fn restore(state: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(state);
        let name = String::from_utf8(reader.length_prefixed()?.to_vec())
            .map_err(|_| CryptoError::Storage("unreadable identity name".into()))?;
        let public_key = reader.length_prefixed()?.to_vec();
        let storage = reader.length_prefixed()?;

        let provider = Provider::import_state(storage)?;

        let signer =
            SignatureKeyPair::read(provider.storage(), &public_key, CIPHERSUITE.signature_algorithm())
                .ok_or_else(|| {
                    CryptoError::Storage("signature key missing from restored state".into())
                })?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: public_key.into(),
        };

        Ok(Self { provider, credential, signer, name })
    }

    /// Identifiers of the groups present in the restored state.
    ///
    /// Storage offers no enumeration: the caller must keep the list of groups it joined and
    /// pass it to [`crate::Conversation::load`].
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Length-prefixed reader, tolerant of truncated or tampered input.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| CryptoError::Storage("truncated state".into()))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn length_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
        let len = usize::try_from(len)
            .map_err(|_| CryptoError::Storage("length out of range".into()))?;
        self.take(len)
    }
}

/// Displayable fingerprint of a public signature key.
///
/// Grouped in blocks of 4 characters: visually comparing two continuous hex strings is
/// notoriously unreliable, and the attack consists precisely of producing a key whose
/// fingerprint *looks like* the right one.
pub fn fingerprint(signature_key: &[u8]) -> String {
    let digest = Sha256::digest(signature_key);
    digest[..16]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Deserialises and validates a KeyPackage received from the server.
///
/// `validate` checks the KeyPackage's signature, its leaf node's signature, its lifetime and
/// its version. **None of that proves anything about the identity behind it.** A malicious
/// server can forge a perfectly valid KeyPackage carrying the name "bob" with its own keys:
/// every one of these checks will pass. Only an out-of-band fingerprint comparison catches
/// the substitution. This is the real weak point of any E2EE deployment.
pub(crate) fn parse_key_package(provider: &Provider, bytes: &[u8]) -> Result<KeyPackage> {
    let message = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| CryptoError::Malformed("unreadable key package"))?;

    let MlsMessageBodyIn::KeyPackage(key_package_in) = message.extract() else {
        return Err(CryptoError::UnexpectedMessage);
    };

    key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls)
}
