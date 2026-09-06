//! Bringing a new device into existence, in the order the server requires.
//!
//! Four steps that have to happen once, in sequence, and that every client would otherwise
//! rewrite: an account, an MLS identity, an attested device, and a stock of key packages.
//!
//! # What goes in the credential
//!
//! The MLS credential carries the **account id**, not the device id and not the handle. A
//! credential naming something renameable would report an identity change on every rename — MLS
//! doing exactly its job, over a cosmetic edit — and a credential naming the device would do the
//! same on every device rotation. A device is told apart by its signature key, and names itself
//! in the attestation.
//!
//! # The handle is forever
//!
//! Account creation writes to an append-only log. The account cannot be deleted, and a handle,
//! once released, is never reissued. Choose it once.

use crypto_core::{Account, Identity};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use crate::api::{Api, KEY_PACKAGE_TARGET};
use crate::error::{ClientError, Result};
use crate::store::{DeviceState, StateStore};
use crate::transport::Transport;

/// A device that exists on a server and can speak for its account.
pub struct Enrolled {
    /// Typed access to the routes, already signing as this device.
    pub api: Api,
    /// The account's root key. Holds the power to attest and revoke devices.
    pub account: Account,
    /// The account id, derived from the identity key.
    pub account_id: String,
    /// This device's MLS identity.
    pub identity: Identity,
    /// This device's id, `{account_id}:{name}`.
    pub device_id: String,
}

impl Enrolled {
    /// Creates an account and its first device, and publishes a key package stock.
    ///
    /// `handle` must match `^[a-z0-9_]{3,32}$`. `device_name` is the suffix of the device id;
    /// it is not the credential, so it can be as prosaic as `"server"`.
    pub async fn create(base_url: &str, handle: &str, device_name: &str) -> Result<Self> {
        let (account, _phrase) = Account::generate()?;
        let account_id = account.id();

        Api::create_account(base_url, handle, &account.identity_key()).await?;

        let identity = Identity::create(&account_id)?;
        let auth = SigningKey::generate(&mut OsRng);
        let device_id = format!("{account_id}:{device_name}");
        let auth_key = auth.verifying_key().to_bytes();

        // Both keys are attested together. Attesting them separately would let a legitimate
        // device's attestation be recombined with a hostile device's MLS key.
        let attestation = account.attest(&account_id, &device_id, &auth_key, identity.signature_key())?;

        Api::register_device(
            base_url,
            &device_id,
            &account_id,
            &auth_key,
            identity.signature_key(),
            &attestation,
        )
        .await?;

        let api = Api::new(Transport::new(base_url, device_id.clone(), auth));

        let mut packages = Vec::with_capacity(KEY_PACKAGE_TARGET);
        for _ in 0..KEY_PACKAGE_TARGET {
            packages.push(identity.publish_key_package()?);
        }
        api.publish_key_packages(&packages).await?;

        Ok(Self { api, account, account_id, identity, device_id })
    }
}

impl Enrolled {
    /// Writes everything needed to come back as this device.
    ///
    /// Call it after anything that changes MLS state — joining a conversation, processing a
    /// commit — not only at enrolment. The blob is monolithic, so this rewrites all groups at
    /// once; see the note on [`crate::store`].
    pub fn persist(&self, store: &dyn StateStore) -> Result<()> {
        let state = DeviceState {
            account_seed: self.account.export_seed(),
            device_id: self.device_id.clone(),
            auth_key: self.api.transport().signing_key().to_bytes(),
            mls_state: self.identity.export_state()?,
        };
        store.save_identity(&state.encode())
    }

    /// Comes back as a device that was persisted, or `None` if nothing was.
    ///
    /// Restoring rather than re-enrolling matters more than it looks: a new enrolment produces a
    /// **different account**, which is a stranger to every conversation the old one was in. A
    /// client that silently falls back to creating one looks like it recovered and has in fact
    /// abandoned all its groups.
    pub fn restore(base_url: &str, store: &dyn StateStore) -> Result<Option<Self>> {
        let Some(blob) = store.load_identity()? else { return Ok(None) };
        let state = DeviceState::decode(&blob)?;

        let account = Account::from_seed(state.account_seed);
        let account_id = account.id();
        let identity = Identity::restore(&state.mls_state)?;

        if !state.device_id.starts_with(&account_id) {
            return Err(ClientError::Storage(format!(
                "saved device {} does not belong to account {account_id}",
                state.device_id
            )));
        }

        let transport = Transport::new(
            base_url,
            state.device_id.clone(),
            SigningKey::from_bytes(&state.auth_key),
        );

        Ok(Some(Self {
            api: Api::new(transport),
            account,
            account_id,
            identity,
            device_id: state.device_id,
        }))
    }

    /// Restores the persisted device, or enrols a new one and persists it.
    ///
    /// The shape almost every long-running client wants, written once here so that the fallback
    /// is deliberate rather than the accidental result of an unhandled `None`.
    pub async fn load_or_create(
        base_url: &str,
        store: &dyn StateStore,
        handle: &str,
        device_name: &str,
    ) -> Result<Self> {
        if let Some(restored) = Self::restore(base_url, store)? {
            return Ok(restored);
        }

        let enrolled = Self::create(base_url, handle, device_name).await?;
        enrolled.persist(store)?;
        Ok(enrolled)
    }
}
