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
use crate::error::Result;
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
