//! What the webview may ask of the native process.
//!
//! # A thin layer, deliberately
//!
//! All the logic lives in [`crate::store`] and [`crate::cipher`], which are testable without
//! Tauri or a webview. This module only translates: base64 in, base64 out, errors as strings.
//! That is what lets the thirteen tests of the other two modules exist — a Tauri command needs an
//! `AppHandle`, hence an application, hence nothing unit-testable.
//!
//! # Why base64 and not bytes
//!
//! Tauri's IPC serialises to JSON. A `Vec<u8>` becomes an array of numbers there — over six bytes
//! of JSON per useful byte. Base64 costs a third, which is still a cost: the MLS state crosses
//! this boundary **in the clear** on every save, and it can run to tens of kilobytes.
//!
//! That cost is not measured. If it becomes visible, the only way out that does not bring the key
//! back into the webview is to hand the whole save to Rust — that is, to move MLS storage too,
//! which is another job.
//!
//! # What these commands do not protect
//!
//! They are reachable by any JavaScript on the page. A hostile script can call `state_open` just
//! as it could call `crypto.subtle.decrypt`: what changes is that it cannot carry the key away,
//! not that it cannot use it. The process boundary replaces the JavaScript engine's guarantee; it
//! does not make the webview a safe place.

use std::sync::Mutex;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use tauri::{Manager, State};

use crate::cipher::DeviceSecrets;
use crate::store::{self, Paths};

/// The secrets and the paths, held by the process for the lifetime of the application.
pub struct Vault {
    secrets: Mutex<DeviceSecrets>,
    paths: Paths,
}

impl Vault {
    /// Opens the vault at startup, creating the secrets on first launch.
    pub fn open(root: std::path::PathBuf) -> std::io::Result<Self> {
        let paths = Paths::new(root);
        let secrets = DeviceSecrets::load_or_create(&paths.secrets())?;

        Ok(Self { secrets: Mutex::new(secrets), paths })
    }
}

/// Turns an error into a presentable message, with no exploitable detail.
///
/// I/O errors carry paths, and AEAD errors say nothing useful anyway. The detail goes to the
/// traces, not to the webview.
fn failure(context: &'static str) -> String {
    context.to_owned()
}

#[tauri::command]
pub fn device_public_key(vault: State<'_, Vault>) -> Result<String, String> {
    let secrets = vault.secrets.lock().map_err(|_| failure("vault unavailable"))?;
    Ok(BASE64_STANDARD.encode(secrets.public_key()))
}

#[tauri::command]
pub fn device_sign(payload: String, vault: State<'_, Vault>) -> Result<String, String> {
    let message = BASE64_STANDARD.decode(payload).map_err(|_| failure("unreadable payload"))?;
    let secrets = vault.secrets.lock().map_err(|_| failure("vault unavailable"))?;

    Ok(BASE64_STANDARD.encode(secrets.sign(&message)))
}

#[tauri::command]
pub fn state_seal(plaintext: String, vault: State<'_, Vault>) -> Result<String, String> {
    let clear = BASE64_STANDARD.decode(plaintext).map_err(|_| failure("unreadable plaintext"))?;
    let secrets = vault.secrets.lock().map_err(|_| failure("vault unavailable"))?;

    let sealed = secrets.seal(&clear).map_err(|_| failure("encryption failed"))?;
    Ok(BASE64_STANDARD.encode(sealed))
}

#[tauri::command]
pub fn state_open(blob: String, vault: State<'_, Vault>) -> Result<String, String> {
    let sealed = BASE64_STANDARD.decode(blob).map_err(|_| failure("unreadable blob"))?;
    let secrets = vault.secrets.lock().map_err(|_| failure("vault unavailable"))?;

    // A failure here means either tampering or a key that does not match. Both are serious and
    // indistinguishable: that is the AEAD's property, not sloppiness.
    let clear = secrets.open(&sealed).map_err(|_| failure("decryption failed"))?;
    Ok(BASE64_STANDARD.encode(clear))
}

/// Reads the persisted session, or `None` on first launch.
#[tauri::command]
pub fn session_load(vault: State<'_, Vault>) -> Result<Option<String>, String> {
    let content = Paths::read(&vault.paths.session())
        .map_err(|_| failure("unreadable session"))?;

    Ok(content.map(|bytes| BASE64_STANDARD.encode(bytes)))
}

#[tauri::command]
pub fn session_save(content: String, vault: State<'_, Vault>) -> Result<(), String> {
    let bytes = BASE64_STANDARD.decode(content).map_err(|_| failure("unreadable session"))?;

    store::write_atomically(&vault.paths.session(), &bytes)
        .map_err(|_| failure("write failed"))
}

/// Erases the session, **leaving the secrets alone**.
///
/// The two erasures are distinct because their consequences are: erasing the session leaves a
/// registered device starting over, erasing the secrets leaves an identity the server still knows
/// but nobody can prove any more. `Session.forget` must call both; that is two calls, and it is
/// intended.
#[tauri::command]
pub fn session_clear(vault: State<'_, Vault>) -> Result<(), String> {
    match std::fs::remove_file(vault.paths.session()) {
        Ok(()) => Ok(()),
        // Erasing what does not exist is the requested outcome, not an error.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(failure("erasure failed")),
    }
}

/// Installs the vault into the application.
///
/// Fails loudly if the secrets can be neither read nor created. That is deliberate: starting
/// without a vault would give an application that seems to work and can persist nothing, so it
/// loses everything on the first restart — the costliest failure, and the latest to be seen.
pub fn install(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let root = app.path().app_local_data_dir()?;
    app.manage(Vault::open(root)?);

    Ok(())
}

/// Stores the lock's master key, sealed by the device secrets.
///
/// # What biometric unlock trades away
///
/// A password is stored nowhere: it exists only in its owner's head, and that is what makes the
/// state unreadable to whoever walks off with the disk. Enabling biometrics **writes the master
/// key to the device**, sealed by the secrets, which are themselves in the clear in the
/// application's private directory.
///
/// The protection becomes the system's: the private directory, and the biometric prompt in front
/// of this command. That is solid against whoever picks up the phone, and worthless against
/// whoever extracts its storage — a `root`, an unencrypted backup, a disk image.
///
/// It is **strictly weaker** than the password alone. The interface must say so before offering
/// the button, not after.
#[tauri::command]
pub fn master_seal(master: String, vault: State<'_, Vault>) -> Result<(), String> {
    let clear = BASE64_STANDARD.decode(master).map_err(|_| failure("unreadable key"))?;

    let secrets = vault.secrets.lock().map_err(|_| failure("vault unavailable"))?;
    let sealed = secrets.seal(&clear).map_err(|_| failure("encryption failed"))?;

    store::write_atomically(&vault.paths.master(), &sealed)
        .map_err(|_| failure("write failed"))
}

/// Returns the master key, after the user authenticates.
///
/// The prompt is raised **here**, in the native process, and not by the webview before the call.
/// That difference is the whole point of the scheme: a prompt placed on the JavaScript side is a
/// courtesy a hostile script skips, whereas this one sits on the key's path. Without
/// authentication, the command returns nothing.
///
/// On desktop there is no prompt: desktop platforms expose nothing equivalent through Tauri. The
/// command stays usable there, which is consistent — enabling it is what `biometric_available`
/// refuses upstream.
#[tauri::command]
pub async fn master_open(app: tauri::AppHandle) -> Result<Option<String>, String> {
    authenticate(&app, "Unlock your conversations")?;

    let vault = app.state::<Vault>();
    let Some(sealed) = Paths::read(&vault.paths.master())
        .map_err(|_| failure("unreadable key"))?
    else {
        return Ok(None);
    };

    let secrets = vault.secrets.lock().map_err(|_| failure("vault unavailable"))?;
    let clear = secrets.open(&sealed).map_err(|_| failure("decryption failed"))?;

    Ok(Some(BASE64_STANDARD.encode(clear)))
}

/// Is biometric unlock enabled on this device?
///
/// Without a prompt, deliberately: the interface must be able to decide which button to show
/// before the user has asked for anything. Prompting here would fire on every startup, including
/// to answer "no".
///
/// The question leaks nothing: it does not say what the key is, only that one exists.
#[tauri::command]
pub fn master_present(vault: State<'_, Vault>) -> Result<bool, String> {
    Ok(Paths::read(&vault.paths.master())
        .map_err(|_| failure("unreadable key"))?
        .is_some())
}

/// Removes the master key. The lock stays on; only biometrics stop opening it.
#[tauri::command]
pub fn master_clear(vault: State<'_, Vault>) -> Result<(), String> {
    match std::fs::remove_file(vault.paths.master()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(failure("erasure failed")),
    }
}

/// Is biometric unlock usable on this device?
///
/// Two conditions, not one: the platform must expose the prompt, and the user must have enrolled
/// a fingerprint or a face. A phone whose biometrics nobody configured answers no, and offering
/// the setting there would give a button that fails in use.
#[tauri::command]
pub fn biometric_available(app: tauri::AppHandle) -> bool {
    let _ = &app;

    #[cfg(mobile)]
    {
        use tauri_plugin_biometric::BiometricExt;
        return app.biometric().status().map(|state| state.is_available).unwrap_or(false);
    }

    #[cfg(not(mobile))]
    false
}

/// The system prompt, where it exists.
///
/// On desktop it does not exist and this function lets the call through: `biometric_available` is
/// what prevents enabling the setting there, and refusing here as well would only mislead the
/// diagnosis if a `master.bin` ever ended up on a desktop.
fn authenticate(app: &tauri::AppHandle, reason: &str) -> Result<(), String> {
    let _ = (app, reason);

    #[cfg(mobile)]
    {
        use tauri_plugin_biometric::{AuthOptions, BiometricExt};

        return app
            .biometric()
            .authenticate(reason.to_owned(), AuthOptions::default())
            .map_err(|_| failure("authentication refused"));
    }

    #[cfg(not(mobile))]
    Ok(())
}
