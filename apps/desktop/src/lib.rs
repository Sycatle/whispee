//! Desktop and mobile application.
//!
//! # Why a library and not just a binary
//!
//! On mobile there is no `main`: the system starts the Android activity or the iOS application,
//! and the Rust code is loaded as a **native library**. Tauri therefore builds the crate with
//! `--lib`, and a crate exposing only a binary fails with `no library targets found` — after
//! several minutes of cross-compilation, which makes the diagnosis all the later.
//!
//! Hence this structure: all the logic lives here, and `main.rs` is only a desktop entry point
//! that calls it. That is the Tauri 2 convention, and it is not cosmetic.
//!
//! # What this application changes in the threat model
//!
//! About the web client, the README repeats a reservation no browser policy lifts: **the server
//! ships the JavaScript, and can ship a version that exfiltrates the keys.** The
//! Content-Security-Policy cannot help — it constrains what the code may do, not who writes it.
//!
//! Here the interface is packaged inside the installed binary. The server no longer ships it, so
//! it can no longer replace it. That is the only known way to close this path, and it is what
//! justifies this application's existence — far more than the comfort of a native window.
//!
//! What it displaces rather than removes: trust now goes to the binary's distribution channel.
//! That is what the verifiable release of `scripts/release.sh` answers — reproducible build
//! first, signature second.
//!
//! # What it does not change yet
//!
//! The cryptography still runs in WebAssembly, in the webview, exactly as on the web. Private
//! keys therefore live in the module's linear memory, reachable by the page's JavaScript. Moving
//! them to native Rust — where `zeroize` really applies and JavaScript has no access — requires
//! making every client crypto call asynchronous, and remains to be done. Until then, writing it
//! down here avoids believing the property already held.

pub mod cipher;
pub mod commands;
pub mod store;

/// Starts the application.
///
/// `mobile_entry_point` generates the symbol the Android activity and the iOS application look
/// for when loading the library. Without it, the build succeeds and the launch fails — the worse
/// of the two ways to fail.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // This list must stay in sync with the commands declared in `commands.rs`: a command left
        // out here still compiles, and only fails when the webview invokes it at runtime.
        .invoke_handler(tauri::generate_handler![
            commands::device_public_key,
            commands::device_sign,
            commands::state_seal,
            commands::state_open,
            commands::session_load,
            commands::session_save,
            commands::session_clear,
            commands::master_seal,
            commands::master_open,
            commands::master_present,
            commands::master_clear,
            commands::biometric_available,
        ])
        // The vault is opened at startup and its failure is fatal: an application that starts
        // without being able to persist seems to work and loses everything on the first restart.
        .setup(|app| commands::install(app))
        .run(tauri::generate_context!())
        .expect("the application could not start");
}
