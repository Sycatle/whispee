//! Session persistence, on the native side.
//!
//! # Why this module exists
//!
//! The client keeps its MLS state in IndexedDB. On mobile that storage is **not guaranteed**:
//! iOS evicts WKWebView data after seven days of inactivity, Android purges under memory
//! pressure. And the loss is final — the MLS ratchet destroys its keys as it goes, so history
//! becomes unreadable and conversations have to be recreated.
//!
//! The application's private directory, by contrast, is only purged on uninstall.
//!
//! # Atomic writing is not an implementation detail
//!
//! It is **the central requirement**, and the only risk this module introduces that IndexedDB did
//! not have. An interrupted IndexedDB transaction leaves the database intact; an interrupted
//! `File::write` leaves a truncated file — an unreadable MLS state, which is exactly the final
//! loss we are trying to avoid.
//!
//! Hence `write to a temporary → fsync → rename → fsync the directory`. The rename is atomic on
//! POSIX as on NTFS: at any instant the final file is either the old content or the new, never a
//! mixture. Both `fsync`s matter as much as the rename — without them the content may only reach
//! the disk after the rename, and a power cut leaves a renamed but empty file.
//!
//! # No previous generation, deliberately
//!
//! Keeping an N-1 copy "to be able to go back" is tempting and **wrong**. The client already
//! documents this about its own backup: an MLS state restored late rewinds epochs and replays
//! already-used keys. A stale state restored silently is a cryptographic fault, not a safety net.
//! The atomic rename is the only acceptable protection.
//!
//! # Two files, not one
//!
//! `session.bin` holds the encrypted session, rewritten on every save. `secrets.bin` holds the
//! device keys, written once. Separating them allows erasing one without the other, which
//! `session_clear` needs: forgetting a session must not destroy an identity the server still
//! knows.
//!
//! Two more have joined them since — `master.bin` and `server.txt` — each for the same kind of
//! reason, argued on its own accessor below. The heading is kept as it was because the argument
//! it makes is about separation, not about the count.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Writes a file such that a reader never sees an intermediate state.
///
/// The temporary is created in the **same directory** as the target: `rename` is only atomic
/// within one filesystem, and a temporary placed in `/tmp` would often cross a mount boundary —
/// the rename would then become a copy, which can be interrupted.
pub fn write_atomically(target: &Path, content: &[u8]) -> std::io::Result<()> {
    let dir = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path without a parent directory")
    })?;

    fs::create_dir_all(dir)?;

    let temporary = target.with_extension("tmp");

    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(content)?;
        // The content must be on disk **before** the rename makes it visible. Without this
        // `sync_all`, a cut between the two leaves a renamed, empty file.
        file.sync_all()?;
    }

    fs::rename(&temporary, target)?;

    // The rename is itself a directory write, and it too can sit in cache. On Windows, opening a
    // directory fails; omitting it there is harmless, `rename` already being transactional on
    // NTFS.
    #[cfg(unix)]
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }

    Ok(())
}

/// Where the session files live.
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The encrypted session. Rewritten on every save.
    pub fn session(&self) -> PathBuf {
        self.root.join("session.bin")
    }

    /// The device keys. Written once, on first launch.
    ///
    /// Separate from the session because their lifetimes and consequences differ: erasing the
    /// session leaves a registered device starting over, erasing the secrets leaves an identity
    /// the server still knows but nobody can prove any more.
    pub fn secrets(&self) -> PathBuf {
        self.root.join("secrets.bin")
    }

    /// The sealed master key of the lock — present only if biometric unlock is enabled.
    ///
    /// A third file, rather than a field of the other two, because its presence **is** the
    /// information: biometric unlock is on if and only if this file exists. Storing it inside the
    /// session would mean opening the session to find out, which presupposes the key it holds.
    pub fn master(&self) -> PathBuf {
        self.root.join("master.bin")
    }

    /// Which delivery service this installation talks to.
    ///
    /// Plain text, and the one file here that is not a blob: it is a value somebody typed, and
    /// somebody looking into their own application directory to find out which server it points
    /// at should be able to read the answer. Nothing in it is secret — the address is in every
    /// packet this application sends.
    ///
    /// A fourth file rather than a field of the session, for the same reason `master.bin` is one:
    /// it has to be readable **before** the session is, being what the session is fetched from.
    /// See [`crate::server`].
    pub fn server(&self) -> PathBuf {
        self.root.join("server.txt")
    }

    /// Reads a file, or `None` if it does not exist.
    ///
    /// Absence is not an error: it is the state of a fresh install, and telling it apart from a
    /// read error is what lets the caller choose between "create a session" and "raise the
    /// alarm". Conflating them would make a failing disk look like a first launch, and erase an
    /// account instead of reporting it.
    pub fn read(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
        match fs::read(path) {
            Ok(content) => Ok(Some(content)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("wac-store-test-{name}"));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn a_write_is_readable_again() {
        let root = temp_dir("reread");
        let paths = Paths::new(root.clone());

        write_atomically(&paths.session(), b"an encrypted state").unwrap();

        assert_eq!(
            Paths::read(&paths.session()).unwrap().as_deref(),
            Some(b"an encrypted state".as_slice()),
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// **The test that carries the module's property.**
    ///
    /// A second write must never leave a mixture of the two contents. That is what the rename
    /// guarantees, and what a `File::create` followed by a `write_all` does not — it truncates
    /// first, then writes.
    #[test]
    fn a_shorter_rewrite_leaves_no_residue() {
        let root = temp_dir("residue");
        let paths = Paths::new(root.clone());

        write_atomically(&paths.session(), b"a very long content to replace").unwrap();
        write_atomically(&paths.session(), b"short").unwrap();

        assert_eq!(
            Paths::read(&paths.session()).unwrap().as_deref(),
            Some(b"short".as_slice()),
            "the tail of the old content survived",
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// A missing file is not an error: it is a fresh install.
    ///
    /// Conflating them would make a failing disk look like a first launch, and create an account
    /// on top of a state that is still there.
    #[test]
    fn a_missing_file_is_distinguished_from_an_error() {
        let paths = Paths::new(temp_dir("missing"));

        assert!(Paths::read(&paths.session()).unwrap().is_none());
    }

    /// The directory is created on demand: on first launch it does not exist.
    #[test]
    fn the_directory_is_created_on_demand() {
        let root = temp_dir("created").join("one").join("two");
        let paths = Paths::new(root.clone());

        write_atomically(&paths.secrets(), b"{}").unwrap();

        assert!(paths.secrets().exists());
        fs::remove_dir_all(root.parent().unwrap().parent().unwrap()).unwrap();
    }

    /// The four files are distinct, and that carries a property.
    ///
    /// Forgetting a session, removing biometric unlock, destroying the device identity and
    /// forgetting which server this is are four acts with different consequences. Two paths that
    /// collided would run the wrong one of the four, with nothing to signal it.
    #[test]
    fn the_four_files_do_not_collide() {
        let paths = Paths::new(temp_dir("distinct"));
        let files = [paths.session(), paths.secrets(), paths.master(), paths.server()];

        for (i, one) in files.iter().enumerate() {
            for other in &files[i + 1..] {
                assert_ne!(one, other);
            }
        }
    }

    /// No temporary may survive a successful write.
    ///
    /// A forgotten `.tmp` is not dangerous in itself, but it holds the state **as the rename sees
    /// it** — one more copy of the blob, which nothing cleans up.
    #[test]
    fn the_temporary_does_not_survive() {
        let root = temp_dir("temporary");
        let paths = Paths::new(root.clone());

        write_atomically(&paths.session(), b"content").unwrap();

        assert!(!paths.session().with_extension("tmp").exists());
        fs::remove_dir_all(&root).unwrap();
    }
}
