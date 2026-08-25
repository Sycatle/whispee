//! Which delivery service this installation talks to.
//!
//! # Why this is a stored value and not a constant
//!
//! It used to be a constant: `apps/web/src/lib/api.ts` carried `http://127.0.0.1:8787` and said,
//! in as many words, that "a desktop build aimed at another server would set `__WHISPEE_API__`
//! from the native side. Nothing does today." That made every packaged build — Linux, Windows,
//! macOS, Android, iOS — an application that could only reach a server running on the same
//! machine. It was a demonstration, not something anybody could install.
//!
//! This module is the caller that was missing. The address is asked for once, on first launch,
//! and kept beside the session.
//!
//! # Why the validation lives here rather than in the webview
//!
//! Because this string is what the shell's `connect-src` was widened for. `tauri.conf.json` now
//! allows `https:` and `wss:` — anywhere, since a policy cannot name an origin it will only learn
//! at runtime — and the compensation for that width is that the value reaching it went through a
//! parser first. A check written in the page could be skipped by the page; this one cannot.
//!
//! # Why the address cannot be changed afterwards
//!
//! Changing server means changing account. This device is attested by an account key the other
//! server has never heard of, and its MLS groups live in the first server's tables. So there is no
//! "switch server" that keeps anything, and offering one would offer a way to silently lose an
//! identity. Erasing the device is the exit, and it already exists.
//!
//! Nothing here enforces that — a second `write` would succeed. What enforces it is that the
//! interface offers no path to one; see `apps/web/src/app/ServerSetup.tsx`.

use std::path::Path;

use url::Url;

/// Rejects everything that is not a bare origin this build may be pointed at.
///
/// # What each rule is for
///
/// **The scheme.** `https` anywhere, `http` only towards loopback. Plain HTTP to a remote host
/// would carry the signed requests, and every blob the server holds, over a network anybody on
/// the path can read — and it would do it *silently*, since nothing in the interface distinguishes
/// the two. The loopback exception is for development, where there is no certificate and no
/// network to be on.
///
/// **No credentials.** `https://user:password@host` is a shape phishing uses to make a hostile
/// host read as a familiar one, and nothing here would ever use them.
///
/// **No path, no query, no fragment.** The client appends `/v1/…` to what it is given. A base with
/// a path would produce URLs nobody wrote, and a base with a query would have it swallowed by the
/// concatenation — a failure whose symptom is a 404 that names nothing.
///
/// The returned string is the origin and only the origin, without a trailing slash, so that
/// `format!("{base}/v1/…")` is right by construction.
pub fn normalise(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("no address");
    }

    let url = Url::parse(trimmed).map_err(|_| "not an address")?;

    let host = url.host_str().ok_or("an address needs a host")?;

    // `Url::is_special` is what makes a host comparison meaningful at all: for a non-special
    // scheme the parser does not normalise the host, so this runs after the scheme check.
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(host) => {}
        "http" => return Err("http reaches only a loopback address; use https"),
        _ => return Err("an address begins with https:// or http://"),
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("an address carries no username or password");
    }

    if url.path() != "/" && !url.path().is_empty() {
        return Err("an address ends at the host, with no path");
    }

    if url.query().is_some() || url.fragment().is_some() {
        return Err("an address ends at the host, with no query");
    }

    // `Url::port` is `None` when the port is the scheme's default, which is exactly the port that
    // should not be spelled out: `https://example.test:443` and `https://example.test` name one
    // server, and storing two spellings of it would show two.
    Ok(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

/// Whether a host names this machine.
///
/// # Why three literals and not `IpAddr::is_loopback`
///
/// Because this list has to agree with the one in `apps/desktop/tauri.conf.json`, and a CSP can
/// only name hosts. `127.0.0.2` is a loopback address that `is_loopback` accepts and that the
/// shell's `connect-src` would then block — an address accepted by this validator, written to the
/// file, and refused by the browser engine at the first request, with no error naming the cause.
/// Two rules that are meant to be one rule have to be spelled the same way.
///
/// Literal names rather than a DNS lookup, for the other half of the reason: resolving would let a
/// remote name that happens to answer `127.0.0.1` today unlock plain HTTP, and the answer could
/// change after the check.
fn is_loopback(host: &str) -> bool {
    // `Url::host_str` returns an IPv6 literal in its bracketed serialised form, which is also the
    // form a `connect-src` source has to be written in — so the two spellings match by themselves.
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// The address this installation was pointed at, or `None` before it has been.
///
/// A file that exists but does not parse is treated as absent rather than as an error: the only
/// way to reach that state is manual editing, and the recoverable outcome — ask again — is better
/// than an application that will not start.
pub fn read(path: &Path) -> std::io::Result<Option<String>> {
    let Some(bytes) = crate::store::Paths::read(path)? else {
        return Ok(None);
    };

    let Ok(text) = String::from_utf8(bytes) else {
        return Ok(None);
    };

    Ok(normalise(&text).ok())
}

/// Records the address, after validating it.
pub fn write(path: &Path, raw: &str) -> Result<String, String> {
    let address = normalise(raw).map_err(str::to_owned)?;

    crate::store::write_atomically(path, address.as_bytes())
        .map_err(|_| "the address could not be saved".to_owned())?;

    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_survives_unchanged() {
        assert_eq!(normalise("https://whispee.example").unwrap(), "https://whispee.example");
    }

    #[test]
    fn a_trailing_slash_is_removed() {
        assert_eq!(normalise("https://whispee.example/").unwrap(), "https://whispee.example");
    }

    #[test]
    fn a_port_is_kept_and_a_default_port_is_not() {
        assert_eq!(
            normalise("https://whispee.example:8443").unwrap(),
            "https://whispee.example:8443",
        );
        assert_eq!(normalise("https://whispee.example:443").unwrap(), "https://whispee.example");
    }

    /// The development case, and the only one plain HTTP is allowed for.
    #[test]
    fn http_reaches_loopback() {
        assert_eq!(normalise("http://127.0.0.1:8787").unwrap(), "http://127.0.0.1:8787");
        assert_eq!(normalise("http://localhost:8787").unwrap(), "http://localhost:8787");
    }

    /// **The test this module exists for.** Plain HTTP to a remote host would carry every signed
    /// request in the clear, and nothing in the interface would say so.
    #[test]
    fn http_does_not_reach_anywhere_else() {
        assert!(normalise("http://whispee.example").is_err());
    }

    /// A host that merely *looks* like loopback is not one. `127.0.0.1.example.test` is a name
    /// somebody else owns.
    #[test]
    fn a_host_that_only_looks_like_loopback_is_refused() {
        assert!(normalise("http://127.0.0.1.example.test").is_err());
        assert!(normalise("http://localhost.example.test").is_err());
    }

    /// **The rule this validator shares with the shell's `connect-src`.**
    ///
    /// `127.0.0.2` is a loopback address, and `tauri.conf.json` does not name it. Accepting it
    /// here would store an address the browser engine refuses to contact, with nothing saying so.
    #[test]
    fn a_loopback_address_the_policy_does_not_name_is_refused() {
        assert!(normalise("http://127.0.0.2:8787").is_err());
        assert!(normalise("http://[::1]:8787").is_ok());
    }

    #[test]
    fn credentials_are_refused() {
        assert!(normalise("https://someone:secret@whispee.example").is_err());
    }

    #[test]
    fn a_path_a_query_and_a_fragment_are_refused() {
        assert!(normalise("https://whispee.example/v1").is_err());
        assert!(normalise("https://whispee.example?token=x").is_err());
        assert!(normalise("https://whispee.example#x").is_err());
    }

    #[test]
    fn a_scheme_that_is_not_http_is_refused() {
        assert!(normalise("file:///etc/passwd").is_err());
        assert!(normalise("javascript:alert(1)").is_err());
        assert!(normalise("ws://whispee.example").is_err());
    }

    #[test]
    fn nothing_at_all_is_refused() {
        assert!(normalise("").is_err());
        assert!(normalise("   ").is_err());
        assert!(normalise("whispee.example").is_err());
    }

    #[test]
    fn what_was_written_is_read_back() {
        let root = std::env::temp_dir().join("wac-server-test-roundtrip");
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("server.txt");

        assert!(read(&path).unwrap().is_none());

        write(&path, "https://whispee.example/").unwrap();
        assert_eq!(read(&path).unwrap().as_deref(), Some("https://whispee.example"));

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A hand-edited file reads as "not configured yet" rather than stopping the application.
    #[test]
    fn an_unreadable_file_reads_as_absent() {
        let root = std::env::temp_dir().join("wac-server-test-garbage");
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("server.txt");

        crate::store::write_atomically(&path, b"not an address").unwrap();
        assert!(read(&path).unwrap().is_none());

        std::fs::remove_dir_all(&root).unwrap();
    }
}
