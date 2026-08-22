//! Fetching what a link says about itself, without letting a message choose what we connect to.
//!
//! # The property that decides everything else
//!
//! **A preview generated at the recipient is a leak of their IP by construction.** Somebody who
//! sends `https://their-server/{uuid}` and watches the request arrive learns that the target
//! opened the conversation, when, and from which address. In an application where everything
//! else is encrypted end to end, that is the most profitable side channel available.
//!
//! So three rules hold above every line of code here, and they are not configurable:
//!
//!   - **Never automatic.** A preview happens because a person pressed a button, once.
//!   - **Never remembered.** Nothing is cached: a cache turns one press into a record.
//!   - **Never from a notification or from the rail**, where nobody pressed anything.
//!
//! The button says *Contact this site*, not *Preview*, because that is what it does.
//!
//! Signal solves this differently and better: the **sender** generates the preview and ships it
//! inside the encrypted message, so the recipient contacts nobody. That is the right answer and
//! it is not this one. It needs a field on the wire, which is a protocol change; this is what can
//! be built without one. Recorded as work remaining, not as a detail.
//!
//! # Why this is in Rust rather than in the webview
//!
//! A `fetch` from the page would fail on nearly every site for want of
//! `Access-Control-Allow-Origin`, and widening `connect-src` to `https:` to fix it would hand
//! back the exfiltration channel the CSP exists to close — in exchange for a feature that still
//! would not work. The native process has neither CORS nor a CSP, and it is also the only place
//! where the address we connect to can be decided by us instead of by a resolver.
//!
//! # What the defence actually defends
//!
//! The URL comes from a message, so it was chosen by somebody else. Without care this command is
//! a request forgery primitive pointed at the machine's own network: `http://127.0.0.1:8787`,
//! `http://169.254.169.254/` for cloud metadata, a printer on `192.168.0.0/16`.
//!
//! The order matters and is the whole trick: **we resolve the name ourselves, filter the
//! addresses, and then connect to an address we retained** — see [`fetch_preview`]. Validating a
//! hostname and handing it to a client that resolves it again is not a defence, because the
//! second answer can differ from the first. That is DNS rebinding, and it is the reason
//! `resolve_to_addrs` exists in this file.
//!
//! Redirects are followed by hand for the same reason: a permitted first hop that answers `302
//! http://127.0.0.1/` walks straight through any check made only on the original URL.
//!
//! # What it does not defend
//!
//! The site learns that somebody pressed the button, and from which address. That is the feature.
//! It does not learn which conversation, which account, or what was said — nothing here sends a
//! `Referer`, a cookie, or a User-Agent naming this application.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::Serialize;
use url::{Host, Url};

/// At most three hops, each one re-validated from scratch.
///
/// Three rather than a larger number because a link in a message that needs four is a shortener
/// chain, and one that needs ten is somebody probing.
const MAX_REDIRECTS: usize = 3;

/// A hard stop while reading, in bytes.
///
/// `Content-Length` is never consulted: it is optional, and a hostile server has every reason to
/// understate it. The body is read in chunks and abandoned the moment the total crosses this,
/// which is what bounds the memory rather than what the peer claims about it.
const MAX_BODY: usize = 256 * 1024;

/// Long enough for a slow site, short enough that nobody watches a spinner.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Around the **whole** redirect loop, not around one request.
///
/// `reqwest`'s own timeout applies per request, so three deliberately slow hops of five seconds
/// each are fifteen seconds that no per-request timeout ever notices.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(6);

/// Deliberately anonymous.
///
/// Not `Whispee/0.1.0`: that would tell every site somebody previews from which software the
/// person is running, which is exactly the kind of thing this application exists not to disclose.
const USER_AGENT: &str = "Mozilla/5.0 (compatible)";

/// How much of a document is worth scanning for its own description.
///
/// Metadata lives in `<head>`; a megabyte of body after it holds nothing this reads.
const MAX_SCAN: usize = 128 * 1024;

/// Titles and descriptions are labels, not documents.
const MAX_TITLE: usize = 200;
const MAX_DESCRIPTION: usize = 400;

/// What comes back to the interface.
///
/// `image` is a URL and not bytes: fetching it is a second, separate command with its own budget
/// and its own failure. The card shows text without ever downloading a picture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkPreview {
    /// The URL finally reached, after redirects — not the one that was asked for.
    pub url: String,
    /// Its host, for display beside the title.
    pub host: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
}

/// Why a URL will not be contacted.
///
/// A type rather than a string so that the caller cannot accidentally render a reason as a title,
/// and so that adding a rule forces every match to be revisited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not `https`, or not on port 443.
    Scheme,
    /// `https://user:pass@host/` — the shape that makes `evil.tld` look like `google.com`.
    Userinfo,
    /// No host at all, or one that does not parse.
    Host,
    /// The name resolved, and every address it resolved to is one we will not talk to.
    Address,
    /// More hops than [`MAX_REDIRECTS`].
    Redirects,
}

impl Refusal {
    /// One sentence, in the interface's language of last resort.
    ///
    /// These strings cross into JavaScript and are shown as they are. They name what was refused
    /// and never quote the URL back — a title echoed into a message list is how a crafted host
    /// becomes a sentence somebody trusts.
    pub fn message(self) -> &'static str {
        match self {
            Refusal::Scheme => "Only https links on the standard port can be contacted.",
            Refusal::Userinfo => "This link carries a name and password, which hides where it goes.",
            Refusal::Host => "This link has no site to contact.",
            Refusal::Address => "This link points back at this machine or its local network.",
            Refusal::Redirects => "This link redirects too many times.",
        }
    }
}

/// Checks the shape of a URL, before anything is resolved or connected.
///
/// **A whitelist, and it stops at `https`.** `http` is absent on purpose: a preview is a request
/// this application makes on somebody's behalf to a site they have not chosen, and doing it in
/// clear text hands the page — and therefore the fact of the press — to the network between here
/// and there. Everything else (`javascript:`, `data:`, `file:`) is refused by the same clause,
/// which is why it is a whitelist and not a list of the schemes we happen to have thought of.
///
/// The port is pinned to 443 for a narrower reason: without that, this command reaches every
/// service on a host that survives the address filter, which turns a preview into a port scanner
/// with a readable result.
pub fn validate(raw: &str) -> Result<Url, Refusal> {
    let url = Url::parse(raw).map_err(|_| Refusal::Host)?;

    if url.scheme() != "https" {
        return Err(Refusal::Scheme);
    }
    // `port()` is `None` when the URL uses the scheme's default, which for `https` is 443.
    if !matches!(url.port(), None | Some(443)) {
        return Err(Refusal::Scheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Refusal::Userinfo);
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(Refusal::Host);
    }

    Ok(url)
}

/// Whether we are willing to open a connection to this address.
///
/// Everything private, local, or administrative is refused. The list is written out rather than
/// leaning on `is_global`, which is unstable, and each entry says what it keeps out.
pub fn addr_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_allowed(v4),
        // **The mapped form is unwrapped and re-tested, and this is the classic bypass.**
        // `::ffff:127.0.0.1` is a v6 address by type and a loopback address by effect: none of
        // the v6 predicates below match it, and the operating system connects to 127.0.0.1 all
        // the same.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4_allowed(v4),
            None => v6_allowed(v6),
        },
    }
}

fn v4_allowed(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();

    // `is_private` covers 10/8, 172.16/12 and 192.168/16; `is_link_local` covers 169.254/16,
    // which is where `169.254.169.254` lives — the cloud metadata endpoint, and the single most
    // valuable address a request forgery can reach.
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
        return false;
    }
    if ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() || ip.is_documentation() {
        return false;
    }
    // 100.64/10, carrier-grade NAT. `Ipv4Addr::is_shared` is unstable, so it is spelled out: the
    // second octet runs from 64 to 127 inclusive.
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    // 0.0.0.0/8 — "this network". Reaching it is never meaningful and on Linux it is loopback.
    if a == 0 {
        return false;
    }
    // 240/4, reserved. Refused for the same reason as documentation space: nothing legitimate
    // answers there, so a URL pointing at it is a probe.
    if a >= 240 {
        return false;
    }
    true
}

fn v6_allowed(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    let [a, b, ..] = ip.segments();
    // fe80::/10, link-local unicast. `is_unicast_link_local` is unstable.
    if a & 0xffc0 == 0xfe80 {
        return false;
    }
    // fc00::/7, unique local. `is_unique_local` is unstable.
    if a & 0xfe00 == 0xfc00 {
        return false;
    }
    // 2001:db8::/32, documentation.
    if a == 0x2001 && b == 0x0db8 {
        return false;
    }
    true
}

/// The three strings a page offers about itself.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
}

/// Reads a document's own description of itself, without executing anything.
///
/// **A bounded scanner rather than a real HTML parser**, and the reason is the binary this ends
/// up in. `html5ever` is tens of thousands of lines of parsing code compiled into the process
/// that holds the identity key, to extract three strings. The scanner below is wrong in ways a
/// conforming parser is not — it does not build a tree, and it will not recover from every
/// malformation — and being wrong here produces a worse title, never an execution.
///
/// Three details are not optional:
///
///   - **`<script>`, `<style>`, `<template>` and comments are skipped wholesale.** Without that,
///     a `<title>` written inside a JavaScript string wins over the real one, which is a free way
///     to put a chosen sentence on somebody's screen.
///   - **Scanning stops at `</head>`.** Metadata that appears after it was not put there by the
///     document's author in any meaningful sense.
///   - **Precedence is Open Graph, then Twitter, then native.** A page that publishes both has
///     said which it means.
pub fn parse_metadata(html: &str, base: &Url) -> Metadata {
    let mut og = Metadata::default();
    let mut twitter = Metadata::default();
    let mut native = Metadata::default();

    // A byte cap on a `str` has to land on a character boundary, or the slice panics — and the
    // document was written by the site being previewed, so a multi-byte character across the
    // limit is a crash somebody else chooses.
    let cap = (0..=html.len().min(MAX_SCAN))
        .rev()
        .find(|&at| html.is_char_boundary(at))
        .unwrap_or(0);
    let source = &html[..cap];
    let bytes = source.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }

        let rest = &source[i..];

        if rest.starts_with("<!--") {
            i += skip_to(rest, "-->").unwrap_or(rest.len());
            continue;
        }
        if starts_with_tag(rest, "/head") {
            break;
        }
        // Skipped wholesale, and the cursor resumes the outer loop rather than falling through:
        // after the skip it sits in the middle of a document, where a tag test would match on
        // whatever happens to be there.
        let mut skipped = false;
        for opaque in ["script", "style", "template"] {
            if starts_with_tag(rest, opaque) {
                let close = format!("</{opaque}");
                i += skip_to(rest, &close).unwrap_or(rest.len());
                skipped = true;
                break;
            }
        }
        if skipped {
            continue;
        }

        if starts_with_tag(rest, "title") {
            if let Some(open_end) = rest.find('>') {
                let after = &rest[open_end + 1..];
                let text = after.find("</").map_or(after, |end| &after[..end]);
                native.title = clean(text, MAX_TITLE);
            }
        } else if starts_with_tag(rest, "meta")
            && let Some(open_end) = rest.find('>')
        {
            let attrs = attributes(&rest[..open_end]);
            let key = attrs
                .iter()
                .find(|(name, _)| name == "property" || name == "name")
                .map(|(_, value)| value.to_ascii_lowercase());
            let content = attrs
                .iter()
                .find(|(name, _)| name == "content")
                .map(|(_, value)| value.clone());

            if let (Some(key), Some(content)) = (key, content) {
                match key.as_str() {
                    "og:title" => og.title = clean(&content, MAX_TITLE),
                    "og:description" => og.description = clean(&content, MAX_DESCRIPTION),
                    "og:image" => og.image = clean(&content, MAX_DESCRIPTION),
                    "twitter:title" => twitter.title = clean(&content, MAX_TITLE),
                    "twitter:description" => {
                        twitter.description = clean(&content, MAX_DESCRIPTION);
                    }
                    "twitter:image" => twitter.image = clean(&content, MAX_DESCRIPTION),
                    "description" => native.description = clean(&content, MAX_DESCRIPTION),
                    _ => {}
                }
            }
        }

        // Always advance: a tag we did not recognise must not leave the cursor where it was, or
        // this loop never ends on a document that contains one.
        i += 1;
    }

    let mut out = Metadata {
        title: og.title.or(twitter.title).or(native.title),
        description: og.description.or(twitter.description).or(native.description),
        image: og.image.or(twitter.image),
    };

    // An image reference is relative more often than not, and it is about to become a URL we
    // connect to — so it is resolved against the page and re-validated like any other.
    out.image = out
        .image
        .and_then(|candidate| base.join(&candidate).ok())
        .filter(|resolved| validate(resolved.as_str()).is_ok())
        .map(|resolved| resolved.to_string());

    out
}

/// Whether `rest` opens the named element.
///
/// Matches `<meta ` and `<meta>` and `<meta\n`, and refuses `<metadata`: without the check on the
/// following character, `og:` metadata would be read out of an element that is not `<meta>`.
fn starts_with_tag(rest: &str, name: &str) -> bool {
    let Some(after) = rest.strip_prefix('<') else {
        return false;
    };
    if after.len() < name.len() {
        return false;
    }
    let (head, tail) = after.split_at(name.len());
    head.eq_ignore_ascii_case(name)
        && tail
            .chars()
            .next()
            .is_none_or(|c| c.is_ascii_whitespace() || c == '>' || c == '/')
}

/// The offset just past `needle`, or `None` if it never closes.
fn skip_to(rest: &str, needle: &str) -> Option<usize> {
    rest.find(needle).map(|at| at + needle.len())
}

/// The `name="value"` pairs of an opening tag, lower-cased names, values as written.
fn attributes(tag: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = tag.as_bytes();
    let mut i = tag.find(char::is_whitespace).unwrap_or(tag.len());

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && !matches!(bytes[i], b'=' | b'/' | b'>') && !(bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if start == i {
            i += 1;
            continue;
        }
        let name = tag[start..i].to_ascii_lowercase();

        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            out.push((name, String::new()));
            continue;
        }
        i += 1;
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let value = match bytes[i] {
            quote @ (b'"' | b'\'') => {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let value = tag[start..i.min(tag.len())].to_string();
                i += 1;
                value
            }
            _ => {
                let start = i;
                while i < bytes.len()
                    && !(bytes[i] as char).is_ascii_whitespace()
                    && bytes[i] != b'>'
                {
                    i += 1;
                }
                tag[start..i.min(tag.len())].to_string()
            }
        };

        out.push((name, value));
    }

    out
}

/// Trims, decodes the few entities that matter, strips what must never reach a label, and bounds
/// the length.
///
/// **The bidirectional marks are the point, not the control characters.** U+202A–U+202E and
/// U+2066–U+2069 reorder the text that follows them, including text that is not theirs: a title
/// carrying U+202E can reverse the host name displayed beside it, so a card can be made to read
/// `moc.live` as `evil.com` — or the other way round, which is the dangerous direction. They are
/// removed rather than escaped, because there is no legitimate use for an unterminated override
/// inside a one-line label.
pub fn clean(raw: &str, limit: usize) -> Option<String> {
    let decoded = decode_entities(raw);
    let mut out = String::with_capacity(decoded.len());
    let mut spaced = false;

    for c in decoded.chars() {
        let strip = matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}')
            || (c.is_control() && c != '\t');
        if strip {
            continue;
        }
        if c.is_whitespace() {
            // Newlines and runs of spaces collapse: this is a label on one line, and a title that
            // was pretty-printed across four of them should not become four lines here.
            if !out.is_empty() {
                spaced = true;
            }
            continue;
        }
        if spaced {
            out.push(' ');
            spaced = false;
        }
        out.push(c);
    }

    if out.is_empty() {
        return None;
    }
    if out.chars().count() > limit {
        out = out.chars().take(limit).collect::<String>() + "…";
    }
    Some(out)
}

/// The five entities that appear in real titles, and no more.
///
/// A full table would be a second dependency's worth of data for a gain nobody would notice; an
/// undecoded `&mdash;` shows as itself, which is wrong and harmless.
fn decode_entities(raw: &str) -> String {
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        // Last, or it would corrupt the others: `&amp;lt;` must decode to `&lt;`, not to `<`.
        .replace("&amp;", "&")
}

/// A picture is bigger than a page's `<head>`, and it has its own budget.
///
/// A megabyte covers the 1200×630 card every site publishes and refuses the multi-megabyte
/// original somebody points at instead. It is separate from [`MAX_BODY`] so that raising one
/// never silently raises the other.
const MAX_IMAGE: usize = 1024 * 1024;

/// Resolves a host ourselves and returns one address we are willing to use.
///
/// **This is the function the module exists for.** Every address the name resolves to is checked,
/// and the first acceptable one is returned so the caller can pin the connection to it. Checking
/// a name and then letting a client resolve it again is not a check: the second answer may
/// differ, which is DNS rebinding.
///
/// A name that resolves *only* to refused addresses is refused, rather than falling back — a host
/// whose every address is private is a host pointed at this machine's network.
async fn resolve_allowed(host: Host<&str>, port: u16) -> Result<std::net::SocketAddr, Refusal> {
    // **The typed host, not the string.** `host_str()` renders an IPv6 literal with its brackets,
    // so `"[::ffff:127.0.0.1]".parse::<IpAddr>()` fails and the address falls through to the
    // resolver — where it is refused, but by accident rather than by this filter. Leaning on a
    // resolver to fail is not a defence, and the case it lets through is the one this module is
    // most careful about elsewhere.
    let literal = match host {
        Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        Host::Domain(_) => None,
    };
    if let Some(literal) = literal {
        return if addr_allowed(literal) {
            Ok(std::net::SocketAddr::new(literal, port))
        } else {
            Err(Refusal::Address)
        };
    }

    let Host::Domain(name) = host else {
        unreachable!("the literal cases returned above");
    };

    tokio::net::lookup_host((name, port))
        .await
        .map_err(|_| Refusal::Host)?
        .find(|candidate| addr_allowed(candidate.ip()))
        .ok_or(Refusal::Address)
}

/// One hop: validate, resolve, pin, send. Never follows a redirect itself.
async fn hop(url: &Url) -> Result<reqwest::Response, String> {
    let host = url.host().ok_or(Refusal::Host).map_err(stringify)?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addr = resolve_allowed(host, port).await.map_err(stringify)?;
    // `resolve_to_addrs` keys on the name as written, which for a literal is the bracketed form.
    let pinned = url.host_str().ok_or(Refusal::Host).map_err(stringify)?;

    let client = reqwest::Client::builder()
        // The pin. Everything above is worthless without this line: it is what makes the address
        // we checked the address we connect to.
        .resolve_to_addrs(pinned, &[addr])
        // Followed by hand instead, so that each hop is re-validated. A client that follows them
        // walks past every check made on the first URL.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(USER_AGENT)
        // No `Referer` on a redirect, which would otherwise disclose the first site to the second.
        .referer(false)
        .build()
        .map_err(|_| "This link could not be contacted.".to_string())?;

    client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| "This site did not answer.".to_string())
}

/// Where a `Location` header actually points, re-validated from scratch.
///
/// Joined against the current URL because `Location` is allowed to be relative, and put back
/// through [`validate`] because it is a URL the *site* chose rather than the message: this is
/// where `302 https://127.0.0.1/` and `302 http://…` are caught. A check made only on the URL a
/// person clicked is not a check at all.
fn redirect_target(current: &Url, location: &str) -> Result<Url, Refusal> {
    current
        .join(location)
        .map_err(|_| Refusal::Host)
        .and_then(|candidate| validate(candidate.as_str()))
}

/// Follows at most [`MAX_REDIRECTS`] hops, re-validating every one, and returns what answered
/// together with the URL that finally answered it.
async fn follow(start: &str) -> Result<(Url, reqwest::Response), String> {
    let mut url = validate(start).map_err(stringify)?;

    for _ in 0..=MAX_REDIRECTS {
        let response = hop(&url).await?;

        if !response.status().is_redirection() {
            return Ok((url, response));
        }

        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "This site redirected to nowhere.".to_string())?;

        url = redirect_target(&url, location).map_err(stringify)?;
    }

    Err(stringify(Refusal::Redirects))
}

/// Reads at most `limit` bytes, chunk by chunk, and stops at the limit rather than at what the
/// peer said.
async fn read_bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "This site stopped answering.".to_string())?
    {
        // Truncate rather than fail: a page whose `<head>` arrived is a page this can read, and
        // refusing it because the body is long would refuse most of the web.
        let room = limit.saturating_sub(body.len());
        if room == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }

    Ok(body)
}

fn stringify(refusal: Refusal) -> String {
    refusal.message().to_string()
}

/// What a site says about one of its own pages.
///
/// **Never called on its own.** Every caller is a person pressing a button — see the rules at the
/// top of this module.
pub async fn fetch_preview(raw: &str) -> Result<LinkPreview, String> {
    // Around the whole loop. Three hops that each answer just inside the connect timeout are
    // otherwise nine seconds no per-request timeout ever sees.
    let work = async {
        let (url, response) = follow(raw).await?;
        let body = read_bounded(response, MAX_BODY).await?;
        // Lossy on purpose: a page in an encoding we do not decode should give a worse title, not
        // an error. Nothing here is executed, so a replacement character costs a glyph.
        let html = String::from_utf8_lossy(&body);
        let meta = parse_metadata(&html, &url);

        Ok(LinkPreview {
            host: url.host_str().unwrap_or_default().to_string(),
            url: url.to_string(),
            title: meta.title,
            description: meta.description,
            image: meta.image,
        })
    };

    tokio::time::timeout(TOTAL_TIMEOUT, work)
        .await
        .unwrap_or_else(|_| Err("This site took too long to answer.".to_string()))
}

/// The bytes of a preview image.
///
/// **These bytes are in exactly the situation of an attachment**: a server nobody vetted chose
/// them. So they are not rendered — they go through `decodePreview` in `lib/preview.ts`, which
/// decodes them and re-emits our own PNG, with no new line of code. That is the demonstration
/// that the decoder was put in the right place: the second source of hostile images reuses the
/// first one's defence unchanged.
///
/// A second command rather than part of the first, so that the text card can be shown without
/// ever downloading a picture.
pub async fn fetch_image(raw: &str) -> Result<Vec<u8>, String> {
    let work = async {
        let (_, response) = follow(raw).await?;
        read_bounded(response, MAX_IMAGE).await
    };

    tokio::time::timeout(TOTAL_TIMEOUT, work)
        .await
        .unwrap_or_else(|_| Err("This image took too long to arrive.".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address parses")
    }

    #[test]
    fn seul_https_sur_le_port_standard_est_accepte() {
        assert!(validate("https://example.com/a").is_ok());
        assert_eq!(validate("http://example.com/").unwrap_err(), Refusal::Scheme);
        assert_eq!(
            validate("javascript:alert(1)").unwrap_err(),
            Refusal::Scheme
        );
        assert_eq!(validate("file:///etc/passwd").unwrap_err(), Refusal::Scheme);
        assert_eq!(validate("data:text/html,x").unwrap_err(), Refusal::Scheme);
        // The port is what turns a preview into a port scanner.
        assert_eq!(
            validate("https://example.com:8787/").unwrap_err(),
            Refusal::Scheme
        );
        assert!(validate("https://example.com:443/").is_ok());
    }

    #[test]
    fn les_identifiants_dans_l_url_sont_refuses() {
        assert_eq!(
            validate("https://google.com@evil.tld/").unwrap_err(),
            Refusal::Userinfo
        );
        assert_eq!(
            validate("https://user:pass@evil.tld/").unwrap_err(),
            Refusal::Userinfo
        );
    }

    /// The four boundaries of `172.16/12`, which is the range people get wrong: it ends at
    /// `172.31`, not at `172.16` and not at `172.255`.
    #[test]
    fn les_quatre_bornes_du_172_16_sur_12() {
        assert!(addr_allowed(ip("172.15.255.255")));
        assert!(!addr_allowed(ip("172.16.0.0")));
        assert!(!addr_allowed(ip("172.31.255.255")));
        assert!(addr_allowed(ip("172.32.0.0")));
    }

    #[test]
    fn les_adresses_locales_et_administratives_sont_refusees() {
        for refused in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            // Cloud metadata. Named on its own line because it is the address this whole module
            // exists to keep out.
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
        ] {
            assert!(!addr_allowed(ip(refused)), "{refused} should be refused");
        }

        for allowed in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "100.63.255.255"] {
            assert!(addr_allowed(ip(allowed)), "{allowed} should be allowed");
        }
    }

    #[test]
    fn les_adresses_v6_locales_sont_refusees() {
        for refused in ["::1", "::", "fe80::1", "fc00::1", "fd00::1", "ff02::1"] {
            assert!(!addr_allowed(ip(refused)), "{refused} should be refused");
        }
        assert!(addr_allowed(ip("2606:4700:4700::1111")));
    }

    /// The bypass: a v6 address that is a v4 loopback once the operating system unwraps it.
    #[test]
    fn les_adresses_v4_mappees_sont_depliees_et_retestees() {
        assert!(!addr_allowed(ip("::ffff:127.0.0.1")));
        assert!(!addr_allowed(ip("::ffff:169.254.169.254")));
        assert!(!addr_allowed(ip("::ffff:10.0.0.1")));
        assert!(addr_allowed(ip("::ffff:1.1.1.1")));
    }

    fn base() -> Url {
        Url::parse("https://example.com/page").expect("base parses")
    }

    #[test]
    fn open_graph_l_emporte_sur_twitter_puis_sur_le_natif() {
        let html = r#"<html><head>
            <title>native</title>
            <meta name="description" content="native description">
            <meta name="twitter:title" content="twitter">
            <meta property="og:title" content="open graph">
        </head><body></body></html>"#;
        let meta = parse_metadata(html, &base());
        assert_eq!(meta.title.as_deref(), Some("open graph"));
        assert_eq!(meta.description.as_deref(), Some("native description"));
    }

    /// A `<title>` inside a script is a chosen sentence, not the document's own.
    #[test]
    fn un_titre_dans_un_script_ne_gagne_pas() {
        let html = r#"<html><head>
            <script>var x = "<title>injected</title>";</script>
            <title>real</title>
        </head></html>"#;
        assert_eq!(
            parse_metadata(html, &base()).title.as_deref(),
            Some("real")
        );
    }

    #[test]
    fn le_balayage_s_arrete_au_head() {
        let html = r#"<html><head><title>real</title></head>
            <body><meta property="og:title" content="late"></body></html>"#;
        assert_eq!(
            parse_metadata(html, &base()).title.as_deref(),
            Some("real")
        );
    }

    #[test]
    fn un_commentaire_ne_fournit_pas_de_metadonnees() {
        let html = r#"<head><!-- <meta property="og:title" content="hidden"> --><title>real</title></head>"#;
        assert_eq!(
            parse_metadata(html, &base()).title.as_deref(),
            Some("real")
        );
    }

    #[test]
    fn une_image_relative_est_resolue_contre_la_page() {
        let html = r#"<head><meta property="og:image" content="/img/card.png"></head>"#;
        assert_eq!(
            parse_metadata(html, &base()).image.as_deref(),
            Some("https://example.com/img/card.png")
        );
    }

    /// An image is a URL we are about to connect to, so it goes through the same gate.
    #[test]
    fn une_image_en_http_ou_en_data_est_ecartee() {
        for hostile in ["http://example.com/a.png", "data:image/png;base64,AAAA"] {
            let html = format!(r#"<head><meta property="og:image" content="{hostile}"></head>"#);
            assert_eq!(parse_metadata(&html, &base()).image, None, "{hostile}");
        }
    }

    #[test]
    fn la_sortie_ne_contient_jamais_de_marque_bidi() {
        let hostile = "abc\u{202e}def\u{2066}ghi";
        let cleaned = clean(hostile, MAX_TITLE).expect("something remains");
        assert_eq!(cleaned, "abcdefghi");
        assert!(!cleaned.chars().any(|c| ('\u{202a}'..='\u{202e}').contains(&c)));
    }

    #[test]
    fn les_espaces_et_les_entites_sont_normalises() {
        assert_eq!(
            clean("  a &amp;  b\n\tc  ", MAX_TITLE).as_deref(),
            Some("a & b c")
        );
        // Decoding order: the ampersand is last, so an escaped entity survives as text.
        assert_eq!(clean("&amp;lt;", MAX_TITLE).as_deref(), Some("&lt;"));
        assert_eq!(clean("   ", MAX_TITLE), None);
    }

    #[test]
    fn un_titre_trop_long_est_borne() {
        let long = "a".repeat(MAX_TITLE + 50);
        let cleaned = clean(&long, MAX_TITLE).expect("something remains");
        assert_eq!(cleaned.chars().count(), MAX_TITLE + 1);
        assert!(cleaned.ends_with('…'));
    }

    /// A document made only of tags the scanner does not know must still terminate.
    #[test]
    fn un_document_non_reconnu_termine() {
        let html = "<".repeat(5000);
        let _ = parse_metadata(&html, &base());
        let html = "<div><span><p>".repeat(2000);
        let _ = parse_metadata(&html, &base());
    }

    /// A literal address in the URL never reaches the resolver, so it has to be caught before it.
    #[tokio::test]
    async fn une_adresse_litterale_locale_est_refusee_sans_resolution() {
        // Through `Url`, so the test exercises the same conversion the caller performs — the
        // bracketed IPv6 form is exactly what a hand-rolled string parse gets wrong. The `Url` is
        // held rather than the host, because `host()` borrows from it.
        for hostile in [
            "https://127.0.0.1/",
            "https://169.254.169.254/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::1]/",
            "https://10.0.0.1/",
        ] {
            let url = Url::parse(hostile).expect("test url parses");
            let refusal = resolve_allowed(url.host().expect("a host"), 443)
                .await
                .expect_err("should be refused");
            assert_eq!(refusal, Refusal::Address, "{hostile}");
        }

        let public = Url::parse("https://1.1.1.1/").expect("test url parses");
        assert_eq!(
            resolve_allowed(public.host().expect("a host"), 443)
                .await
                .expect("a public literal resolves to itself")
                .ip(),
            ip("1.1.1.1")
        );
    }

    /// The hop that walks past a check made only on the first URL.
    #[test]
    fn une_redirection_vers_une_adresse_privee_est_refusee() {
        let current = Url::parse("https://example.com/a").expect("base parses");

        for hostile in [
            "https://127.0.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::ffff:127.0.0.1]/",
            "https://192.168.1.1/",
        ] {
            // The address filter runs at connection time; what `redirect_target` must guarantee
            // here is that the URL is carried through `validate` at all, so the hop is a hop and
            // not a bypass.
            let target = redirect_target(&current, hostile).expect("shape is valid");
            let host = target.host_str().expect("a host");
            let literal: IpAddr = host.trim_matches(['[', ']']).parse().expect("a literal");
            assert!(!addr_allowed(literal), "{hostile} should be refused");
        }

        // Scheme downgrades and non-web schemes die in `validate`, before any address matters.
        assert_eq!(
            redirect_target(&current, "http://example.com/").unwrap_err(),
            Refusal::Scheme
        );
        assert_eq!(
            redirect_target(&current, "file:///etc/passwd").unwrap_err(),
            Refusal::Scheme
        );
        assert_eq!(
            redirect_target(&current, "https://user:pw@evil.tld/").unwrap_err(),
            Refusal::Userinfo
        );
    }

    /// A relative `Location` is the ordinary case and must still resolve against the page.
    #[test]
    fn une_redirection_relative_est_jointe_a_la_page_courante() {
        let current = Url::parse("https://example.com/a/b").expect("base parses");
        assert_eq!(
            redirect_target(&current, "/c").expect("valid").as_str(),
            "https://example.com/c"
        );
    }

    #[test]
    fn metadata_ne_confond_pas_meta_et_metadata() {
        let html = r#"<head><metadata property="og:title" content="wrong"><title>real</title></head>"#;
        assert_eq!(
            parse_metadata(html, &base()).title.as_deref(),
            Some("real")
        );
    }
}
