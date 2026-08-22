/**
 * URLs inside a message: which stretches of text are one, where they lead, and when saying so
 * would be a lie.
 *
 * Pure, like `lib/mention.ts` and `lib/shortcode.ts` next door, and for the same reason: the hard
 * parts here are trailing punctuation and a hostname that is not what it looks like, and neither
 * needs a DOM to be got wrong.
 *
 * # The text of a link is the URL, and that is a decision made elsewhere
 *
 * The markdown this project renders has no `[label](url)` form. That is argued in `markdown.ts`,
 * and it is what makes this module tractable: a link can only ever misrepresent *itself*. There
 * is no separate label to compare against, so the whole question reduces to whether the URL as
 * written means what a reader will take it to mean.
 *
 * # A whitelist of schemes, never a blacklist
 *
 * Only `http:` and `https:` are ever rendered as a link. Everything else — `javascript:`,
 * `data:`, `blob:`, `file:`, and whatever is registered next — stays prose.
 *
 * This is the one rule here that is load-bearing, and it is a whitelist because a blacklist of
 * dangerous schemes is a list somebody has to keep complete. `javascript:` is the famous one;
 * `data:text/html` is the same hole with a different spelling, and `blob:` would be a document on
 * *this* origin, which is the origin holding the MLS state and the identity key.
 *
 * # Deceptive is not the same as dangerous, and gets a different answer
 *
 * A `https://` URL can be perfectly valid and still be read as somewhere it is not. Three ways,
 * in descending order of how strong the evidence is:
 *
 *   - **userinfo** — `https://paypal.com@evil.tld/x` is read left to right by a human and right
 *     to left by a browser. It is the single most effective spelling there is, and detecting it
 *     is a string comparison.
 *   - **punycode** — a hostname carrying non-ASCII is normalised by `URL` into `xn--…`, so this
 *     costs nothing to detect and the canonical name is there to display.
 *   - **mixed script** — one label mixing Latin with Cyrillic or Greek, which is how `аpple.com`
 *     is written with a Cyrillic `а`. This is the single-script level of UTS #39, in ten lines,
 *     using Unicode property escapes the platform has had since ES2018.
 *
 * A deceptive URL is **not rendered as a link at all**. Not a warning beside a working link — a
 * warning next to a control that still does the dangerous thing is a warning that gets clicked
 * through. Refusing the click costs a copy-paste and is the strongest answer available here.
 *
 * # What none of this solves
 *
 * A link to a domain that is genuinely the attacker's, spelled honestly, reads as exactly what it
 * is and passes every check above. Nothing in a client can help there.
 *
 * And clicking any link at all tells its host that you read this message, and from which address.
 * In an application where everything else is end-to-end encrypted, that is the cheapest side
 * channel on offer. `rel="noreferrer"` removes the referrer; nothing removes the IP.
 */

/** Why a URL should not be offered as a link, or `null` when there is no reason. */
export type Deception = "userinfo" | "punycode" | "mixed-script";

/** A stretch of message text that is a URL. */
export interface Link {
  /** The text exactly as written, which is also what is displayed. */
  readonly raw: string;
  /** Where it goes. Only ever `http:` or `https:`. */
  readonly href: string;
  /** The normalised host — punycode, never the Unicode form. See `hostOf`. */
  readonly host: string;
  /** `null` when the URL may be clicked. */
  readonly deception: Deception | null;
}

/**
 * The scanner.
 *
 * `https?://` with an explicit scheme, or a bare `www.` which is promoted. Deliberately **not**
 * bare domains: `foo.js`, `v1.2`, `Corp.Ltd` and `e.g` are all text somebody wrote, and turning
 * them into links would be wrong far more often than right.
 *
 * The run stops at whitespace and at the bidirectional overrides. The overrides are the ones that
 * matter: they are what would let a hostname print in an order it does not have, and they are not
 * whitespace, so nothing else here would exclude them.
 *
 * The C0 controls are deliberately *not* listed. `no-control-regex` objects to writing them, and
 * it is right to — the ones that are not already whitespace reach `new URL`, which percent-encodes
 * them. A link to `https://example.com/%00` is broken, and a broken link is not a threat.
 */
const SCAN = /(?:https?:\/\/|www\.)[^\s\u202a-\u202e\u2066-\u2069]+/giu;

/** Trailing characters that end a sentence rather than a URL. */
const TRAILING = /[.,;:!?'"]+$/;

/**
 * Trims what belongs to the sentence rather than to the URL.
 *
 * Two passes, and the order matters. Punctuation first — `see https://x.com/a.` ends a sentence.
 * Then unbalanced closers: `(https://x.com/a)` is a URL in parentheses, while
 * `https://en.wikipedia.org/wiki/A_(b)` is a URL *containing* them, and counting is what tells
 * the two apart. Both are common enough that getting either wrong is noticed immediately.
 */
export function trimTrailing(raw: string): string {
  let out = raw.replace(TRAILING, "");

  for (const [open, close] of [
    ["(", ")"],
    ["[", "]"],
    ["{", "}"],
  ] as const) {
    while (out.endsWith(close)) {
      const opens = out.split(open).length - 1;
      const closes = out.split(close).length - 1;
      if (closes <= opens) break;
      out = out.slice(0, -1);
    }
  }

  // A second punctuation pass: trimming `)` can expose the full stop that was in front of it.
  return out.replace(TRAILING, "");
}

/** Scripts that are never mixed with Latin in an honest hostname. */
const CONFUSABLE = [/\p{Script=Cyrillic}/u, /\p{Script=Greek}/u];
const LATIN = /\p{Script=Latin}/u;

/**
 * Whether any single label mixes Latin with a script that imitates it.
 *
 * Per label and not per hostname: `москва.рф` is entirely Cyrillic and entirely honest, and a
 * whole-hostname test would flag it while missing `аpple.com`, where one label is mixed and the
 * TLD is Latin. The mixing inside one word is the signal.
 *
 * Run on the text as written, before `URL` normalises it away into punycode.
 */
export function mixesScripts(host: string): boolean {
  return host
    .split(".")
    .some((label) => LATIN.test(label) && CONFUSABLE.some((script) => script.test(label)));
}

/**
 * The hostname to show a reader: the normalised, punycode form.
 *
 * `URL` does the conversion; the work is in *not* undoing it. A homograph is only a homograph
 * while it is displayed as Unicode — `xn--80ak6aa92e.com` deceives nobody.
 */
export function hostOf(url: URL): string {
  return url.hostname;
}

/**
 * Reads one candidate. Returns `null` for anything that is not an `http(s)` URL at all.
 *
 * Note what is checked on the *written* form and what on the parsed one. Mixed script has to be
 * asked before parsing, because parsing is what destroys the evidence. Userinfo and punycode are
 * asked after, because parsing is what makes them unambiguous.
 */
export function classify(raw: string): Link | null {
  const candidate = /^www\./i.test(raw) ? `https://${raw}` : raw;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return null;
  }

  // The whitelist. Everything not named here stays prose, whatever it is.
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  // A hostname is not optional for a link somebody is meant to trust.
  if (url.hostname === "") return null;

  // The authority as the sender typed it, before `URL` folded it to punycode.
  const written = candidate.replace(/^https?:\/\//i, "").split(/[/?#]/, 1)[0] ?? "";

  const deception: Deception | null =
    url.username !== "" || url.password !== ""
      ? "userinfo"
      : mixesScripts(written.split("@").pop() ?? "")
        ? "mixed-script"
        : url.hostname.split(".").some((label) => label.startsWith("xn--"))
          ? "punycode"
          : null;

  return { raw, href: url.href, host: hostOf(url), deception };
}

/** Where a URL sits in a string, and what it is. */
export interface Found extends Link {
  readonly from: number;
  readonly to: number;
}

/**
 * Every URL in a stretch of text, in order.
 *
 * Candidates that do not survive `classify` — an unparseable host, a scheme not on the whitelist
 * — are dropped rather than reported, because to the reader they are simply prose.
 */
export function scan(text: string): Found[] {
  const out: Found[] = [];

  SCAN.lastIndex = 0;
  for (let match = SCAN.exec(text); match !== null; match = SCAN.exec(text)) {
    const raw = trimTrailing(match[0]);
    if (raw === "") continue;

    const link = classify(raw);
    if (link === null) continue;

    out.push({ ...link, from: match.index, to: match.index + raw.length });
  }

  return out;
}
