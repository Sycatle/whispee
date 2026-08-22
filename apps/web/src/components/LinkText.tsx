import { classify } from "@/lib/link";
import { isTauri } from "@/lib/platform";
import { Tooltip } from "@/ui/Tooltip";

/**
 * A URL inside a message.
 *
 * # A deceptive link is not offered as a link at all
 *
 * `lib/link.ts` decides; this draws the decision. When it reports a deception — credentials in
 * the authority, a punycode label, one label mixing Latin with a lookalike script — the text stays
 * text and there is nothing to click.
 *
 * A warning beside a working link is a warning that gets clicked through. It is the shape every
 * browser tried and abandoned, and it fails for a reason that has nothing to do with wording:
 * the person deciding whether to trust the link is the person least equipped to evaluate the
 * warning, and the control is right there. Refusing the click costs a copy-paste and is the
 * strongest answer available from inside a message.
 *
 * # What clicking one costs, and it is not nothing
 *
 * Opening a link tells its host that this message was read, when, and from which address. In an
 * application where everything else is end-to-end encrypted, that is the cheapest side channel
 * available to whoever sent it — a unique URL per recipient turns a link into a read receipt that
 * no setting governs.
 *
 * `rel="noreferrer"` removes the referrer. Nothing removes the address. This is written here
 * rather than shown to the reader, because a caveat on every link is a caveat nobody reads.
 *
 * # Under Tauri, a plain `target="_blank"` does nothing at all
 *
 * `apps/desktop/capabilities/default.json` grants `core:default` and no opener, so the webview's
 * request for a new window is refused: the link does not open and reports nothing. Rather than
 * ship a control that silently fails on one target, the desktop build renders the URL as text —
 * the same treatment a deceptive link gets, for a different reason.
 *
 * Wiring the opener plugin is the fix and it is a decision of its own: it widens what the page's
 * JavaScript can reach, on a shell whose configuration says in as many words that keeping that
 * surface small is the point of the application.
 */
export function LinkText({ raw }: { raw: string }) {
  const link = classify(raw);

  // Not a URL this code will vouch for. `classify` already refused every scheme but http and
  // https, so this covers the unparseable as well.
  if (link === null) return <>{raw}</>;

  if (link.deception !== null) {
    return (
      <Tooltip label={reasonFor(link.deception, link.host)}>
        {/* Dotted rather than solid, and warn rather than accent: it has to look like something
            other than a link, or refusing the click only makes the link seem broken. */}
        <span className="underline decoration-dotted underline-offset-2 text-(--color-warn)">
          {raw}
        </span>
      </Tooltip>
    );
  }

  if (isTauri()) {
    return <span className="underline decoration-dotted underline-offset-2">{raw}</span>;
  }

  return (
    <a
      href={link.href}
      target="_blank"
      // `noopener` first: without it the opened page gets a handle on this one through
      // `window.opener` and can navigate it somewhere else. `nofollow ugc` says what this link is
      // — content somebody sent — to anything that reads the markup.
      rel="noopener noreferrer nofollow ugc"
      className="text-(--color-accent) underline underline-offset-2"
    >
      {raw}
    </a>
  );
}

/**
 * Why a link is not offered.
 *
 * Each names the host as the browser resolved it, because that is the fact the spelling was
 * hiding — and in the punycode case it is the whole of the answer.
 */
function reasonFor(deception: NonNullable<ReturnType<typeof classify>>["deception"], host: string) {
  switch (deception) {
    case "userinfo":
      return `This link goes to ${host}, not to what it appears to say before the @.`;
    case "punycode":
      return `This link goes to ${host}. Its name is written in characters that display differently.`;
    case "mixed-script":
      return `This link goes to ${host}. Its name mixes alphabets, which is how a familiar name is imitated.`;
    default:
      return `This link goes to ${host}.`;
  }
}
