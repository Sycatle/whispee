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
 * # Under Tauri the link is opened by the system, not by the webview
 *
 * A plain `target="_blank"` does nothing there: the webview asks the shell for a new window and
 * the shell refuses, with no error anybody sees. So the desktop build asks the operating system
 * instead, through `tauri-plugin-opener`.
 *
 * That widens what the page's JavaScript can reach, on a shell whose configuration says in as
 * many words that keeping that surface small is the point of the application — so it is bounded
 * where such things are bounded: `capabilities/default.json` scopes the permission to `http` and
 * `https`. Unscoped, "open a URL" means "open what the system knows how to open", which includes
 * files and executables. Scoped, the worst a hostile message obtains is sending somebody to a web
 * page, which is what a link is.
 *
 * The click is still a click on an `<a>` with a real `href`, with the default prevented. Keeping
 * the anchor is not decoration: it is what puts the destination in the status bar, what makes
 * "copy link" work, and what a screen reader announces as a link.
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

  return (
    <a
      href={link.href}
      target="_blank"
      // `noopener` first: without it the opened page gets a handle on this one through
      // `window.opener` and can navigate it somewhere else. `nofollow ugc` says what this link is
      // — content somebody sent — to anything that reads the markup.
      rel="noopener noreferrer nofollow ugc"
      onClick={(event) => {
        if (!isTauri()) return;

        // The webview would refuse the new window and report nothing, so the system is asked
        // instead. The import is dynamic because this module is in the web bundle too, where the
        // plugin is dead weight — `lib/platform.ts` explains why there is one bundle and not two.
        event.preventDefault();
        void import("@tauri-apps/plugin-opener")
          .then((opener) => opener.openUrl(link.href))
          // Nothing is shown on failure. The link is still selectable and still copyable, and a
          // toast about a browser that would not start is a toast about somebody else's machine.
          .catch(() => {});
      }}
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
