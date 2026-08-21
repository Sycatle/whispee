/**
 * Presence display.
 *
 * Kept separate rather than inlined into `page.tsx`: that file already runs past eight hundred
 * lines, and the display rule — a dot when it is fresh, a time otherwise, nothing when we do not
 * know — deserves to be readable in one piece.
 */
import type { ReactNode } from "react";

import type { Session } from "@/lib/session";
import { describePresence, isOnline } from "@/lib/presence";
import { cn } from "@/ui/cn";

/**
 * Presence, as a badge on the corner of the face it belongs to.
 *
 * A separate dot beside an avatar is a second object in the row: it takes its own column, it
 * pushes the name across, and the eye has to work out which of the two things it is about. On the
 * corner it is unambiguous by construction — it is *on* the face it describes — and it costs no
 * layout at all, being absolutely positioned over a wrapper that takes the child's own size.
 *
 * # Three states, because there are three, and the grey one is the interesting one
 *
 * This used to draw nothing at all when somebody was not fresh, on the argument that a grey dot
 * says "offline" when we do not always know that. The argument was right about one case and
 * wrong about the other, because `lib/presence.ts` distinguishes them: `lastSeen === undefined`
 * is *nobody has ever told us*, while a `lastSeen` that has simply gone stale is *we know when
 * they were last here, and it was a while ago*. The first cannot honestly be drawn. The second
 * can, and refusing to draw it made "offline" and "never heard of" look identical — which is its
 * own lie, and the one people actually noticed.
 *
 * So: green when fresh, grey when known-and-stale, and nothing when there is nothing to report.
 *
 * The ring around the badge is the surface colour, not a border: it separates the dot from
 * whatever it sits on without adding a line, and it keeps a green dot from touching a green pixel
 * of the identicon underneath.
 *
 * What this does not solve: the wrapper takes the size of `children`, so the badge lands on the
 * corner of whatever is passed. Hand it the avatar, not a column that also carries a caption, or
 * the badge will sit on the corner of the caption instead.
 */
export function PresenceBadge({
  session,
  handle,
  children,
}: {
  session: Session;
  handle: string;
  children: ReactNode;
}) {
  // Our own account never appears in the presence map: nothing broadcasts a device's activity
  // back to itself, so `presenceOf` returns `undefined` for us and the badge would be missing on
  // the one face that is certainly here. Somebody looking at their own avatar is, by the fact of
  // looking at it, online.
  const self = handle === session.handle;
  const lastSeen = session.presenceOf(handle);
  const online = self || isOnline(lastSeen, session.presenceClock);
  const known = self || lastSeen !== undefined;

  return (
    <span className="relative inline-flex">
      {children}
      {known && (
        <>
          <span
            aria-hidden="true"
            className={cn(
              "pointer-events-none absolute -right-0.5 -bottom-0.5 size-2.5 rounded-pill",
              "ring-2 ring-(--color-surface)",
              online ? "bg-(--color-ok)" : "bg-(--color-ink-muted)",
            )}
          />
          {/* The word, for whoever cannot see the colour — and the two states have to be named,
              since the only thing separating them on screen is a hue. */}
          <span className="sr-only">{online ? "online" : "offline"}</span>
        </>
      )}
    </span>
  );
}

/**
 * "Online" dot, no text.
 *
 * Kept for the rows that have no avatar to put a ring on — a bare list entry, a member line.
 * `PresenceRing` is the form to reach for wherever there is a face.
 *
 * Nothing at all when the account is not fresh: a grey dot would ask the eye to tell two shades
 * apart in a list, in order to say "offline" when we do not always know that. No dot is both
 * more honest and more readable.
 */
export function PresenceDot({ session, handle }: { session: Session; handle: string }) {
  if (!isOnline(session.presenceOf(handle), session.presenceClock)) return null;

  // A name on a bare `<span>` names an element whose role is `generic`, which ARIA forbids
  // naming and most screen readers drop on the floor: the dot was silent. `PresenceRing` above
  // already had the right shape — the mark is decoration, the word is text.
  return (
    <>
      <span
        aria-hidden="true"
        className="inline-block size-2 shrink-0 rounded-pill bg-(--color-ok)"
        title="online"
      />
      <span className="sr-only">online</span>
    </>
  );
}

/**
 * The "online" / "last seen at 14:02" line.
 *
 * Renders nothing when the server has nothing to say — an account never seen, or one that
 * declined to broadcast its presence. "Offline" would be a claim, and we cannot back it.
 */
export function PresenceLine({ session, handle }: { session: Session; handle: string }) {
  const text = describePresence(session.presenceOf(handle), session.presenceClock);
  if (!text) return null;

  return <span className="text-caption text-(--color-ink-muted)">{text}</span>;
}
