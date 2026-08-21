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

/**
 * "Online" ring, drawn around the avatar it belongs to.
 *
 * A separate dot beside an avatar is a second object in the row: it takes its own column, it
 * pushes the name across, and the eye has to work out which of the two things it is about. A
 * ring is unambiguous by construction — it is *on* the face it describes — and it costs no
 * layout at all, being absolutely positioned over a wrapper that takes the child's own size.
 *
 * Nothing at all when the account is not fresh, and that is the same deliberate position the
 * dot below takes: absence, not a grey ring. See its note.
 *
 * What this does not solve: the ring follows the wrapper's box, so it encircles everything
 * passed as `children`. Hand it the avatar and not a column that also carries a caption or a
 * proof strip, or the ring will loop round the caption too.
 */
export function PresenceRing({
  session,
  handle,
  children,
}: {
  session: Session;
  handle: string;
  children: ReactNode;
}) {
  const online = isOnline(session.presenceOf(handle), session.presenceClock);

  return (
    <span className="relative inline-flex">
      {children}
      {online && (
        <>
          {/* `-inset-0.5` leaves a hairline of surface between the avatar and the ring, so the
              two read as a mark on a face rather than as a coloured border the identicon grew.
              Decorative: the text beside it carries the meaning for a screen reader. */}
          <span
            aria-hidden="true"
            className="pointer-events-none absolute -inset-0.5 rounded-pill border-2 border-(--color-ok)"
          />
          <span className="sr-only">online</span>
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
