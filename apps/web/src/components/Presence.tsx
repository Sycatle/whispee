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
import { Typing } from "@/ui/Typing";

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
  typing = false,
  children,
}: {
  session: Session;
  handle: string;
  /**
   * Whether this person is typing right now.
   *
   * Passed in rather than read here, and that is not laziness. Whether an indicator may be shown
   * at all is `session.typingIn(view)`'s decision — it is reciprocal, so somebody who turned
   * their own indicator off does not get to see other people's — and that question needs a
   * conversation, which a badge does not have. A badge that read the typing map directly would
   * quietly show what the setting says to hide.
   */
  typing?: boolean;
  children: ReactNode;
}) {
  // Our own account never appears in the presence map: nothing broadcasts a device's activity
  // back to itself, so `presenceOf` returns `undefined` for us and the badge would be missing on
  // the one face that is certainly here. Somebody looking at their own avatar is, by the fact of
  // looking at it, online.
  const self = handle === session.accountId;
  const lastSeen = session.presenceOf(handle);
  const online = self || isOnline(lastSeen, session.presenceClock);
  const known = self || lastSeen !== undefined;

  return (
    <span className="relative inline-flex">
      {children}
      {/* Typing is drawn even when presence is not.
 
          The two answer different questions, and only one of them can be unknown: presence is
          something the other side chooses to broadcast, while typing is something we were just
          told. Somebody who has turned presence off and is typing has no dot and does say so —
          suppressing the dots because the dot is missing would hide a fact we hold behind the
          absence of one we do not. */}
      {(known || typing) && (
        <>
          <span
            aria-hidden="true"
            className={cn(
              "pointer-events-none absolute -right-0.5 -bottom-0.5 flex items-center justify-center",
              "rounded-pill ring-2 ring-(--color-surface)",
              // One box in two shapes rather than two elements swapped: the width is what
              // changes, so the badge grows out of the dot and settles back into it instead of
              // one thing vanishing as another appears at the same corner.
              "transition-[width,background-color] duration-(--duration-quick) ease-out",
              "motion-reduce:transition-none",
              typing
                ? "h-2.5 w-[1.375rem] bg-(--color-accent) text-(--color-accent-ink)"
                : "size-2.5",
              !typing && (online ? "bg-(--color-ok)" : "bg-(--color-ink-muted)"),
            )}
          >
            {typing && <Typing />}
          </span>
          {/* The word, for whoever cannot see the colour — and the states have to be named, since
              the only thing separating them on screen is a hue or a shape. */}
          <span className="sr-only">{typing ? "typing" : online ? "online" : "offline"}</span>
        </>
      )}
    </span>
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
