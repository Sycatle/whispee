/**
 * Presence display.
 *
 * Kept separate rather than inlined into `page.tsx`: that file already runs past eight hundred
 * lines, and the display rule — a dot when it is fresh, a time otherwise, nothing when we do not
 * know — deserves to be readable in one piece.
 */
import type { Session } from "@/lib/session";
import { describePresence, isOnline } from "@/lib/presence";

/**
 * "Online" dot, no text.
 *
 * Nothing at all when the account is not fresh: a grey dot would ask the eye to tell two shades
 * apart in a list, in order to say "offline" when we do not always know that. No dot is both
 * more honest and more readable.
 */
export function PresenceDot({ session, handle }: { session: Session; handle: string }) {
  if (!isOnline(session.presenceOf(handle), session.presenceClock)) return null;

  return (
    <span
      className="inline-block size-2 shrink-0 rounded-full bg-(--color-ok)"
      title="online"
      aria-label="online"
    />
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

  return <span className="text-xs text-(--color-ink-muted)">{text}</span>;
}
