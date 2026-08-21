/**
 * Presence: from "seen at such a time" to "online".
 *
 * # Why the decision lives here and not on the server
 *
 * The server returns a raw timestamp, never a boolean. A boolean would freeze the policy into the
 * protocol and rule out showing "last seen at 14:02" from the same data — when it is exactly the
 * same data, read with a different threshold.
 *
 * # Why the server's time travels with the response
 *
 * Because we are comparing two clocks. `MAX_CLOCK_SKEW` exists on the server precisely because
 * they drift: comparing a server timestamp to local time would make the dot flicker for every
 * badly set user, with no way for them to understand why.
 */

/**
 * Past this, an account counts as offline.
 *
 * The arithmetic, because this is typically the value someone "optimises" to sixty seconds later
 * and is then surprised the dot flickers:
 *
 *  * the server only rewrites once a minute (`PRESENCE_REFRESH`);
 *  * the client only reads presence on each poll round, so every thirty seconds;
 *  * some margin is needed for a missed heartbeat or a stream reconnection, whose resume delay
 *    goes up to thirty seconds.
 *
 * That is two and a half minutes. Going below does not make presence more accurate, only more
 * nervous.
 */
export const ONLINE_WINDOW_MS = 150_000;

/** An account's last known activity, in milliseconds. */
export type LastSeen = number | undefined;

/**
 * Online?
 *
 * A timestamp in the future counts as "online": it comes from a clock offset, and the only other
 * possible answer — "seen in three minutes" — would be absurd.
 */
export function isOnline(lastSeen: LastSeen, serverNow: number): boolean {
  if (lastSeen === undefined) return false;
  return serverNow - lastSeen < ONLINE_WINDOW_MS;
}

/**
 * What is displayed next to a name.
 *
 * An empty string when we do not know — not "offline". An account we have never heard from is not
 * an absent account: it is an account the server has nothing to say about, because it has never
 * been seen or because its owner declined to broadcast it. Deciding on their behalf would be the
 * screen's first lie.
 */
export function describePresence(lastSeen: LastSeen, serverNow: number): string {
  if (lastSeen === undefined) return "";
  if (isOnline(lastSeen, serverNow)) return "online";

  return `last seen ${agoOf(serverNow - lastSeen)}`;
}

/**
 * How long ago, in words.
 *
 * This used to read "last seen at 14:02", which answers a question nobody asked. What a reader
 * wants to know is whether the person they are writing to is likely to answer, and an absolute
 * time makes them do the subtraction themselves — against a clock they have to find, in a
 * timezone they have to assume. "Twelve minutes ago" is the answer; "at 14:02" is the data the
 * answer is computed from.
 *
 * The steps get coarser as they get older, because precision that nobody can use is noise: the
 * difference between eleven and twelve minutes changes a decision, the difference between eleven
 * and twelve days does not.
 *
 * Elapsed time is measured against the **server** clock, which is why this takes a duration
 * rather than two instants. A device whose own clock is wrong would otherwise report somebody as
 * last seen in the future, or hours ago, purely from its own drift.
 *
 * What this does not solve: it says "yesterday" for anything between one and two days, which is
 * wrong by the calendar for somebody last seen at 23:50 and read at 00:10. Naming the weekday
 * instead would need the reader's timezone and their idea of where a day starts, and the reason
 * to know a peer was last around "yesterday" does not survive that much machinery.
 */
export function agoOf(elapsed: number): string {
  const minutes = Math.floor(elapsed / 60_000);
  if (minutes < 1) return "moments ago";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;

  const days = Math.floor(hours / 24);
  if (days === 1) return "yesterday";
  if (days < 7) return `${days} days ago`;

  const weeks = Math.floor(days / 7);
  if (weeks < 5) return `${weeks} week${weeks === 1 ? "" : "s"} ago`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months === 1 ? "" : "s"} ago`;

  // Past a year the number stops mattering: what it means is "not recently", and anybody who
  // needs the date has the conversation itself to look at.
  return "over a year ago";
}
