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

  const date = new Date(lastSeen);
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");

  const sameDay = new Date().toDateString() === date.toDateString();
  return sameDay ? `last seen at ${hours}:${minutes}` : `last seen on ${date.toLocaleDateString()}`;
}
