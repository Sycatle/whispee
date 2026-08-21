/**
 * What this device has checked about other people, and what it has seen of them.
 *
 * # Why this is the slice that matters most
 *
 * Same shape as `session-naming.ts` and `session-preferences.ts` — the mapping to disk and the
 * mapping back, together, so a test can assert they agree. What makes this one different is the
 * cost of getting it wrong.
 *
 * `verified` is a `Record<account, fingerprint>`. Read under a key it was not written under, it
 * does not fail: it comes back empty, and every account the user compared out of band goes back to
 * unverified. Worse, an account whose fingerprint is *remembered wrongly* reports `changed` — the
 * red banner that exists to announce that a server substituted somebody's key, raised by our own
 * bookkeeping, on a correspondent who did nothing.
 *
 * That is not a cosmetic failure. The banner is the output of the whole verification apparatus,
 * and it works only for as long as people believe it. Teaching them to click through it once is a
 * lesson that does not come undone.
 *
 * # Why the fingerprint is kept, and not a boolean
 *
 * Because keeping the value is what makes a **change** detectable. The fingerprint covers the
 * account key, not a device key: it does not move when a correspondent adds a phone. If it moves
 * anyway, it is either a recovery from the phrase or a substitution by the server. One is rare,
 * the other is the attack, and only the user can tell them apart — but they have to be told first,
 * and they can only be told if the old value is still there to show them.
 *
 * # What it does not solve
 *
 * The identity these records are keyed by, and what becomes of a state written under the old one.
 * This makes the rekey a substitution in one file and makes the round trip assertable; it does not
 * decide whether an unreadable state is converted or discarded. Note that the only version gate in
 * the client is `session-codec.ts`, and it guards the **native** file — `IndexedDbStore.load`
 * reads whatever is in the database and hands it over.
 */
import type { ResolvedAccount } from "./account";
import type { VerificationState } from "./session-types";
import type { StoredSession } from "./storage";

export class TrustStore {
  /**
   * Account fingerprints already compared out of band, by account.
   *
   * The value, not a flag. See the note above: a boolean cannot tell "never checked" from
   * "checked, and it is not what it was".
   */
  private fingerprints: Record<string, string> = {};

  /**
   * Devices known for each correspondent.
   *
   * Used to spot an addition. A device appearing on a peer is an event worth reporting, and it is
   * that notification — not the fingerprint, deliberately stable — that reveals a hostile device
   * legitimately attested by a compromised account.
   */
  private devices: Record<string, string[]> = {};

  /**
   * Rebuilds what a stored session had checked.
   *
   * Both fields are required in `StoredSession`, so there is no absent-versus-`undefined` question
   * here as there is for the names: `?? {}` covers a session written before the field existed, and
   * an empty record means "nothing checked yet", which is the honest reading of both.
   */
  static hydrate(stored: StoredSession | undefined): TrustStore {
    const trust = new TrustStore();
    if (!stored) return trust;

    trust.fingerprints = stored.verified ?? {};
    trust.devices = stored.knownDevices ?? {};

    return trust;
  }

  /** What this contributes to the stored session. The mirror of `hydrate`, and tested against it. */
  snapshot(): Pick<StoredSession, "verified" | "knownDevices"> {
    return { verified: this.fingerprints, knownDevices: this.devices };
  }

  /**
   * Verification state of a peer.
   *
   * Without an out-of-band comparison, a malicious server can serve each side a KeyPackage it
   * controls and relay in the clear between two perfectly encrypted sessions. No cryptographic
   * check catches it — this is the real weak link of every E2EE deployment, and the reason this
   * state is always on screen rather than tucked into a menu.
   */
  verificationOf(account: ResolvedAccount): VerificationState {
    const known = this.fingerprints[account.handle];
    if (!known) return { status: "unverified" };
    if (known === account.fingerprint) return { status: "verified" };
    return { status: "changed", previous: known };
  }

  /** Records that somebody's fingerprint was compared out of band and matched. */
  markVerified(account: ResolvedAccount): void {
    this.fingerprints[account.handle] = account.fingerprint;
  }

  /** Records the devices a peer is known to have, without reporting anything. */
  noteDevices(handle: string, ids: string[]): void {
    this.devices[handle] = ids;
  }

  /**
   * Reports the devices of a peer that were not there last time, and remembers the new list.
   *
   * Returns the fresh ones so the caller can decide whether the change is worth saying out loud.
   * Nothing is recorded when nothing is new, so a caller need not persist for an answer that did
   * not move.
   */
  newDevicesIn(handle: string, ids: string[]): string[] {
    const known = new Set(this.devices[handle] ?? []);
    const fresh = ids.filter((id) => !known.has(id));

    if (fresh.length > 0) this.devices[handle] = ids;

    return fresh;
  }
}
