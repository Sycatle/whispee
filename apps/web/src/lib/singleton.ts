/**
 * One tab per account, and why that is a correctness rule rather than a nicety.
 *
 * # What two tabs do to each other
 *
 * A session holds the MLS ratchet **in memory** and writes it to IndexedDB after every poll. Two
 * tabs of the same account therefore hold two copies of a state that is not allowed to have two
 * copies: each advances its own ratchet as it reads envelopes, and each persists over the other.
 *
 * The damage is not a lost render. Decrypting an application message **consumes** the key for its
 * generation — that is what forward secrecy means — so once the surviving state has moved past an
 * envelope the other tab read, that envelope can never be read again. OpenMLS answers "the
 * requested secret was deleted to preserve forward secrecy", the client logs a skip, and the
 * message is gone. `crypto-core`'s own test says it in one line: *a client that re-reads its
 * envelopes after losing its cursor loses the message.*
 *
 * So a second tab does not degrade the experience, it destroys mail. Silently, and for good.
 *
 * # Why the Web Locks API and not an election
 *
 * A lock held for the lifetime of the tab is released by the browser when the tab dies — crash,
 * kill, close, navigate away — with nothing to clean up. Every other mechanism available here
 * (a claim row with a heartbeat, a `BroadcastChannel` election) has to answer "what if the holder
 * vanished", and answers it with a timeout that is either too short to be safe or too long to be
 * usable.
 *
 * # It fails open, deliberately
 *
 * A browser with no `navigator.locks`, or a lock manager that throws, yields *no guard* rather
 * than a locked-out application. The thing being prevented is a mistake somebody makes rarely;
 * refusing to start a messenger because a lock could not be taken would be a worse failure than
 * the one being defended against, and it would be triggered by the environment rather than by the
 * user.
 */

/**
 * The name the session is claimed under.
 *
 * One name for the whole origin, not one per account: a browser profile holds one identity here,
 * and the state two tabs would fight over is the one in this origin's IndexedDB whatever account
 * happens to be signed in.
 */
export const SESSION_LOCK = "whispee.session";

/** The slice of `LockManager` this needs. Structural, so a test can hand it a fake. */
export interface Locks {
  request(
    name: string,
    options: { mode?: "exclusive" | "shared"; ifAvailable?: boolean },
    callback: (lock: unknown) => Promise<void> | void,
  ): Promise<unknown>;
}

/** A claim on the session: whether we hold it, and how to give it back. */
export interface Claim {
  /** True when this tab may run a session. False means another tab already is. */
  readonly held: boolean;
  /** Releases the lock. Idempotent — the browser releases it on unload regardless. */
  release(): void;
}

/**
 * Claims the right to run a session in this tab.
 *
 * `ifAvailable` and never a wait: a tab that queued would sit on a blank screen for as long as the
 * other one lives, which reads as a hang. Answering "another tab has it" immediately is the only
 * answer a person can act on.
 */
export async function claim(name: string, locks: Locks | undefined = navigator.locks): Promise<Claim> {
  if (!locks) return open();

  let release = () => {};

  try {
    const held = await new Promise<boolean>((resolve, reject) => {
      void locks
        .request(name, { mode: "exclusive", ifAvailable: true }, (lock) => {
          if (!lock) {
            resolve(false);
            return;
          }

          // The callback's promise is what holds the lock: it stays taken until `release` settles
          // it. Returning immediately would drop the lock the instant it was granted.
          return new Promise<void>((done) => {
            release = done;
            resolve(true);
          });
        })
        .catch(reject);
    });

    return { held, release: () => release() };
  } catch {
    return open();
  }
}

/** No guard. See the note on failing open at the top of this file. */
function open(): Claim {
  return { held: true, release: () => {} };
}
