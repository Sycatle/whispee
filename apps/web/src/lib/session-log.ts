/**
 * What this device has accepted about the key log, and what it refuses to forget.
 *
 * # Why the head is remembered at all
 *
 * Because without a memory, a server can rewrite an already published key and serve a log that is
 * internally consistent about the lie. The head is an **anchor**: every later log it serves must
 * be proved to extend this one. That is the whole mechanism, and it only works for as long as the
 * anchor survives a reload — which is why this slice, alone among the ones extracted here, exists
 * mostly to be written down correctly.
 *
 * # The two rules that are easy to get backwards
 *
 * **A head is remembered only on success.** Endorsing a head we have just refused would amount to
 * validating what we reject, and the next check would then measure the new log against the
 * attacker's anchor rather than the last honest one.
 *
 * **A refusal is not a deferral.** A proof that does not verify is not a network error to retry:
 * it is exactly the signal this whole apparatus exists to produce, and it has to reach the caller.
 * Swallowing it is what let a conversation open on a key the server had just failed to prove. An
 * unreachable log, by contrast, invents no alert and remembers nothing, so the check is redone.
 *
 * Those two are one `if` apart in the same `catch`, and both are silent when wrong.
 *
 * # Why the checks arrive as a port
 *
 * The same reason as `session-lock.ts`: what is worth testing here is the state machine — when the
 * head moves, when an alert is raised, which failures propagate — and none of it needs a real
 * Merkle proof. `transparency.ts` holds the cryptography and has its own tests.
 *
 * # What it does not solve
 *
 * The log is signed by the party it watches, and its public key is served by that same party.
 * Gossip catches a forked log partially — only between people who actually talk — and does not
 * remove the defect. `VITE_LOG_PUBKEY` pins the key at build time and closes the hole only in the
 * packaged desktop binary; on the web, the server delivering the bundle delivers the pin.
 */
import { fromBase64, toBase64 } from "./keys.ts";
import type { GossipHead } from "./content";
import { LogProofRefused } from "./session-types.ts";
import type { StoredSession } from "./storage";
import type { SeenHead, Verdict } from "./transparency";

/**
 * The proofs this needs asked for, and nothing else.
 *
 * A port rather than `Api` and `Crypto`, so a test can state a verdict instead of building a
 * Merkle tree, and so the pinned key stays where it is configured.
 */
export interface LogChecks {
  /** Proves an account's key is in the log, measured against the head last accepted. */
  account(
    account: string,
    identityKey: Uint8Array,
    seen: SeenHead | undefined,
  ): Promise<{ verdict: Verdict; head?: SeenHead }>;
  /** Proves the log we are served extends the view a peer reports seeing. */
  extendsView(peer: GossipHead): Promise<Verdict>;
}

/** What a peer's view of the log disagreeing with ours means, in the words the user reads. */
const FORKED =
  "Someone you are talking to sees a different key log than you do. " +
  "The server is presenting two versions of it: that is an attack, not a glitch.";

export class LogWitness {
  /**
   * Last accepted head.
   *
   * Acts as an anchor: the server must prove its log extends it. With no memory, it could rewrite
   * an already published key and serve an equally consistent log.
   */
  private seen: SeenHead | undefined;

  /**
   * Log anomalies seen since startup.
   *
   * Kept and displayed rather than discarded: a proof that does not verify is not a network error
   * to retry, it is exactly the signal this whole apparatus exists to produce.
   *
   * Not persisted, and deliberately. An alert describes what this session was served; carrying it
   * across a restart would keep accusing a server that may since have been the honest one, and
   * the check that produced it is redone anyway.
   */
  readonly alerts: string[] = [];

  /**
   * Rebuilds the anchor a stored session was carrying.
   *
   * Base64 on disk and bytes in memory, because `IndexedDbStore` writes through `structuredClone`
   * on one platform and `JSON.stringify` on the other, and a `Uint8Array` handed to the second
   * comes back as an object keyed by strings.
   */
  static hydrate(stored: StoredSession | undefined): LogWitness {
    const witness = new LogWitness();
    if (!stored?.logHead) return witness;

    witness.seen = {
      size: stored.logHead.size,
      root: fromBase64(stored.logHead.root),
      logKey: fromBase64(stored.logHead.logKey),
    };

    return witness;
  }

  /** What this contributes to the stored session. The mirror of `hydrate`. */
  snapshot(): Pick<StoredSession, "logHead"> {
    if (!this.seen) return {};

    return {
      logHead: {
        size: this.seen.size,
        root: toBase64(this.seen.root),
        logKey: toBase64(this.seen.logKey),
      },
    };
  }

  /** The head last accepted, for whoever needs to prove something against it. */
  get head(): SeenHead | undefined {
    return this.seen;
  }

  /**
   * What to tell a peer we see, or nothing if we have accepted no head yet.
   *
   * The log key is left out: the peer has its own, and sending ours would offer it a value to
   * agree with rather than a claim to check.
   */
  gossip(): GossipHead | undefined {
    return this.seen && { size: this.seen.size, root: this.seen.root };
  }

  /**
   * Checks an account's key against the log, and reports whether the anchor moved.
   *
   * Returns `true` when the head actually advanced, so the caller can write it down then and not
   * on every resolve: persisting re-seals the whole MLS state, which is far too much work to
   * repeat for a head already on disk. A log only grows when an account is created or a key
   * rotated, so the write is rare — and it is the write that makes the anchor mean anything after
   * a reload.
   *
   * Throws `LogProofRefused` when the server fails to prove what it claims — the type that already
   * exists for it, rather than a second one: `session.ts` catches it by identity in more than one
   * place, and two names for one condition is how one of those stops matching. The reason is
   * recorded before the throw, so the alert survives a caller that catches.
   */
  async check(checks: LogChecks, account: string, identityKey: Uint8Array): Promise<boolean> {
    try {
      const { verdict, head } = await checks.account(account, identityKey, this.seen);

      if (!verdict.ok) {
        this.raise(verdict.reason);
        throw new LogProofRefused(account, verdict.reason);
      }

      // Remembered only on success: endorsing a head we just rejected would validate what we
      // reject, and measure the next log against the attacker's anchor.
      const advanced = head !== undefined && this.seen?.size !== head.size;
      this.seen = head;
      return advanced;
    } catch (error) {
      // A refusal is not a deferral. It has already been recorded and it must reach the caller:
      // swallowing it here is what let a conversation open on a key the server had just failed to
      // prove.
      if (error instanceof LogProofRefused) throw error;

      // Log unreachable: no security alert is invented for a network failure. Nothing is
      // remembered either, so the check is redone.
      console.warn("log verification deferred", error);
      return false;
    }
  }

  /**
   * Confronts a peer's view of the log with ours.
   *
   * The roots are not compared directly — two logs of different sizes differ normally. We ask the
   * server to **prove** that the log it serves us extends the one it served the other side. If it
   * served two distinct logs it cannot: no consistency proof links two trees that have forked.
   * This is the only check that catches that case.
   *
   * Failures are swallowed rather than raised. An unreachable server is not evidence of a fork,
   * and the comparison happens again at the next gossip.
   */
  async compare(checks: LogChecks, peer: GossipHead): Promise<void> {
    try {
      const verdict = await checks.extendsView(peer);
      if (!verdict.ok) this.raise(FORKED);
    } catch (error) {
      console.warn("log comparison deferred", error);
    }
  }

  /** Records an anomaly, without duplicates. The same server failing twice is one thing to say. */
  private raise(reason: string): void {
    if (!this.alerts.includes(reason)) this.alerts.push(reason);
  }
}
