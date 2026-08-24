/**
 * The history vault, from the session's side.
 *
 * # Why this left `Session`
 *
 * Because `session.ts` had already written down the reason, in the comment above `hydrate`:
 * restoring touches "neither `contentCursor`, nor `readCursor`, nor `receipts`", and not
 * `view.cursor` either, because that one belongs to the MLS state — the vault says nothing about
 * the ratchet. A comment is how you say that; a boundary is how you make it true.
 *
 * So this file **never sees a `ConversationView`**. It is handed a group id and a list of messages
 * already held, and it hands back the ones to add. There is no cursor within reach, which is a
 * stronger guarantee than a test asserting one was not moved: a test checks the code as written,
 * and this checks every version of it anybody writes next.
 *
 * That matters more than it sounds. Moving the announced cursor on a restore would re-emit a
 * receipt for every archived message on every reload, and each receipt would breed another. It is
 * the one path by which the loop described in the README can come back to life.
 *
 * # What stays behind
 *
 * When to restore — on opening a conversation, never from the periodic poll, which sweeps every
 * conversation every thirty seconds and would make that one round trip per group forever. The
 * once-per-session flag. Pushing the messages into the view and bumping its revision counter. And
 * persisting, which is ordered against the MLS state.
 *
 * # What it does not solve
 *
 * The vault is still the server's unbounded store. `envelopes` is purged; `vault_entries` is
 * deliberately not, and has inherited the role `envelopes` used to play. The bound that would
 * settle it is a per-account stored-bytes quota, which `crates/server/src/throttle.rs` names and
 * does not implement. Nothing on this side of the wire can fix that.
 *
 * Nor does it restore forward secrecy. Archiving under a key derived from the recovery phrase is
 * what lets a new device read the past back, and it is exactly what is given up for it.
 */
import type { Message } from "./session-types";
import type { StoredSession } from "./storage";
import * as vault from "./vault.ts";

/** What this needs from the delivery service. `vault.ts` states the shape; this only names it. */
export type VaultApi = vault.VaultApi;

/**
 * Was this refusal a full account rather than a passing failure?
 *
 * Read off the status rather than off the error's class: importing `api.ts` here would drag the
 * HTTP layer into the session layer, and `node --test` cannot load it at all — its strip-only mode
 * rejects the constructor parameter property `ApiError` is built on. 507 is the contract, stated
 * on both sides of the wire, and it is what this reads.
 */
function refusedForRoom(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "status" in error &&
    (error as { status: unknown }).status === 507
  );
}

export class Archive {
  /**
   * The key the entries are sealed under, or `null` when the vault is off.
   *
   * Derived from the recovery phrase, so stable **across devices and across sessions** — which is
   * what lets a new device read the history back, and exactly what is given up for it.
   *
   * Not stable across a rotation, and the two senses are easy to confuse. `rotateAccount` generates
   * a whole new account: new seed, new phrase, therefore a different vault key. Archived history
   * becomes permanently unreadable, and that is the intended behaviour — a rotation is a total
   * revocation, including of what had been set aside.
   */
  private key: CryptoKey | null = null;

  /**
   * Opens the vault for an account, tolerating failure.
   *
   * Returns an archive that is simply off rather than throwing. This sits on the opening path of
   * **every** session now that the vault is on by default, and an exception here would make
   * messages inaccessible because their backup failed. Archiving is lost; the conversation never
   * is.
   *
   * The key material is taken as a thunk rather than a value so that **deriving** it is inside the
   * same `try` as importing it. The derivation is the half more likely to fail, and a caller who
   * evaluated it one line earlier would have moved it outside the net without noticing.
   */
  static async open(vaultKey: () => Uint8Array): Promise<Archive> {
    const archive = new Archive();

    try {
      archive.key = await vault.importVaultKey(vaultKey());
    } catch (error) {
      console.warn("vault key unavailable: archiving off for this session", error);
    }

    return archive;
  }

  /** An archive for an account that turned the vault off. Not a failure, and not logged as one. */
  static off(): Archive {
    return new Archive();
  }

  /** Is the vault on? */
  get enabled(): boolean {
    return this.key !== null;
  }

  /**
   * Turns the vault back on after an explicit shutdown.
   *
   * Messages **already exchanged** will not be archived: their MLS keys are destroyed, and nothing
   * can reconstruct them. Archiving resumes now, never retroactively — the interface has to say
   * so, or the user will believe they recovered a past that no longer exists.
   *
   * Unlike `open`, a failure here throws: the user asked for this, and telling them it worked when
   * it did not is worse than an error message.
   */
  async enable(vaultKey: Uint8Array): Promise<void> {
    this.key = await vault.importVaultKey(vaultKey);
  }

  /**
   * Turns the vault off. **Does not erase what is already archived**: the server keeps the
   * entries, and the key that opens them is still derivable from the phrase.
   *
   * Saying so rather than implying an erasure. Promising a deletion we do not control — the server
   * may keep copies — would be a security lie.
   */
  disable(): void {
    this.key = null;
  }

  /** What this contributes to the stored session. */
  snapshot(): Pick<StoredSession, "vaultEnabled"> {
    return { vaultEnabled: this.key !== null };
  }

  /**
   * Fetches a conversation's archived history and reports what is not already held.
   *
   * Takes the messages already in hand rather than a view, and returns the ones to add rather than
   * inserting them. That is the whole boundary: nothing here can reach a cursor, so nothing here
   * can move one.
   *
   * Throws when there were entries and none of them could be read. That means the vault key is no
   * longer the right one — the account has been rotated — and saying so beats serving an empty
   * thread that looks like a conversation nobody ever had.
   */
  async restore(api: VaultApi, groupId: Uint8Array, held: Message[]): Promise<Message[]> {
    if (!this.key) return [];

    const { messages, unreadable } = await vault.restore(api, this.key, groupId);

    if (messages.length === 0 && unreadable > 0) {
      throw new Error("The archived history can no longer be read: the recovery phrase changed.");
    }

    return vault.merge(held, messages);
  }

  /**
   * True when the server refused an archive for want of room.
   *
   * The other failures stay swallowed, and rightly: a delivered message whose backup is late is
   * not a problem, and the next send retries it. A ceiling is different in kind — retrying never
   * clears it, and a user who is not told believes their history is being archived while nothing
   * is. That belief is what this flag exists to prevent.
   */
  full = false;

  /**
   * Archives the messages just read or sent, if the vault is on.
   *
   * A failed archive must not block the conversation: the message is already delivered, only the
   * backup is missing, and it will be retried on the next send. Hence the swallowed error — the
   * one place in this file where failing quietly is the right answer, and `full` above is the one
   * refusal that is not.
   */
  async store(api: VaultApi, groupId: Uint8Array, messages: Message[]): Promise<void> {
    if (!this.key || messages.length === 0) return;

    try {
      await vault.store(api, this.key, groupId, messages);
      this.full = false;
    } catch (error) {
      if (refusedForRoom(error)) {
        this.full = true;
        return;
      }
      console.warn("archiving deferred", error);
    }
  }
}
