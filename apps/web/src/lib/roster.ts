/**
 * The people this account knows, derived rather than stored.
 *
 * # Why this is a pure function and not a method on `Session`
 *
 * There is no contact list in this client. The model knows conversations, and a conversation
 * knows the accounts in it; nobody has ever written down "these are my people". The rail's
 * Contacts section needs that set, and the cheapest honest way to obtain it is to compute it
 * from what already exists.
 *
 * It is not added to `session.ts` on purpose. That file is 2 600 lines carrying the MLS ratchet,
 * the outbox and the vault; a display question does not get to touch it, and every method added
 * there is a merge conflict for whoever is editing it in parallel. Here it is forty lines of
 * arithmetic over plain objects, which is exactly what `node --test` can check without a DOM.
 *
 * The other reason is that this file is **meant to be thrown away**. The friend batch introduces
 * a real contact policy and a real list; on that day this module is deleted whole rather than
 * unpicked from a class.
 *
 * # The rule
 *
 * A contact is somebody we have a reason to know about and **no open one-to-one thread with**.
 * Two sources of "reason to know": a handle we have verified out of band, and a handle that
 * appears in any conversation, group threads included. Subtract everyone who already has their
 * own one-to-one conversation, because those are the rows of the Conversations section directly
 * above — listing them twice would make the rail read as if the same person existed twice.
 *
 * # What this does not solve
 *
 * It cannot show somebody we have never exchanged with. A handle typed once and never messaged
 * leaves no trace anywhere in the model, so the Contacts section starts empty on a fresh account
 * and fills up as a side effect of talking to people. That is a real limitation of deriving
 * instead of storing, and it is the limitation the friend batch exists to remove.
 *
 * It also says nothing about whether a contact is reachable, blocked or online. Those are
 * questions for the account, not for this set.
 */

/** The shape of a conversation this module reads. Structural, so a `ConversationView` fits. */
export interface RosterConversation {
  /**
   * The resolved members. Empty until the first poll resolves them, which is why `peers` is
   * consulted as well rather than instead.
   */
  readonly accounts: readonly { readonly handle: string }[];
  /**
   * The MLS tree members, named by account. Available from restore, before any resolution, so a
   * conversation that has not been polled yet still contributes its people.
   */
  readonly peers: readonly { readonly name: string }[];
}

export interface RosterInput {
  readonly conversations: Iterable<RosterConversation>;
  /**
   * Handles verified out of band.
   *
   * Passed in rather than read from the session because the record that holds them is private to
   * `Session`, and because keeping it a parameter is what makes the union above testable. Today
   * the caller can only supply handles it can already see; the friend batch supplies more, and
   * this signature does not change when it does.
   */
  readonly verified: Iterable<string>;
  /** Our own handle, which is never a contact of ours. */
  readonly self: string;
}

/**
 * The handles named by one conversation, deduplicated.
 *
 * `accounts` first and `peers` as the fallback, matching what the rail displays: a conversation
 * shows its resolved accounts and falls back to tree members when there are none yet.
 */
function handlesIn(conversation: RosterConversation): Set<string> {
  const handles = new Set<string>();
  for (const account of conversation.accounts) handles.add(account.handle);
  for (const peer of conversation.peers) handles.add(peer.name);
  return handles;
}

/**
 * The contacts, sorted by handle.
 *
 * Sorted rather than left in discovery order: this list has no activity to rank it by, so any
 * other order would be the order a `Map` happens to hold — stable enough to look intentional and
 * arbitrary enough to move under the cursor when a poll lands.
 */
export function roster(input: RosterInput): string[] {
  const known = new Set<string>();
  const paired = new Set<string>();

  for (const conversation of input.conversations) {
    const handles = handlesIn(conversation);
    for (const handle of handles) known.add(handle);

    // A one-to-one is a conversation with exactly one other person in it. Counted after
    // removing ourselves, because the tree lists us among its members and the resolved accounts
    // do not — without this a two-person group would be counted differently depending on
    // whether it had been polled yet.
    handles.delete(input.self);
    if (handles.size === 1) for (const handle of handles) paired.add(handle);
  }

  for (const handle of input.verified) known.add(handle);

  known.delete(input.self);
  for (const handle of paired) known.delete(handle);

  return [...known].sort((a, b) => a.localeCompare(b));
}
