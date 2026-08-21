/**
 * What a conversation view says about itself.
 *
 * # Why these left `Session`
 *
 * None of them reads a mutable field of the session, and none of them writes anything. They were
 * instance methods only because the two or three values they need — who we are, whether read
 * receipts are on — happen to live on the class. Passing those in costs one argument and buys the
 * thing `Session` cannot have: a test.
 *
 * This is the same trade `thread.ts` already made, and for the same reason. A rule computed inside
 * a class that needs WASM and IndexedDB to exist can only be checked by running the application;
 * here it is an argument in, a value out, and `node --test` can ask it anything.
 *
 * # What it does not solve
 *
 * Nothing here was ever the hard part. The decisions that are genuinely coupled — when to persist,
 * which cursor advances on what, publishing before applying — stay in `session.ts` and stay
 * untested. Extracting the easy half does not make the other half easier; it stops the two being
 * mistaken for each other.
 */
import type { ResolvedAccount } from "./account";
import { statusOf } from "./receipts.ts";
import type { ConversationView, Roles, VerificationState } from "./session-types";

/**
 * Separates handles when a membership set is flattened for comparison.
 *
 * A byte no handle can contain — `handle.ts` allows `[a-z0-9_]` only — so that two different sets
 * cannot flatten to the same string. Named rather than inlined because it is the one thing making
 * the comparison sound, and an inlined escape is easy to "tidy" into a comma.
 */
const MEMBER_SEPARATOR = "\u0000";

/**
 * Verification state of a peer.
 *
 * Without an out-of-band comparison, a malicious server can serve each side a KeyPackage it
 * controls and relay in the clear between two perfectly encrypted sessions. No cryptographic check
 * catches it — this is the real weak link of every E2EE deployment, and the reason this state is
 * always on screen rather than tucked into a menu.
 *
 * Takes the whole record of what has been verified rather than a single fingerprint, so that
 * "never verified" and "verified, and it has changed" are told apart here rather than by every
 * caller.
 */
export function verificationOf(
  verified: Record<string, string>,
  account: ResolvedAccount,
): VerificationState {
  const known = verified[account.handle];
  if (!known) return { status: "unverified" };
  if (known === account.fingerprint) return { status: "verified" };
  return { status: "changed", previous: known };
}

/**
 * Looks for a conversation whose participants are exactly the ones asked for.
 *
 * Membership is read from the **MLS tree** (`view.peers`), not from a local field: the tree is the
 * authenticated state, and it decides who is a member. A local record would diverge at the first
 * missed removal.
 *
 * We compare sets, not lists: typing order must not produce two different groups. An account with
 * several devices appears several times in the tree, hence the `Set`.
 */
export function matchingConversation(
  views: Iterable<ConversationView>,
  handles: string[],
  self: string,
): ConversationView | undefined {
  const target = [...new Set(handles)].sort().join(MEMBER_SEPARATOR);

  for (const view of views) {
    const members = [...new Set(view.peers.map((peer) => peer.name))]
      .filter((name) => name !== self)
      .sort()
      .join(MEMBER_SEPARATOR);

    if (members === target) return view;
  }

  return undefined;
}

/**
 * Picks the successor of a departing admin.
 *
 * # The constraint that dictates the rule
 *
 * Succession must be computable **identically by every client**. Two clients picking different
 * successors would not raise an error: they would install two incompatible rosters and the group
 * would silently fork.
 *
 * Hence the MLS tree order, the only chronology everyone shares without exchanging anything. It is
 * also why this is a pure function and must stay one: anything it read from a session would be
 * something one client could hold and another could not.
 *
 * # The approximation, and why it is accepted
 *
 * MLS **reuses freed leaves**: a late arrival can inherit a departed member's slot and end up
 * first. Tree order therefore approximates seniority without reproducing it. Real seniority would
 * require tracking arrival order in the roster and updating it on every addition — one more commit
 * per join. The choice here favours determinism, which is what guards against forks.
 */
export function successorOf(view: ConversationView, roles: Roles, self: string): string | null {
  const members = view.peers.map((peer) => peer.name).filter((name) => name !== self);

  // The rank immediately below: a moderator, if one is left in the group.
  const moderator = members.find((name) => roles.moderators.includes(name));
  if (moderator !== undefined) return moderator;

  // Failing that, the oldest member in tree order.
  return members[0] ?? null;
}

/**
 * How many messages have arrived in this conversation since the user last looked.
 *
 * Counted from the thread rather than from the difference between two cursors, because the cursors
 * advance on **envelopes** and a run of receipts would otherwise read as unread messages. Our own
 * are excluded: nobody is behind on what they wrote themselves.
 */
export function unreadIn(view: ConversationView): number {
  return view.messages.filter((message) => !message.mine && message.seq > view.readCursor).length;
}

/**
 * When this conversation last had something in it, for ordering the list.
 *
 * The declared stamp when there is one, and `0` otherwise — an older thread with no stamps sinks
 * rather than floating to the top on a value invented for it. A queued message counts: the
 * conversation you just wrote in is the one you are in.
 */
export function lastActivityIn(view: ConversationView): number {
  const written = view.outbox.reduce((latest, entry) => Math.max(latest, entry.sentAt), 0);
  const received = view.messages.reduce(
    (latest, message) => Math.max(latest, message.sentAt ?? 0),
    0,
  );
  return Math.max(written, received);
}

/**
 * State to show on a message we sent: sent, delivered, read.
 *
 * Named for what it answers rather than `statusOf`, which is what `receipts.ts` calls the function
 * underneath. As a method on `Session` the two names collided and the class shadowed the import —
 * legal, and one rename away from calling itself forever.
 */
export function deliveryStatus(
  view: ConversationView,
  seq: number,
  self: string,
  readReceipts: boolean,
): "sent" | "delivered" | "read" {
  const handles = [...new Set(view.accounts.map((account) => account.handle))].filter(
    (handle) => handle !== self,
  );
  return statusOf(view.receipts, handles, seq, readReceipts);
}
