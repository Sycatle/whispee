/**
 * The shapes a conversation is made of.
 *
 * # Why these live apart from the class that fills them
 *
 * Two reasons, and neither is tidiness.
 *
 * The first is a cycle. `history.ts` persists a thread, so it needs `Message` and `Pending`; but
 * `session.ts` imports `history.ts` to read that cache back. The import went both ways and only
 * survived because one direction was type-only. A file that holds the shapes and knows nothing
 * about the orchestration breaks the loop rather than tiptoeing around it.
 *
 * The second is arithmetic. `session.ts` is the file every feature has to touch, and several
 * features are being built at once. Whatever can be edited somewhere else should be, or every
 * branch conflicts with every other branch in the same two hundred lines.
 *
 * # What is deliberately not here
 *
 * The class. Splitting `Session` itself was considered and refused: everything in it is an
 * instance method over private fields behind a private constructor, so extracting a second slice
 * would mean widening the visibility of state that has no reason to be visible. Moving the
 * shapes costs nothing and buys both of the above; moving the behaviour would cost the
 * encapsulation and buy line count.
 */
import type { ResolvedAccount } from "./account";
import type * as content from "./content";
import type { ReceiptBook } from "./receipts";
import type { Typing } from "./signals";
import type { Peer } from "./wasm";

export interface Message {
  seq: number;
  sender: string | null;
  mine: boolean;
  /**
   * When the sender says it was written, in milliseconds.
   *
   * **Declared, not proven.** It travels inside the MLS message, so the server never sees it and
   * cannot alter it — but any member of the group can put whatever they like in their own. It is
   * an annotation on the thread, never its order: that stays `seq`, which the server assigns and
   * no member controls.
   *
   * Optional because two real cases have none: control traffic is never stamped, and neither is
   * anything written before stamping existed.
   */
  sentAt?: number;
  /**
   * The decrypted body.
   *
   * It was once true that this never touched disk, and the note here said so. It is not true any
   * more: `history.ts` keeps a window of recent threads sealed under the same key as the MLS
   * state, so that opening the application shows a conversation before the network answers.
   *
   * What that costs is written where the decision was made rather than repeated here, but the
   * short of it: someone holding an **unlocked** device can read the thread, which was already
   * outside the threat model; someone holding a **locked** one no longer finds nothing, they
   * find ciphertext under the master key.
   */
  content: content.Content;
}

export type VerificationState =
  | { status: "unverified" }
  | { status: "verified" }
  /** The fingerprint changed since verification: a reinstall, or a substitution. */
  | { status: "changed"; previous: string };

/**
 * A message written but not yet accepted by the server.
 *
 * # Why these live beside `messages` and not inside it
 *
 * A `Message` is identified by `seq`, which the **server** assigns. Everything downstream depends
 * on that: `view.mine` skips our own envelopes by sequence, receipts acknowledge up to a number,
 * a reply points at one. A message that has not been posted has no such number, and inventing a
 * placeholder would put a fake one into all of it — the kind of value that leaks into a receipt
 * and acknowledges a message nobody sent.
 *
 * So they are kept apart, rendered after the thread, and moved into it under the number the
 * server gives them.
 *
 * # What is deliberately not queued
 *
 * Attachments, reactions and replies. An attachment has to upload before its descriptor can be
 * written, so "queued" would mean holding a file in the outbox and re-uploading it later —
 * a different feature with its own failure modes. A reaction that fails costs a tap. A reply
 * points at a `seq`, and a `seq` is exactly what an unsent message does not have.
 */
export interface Pending {
  /** Ours, not the server's. Stable across a reload, which is what makes retrying possible. */
  localId: string;
  text: string;
  sentAt: number;
  /**
   * `sending` while a request is in flight, `failed` once one has come back badly.
   *
   * A reload turns `sending` into `failed`: a request whose answer we did not see may or may not
   * have arrived, and the honest thing is to say it did not go rather than to retry silently and
   * risk a double. The user decides.
   */
  state: "sending" | "failed";
}

/** Group roles: a single admin, with moderators under them. */
export interface Roles {
  admin: string;
  moderators: string[];
}

export interface ConversationView {
  groupId: Uint8Array;
  /** Stable display key: a `Uint8Array` cannot be used as a Map or React key. */
  key: string;
  messages: Message[];
  /** One per member device. Two devices of the same account appear twice. */
  peers: Peer[];
  /**
   * Peers grouped by account, with attestations re-verified.
   *
   * Filled during polling rather than at render time: resolution goes over the network, and a
   * React component is not the place to decide whether to trust someone.
   */
  accounts: ResolvedAccount[];
  epoch: bigint;
  cursor: number;
  /**
   * Has our log head already been gossiped in this conversation?
   *
   * Deliberately not persisted: one broadcast per session. The check is about the existence of
   * a fork, and redoing it now and then costs one message.
   */
  gossiped?: boolean;
  /**
   * Has the archived history already been pulled back in this session?
   *
   * Same reasoning as `gossiped`: deliberately not persisted, because messages only live in
   * memory. Every session must therefore ask the vault again — once, when the conversation is
   * opened, not on every poll.
   */
  hydrated?: boolean;
  /**
   * The group's posting key, if we know it.
   *
   * Its presence switches sends onto the anonymous path: the server stops learning which member
   * is writing. Its absence is not an error — conversations created before sealed sender keep
   * using signed posts.
   */
  postingKey?: Uint8Array;
  /** Has the key already been shared in this conversation, this session? */
  postingKeyShared?: boolean;
  /**
   * The epoch at which we last announced our display name here.
   *
   * The guard rail, and the field exists only to be one. A name has to reach a group once when we
   * join it, once when we change the name, and once more whenever somebody new arrives — and a
   * new arrival is precisely what moves the epoch, so one comparison covers all three. Without
   * it, the announcement would sit in the poll loop and go out on every pass: an envelope every
   * few seconds, per conversation, saying what everyone already knows. That is traffic the server
   * counts even though it cannot read it, and a message rate is a fact about a conversation.
   *
   * Deliberately not persisted, like `gossiped` and `postingKeyShared`: re-announcing once per
   * session costs one envelope and repairs anything a peer missed while it was away.
   */
  profileEpoch?: bigint;
  /**
   * Sequence numbers we posted ourselves.
   *
   * They are already applied locally and MLS refuses to read them again. So we skip them when
   * polling — but **without moving the cursor up to them**: the number the server assigns to our
   * message says nothing about the envelopes before it. Skipping that far steps over other
   * members' commits, and the group freezes at a stale epoch with no error to show for it.
   */
  mine: Set<number>;
  /**
   * What each account has acknowledged, in this conversation.
   *
   * Not persisted: a receipt means "as of then", and replaying it across sessions would show a
   * read state nobody has confirmed since. Receipts come back on their own at the next poll.
   */
  receipts: ReceiptBook;
  /**
   * Highest sequence number of a **received, displayable message**.
   *
   * # Why reusing `cursor` is not enough
   *
   * `cursor` advances on every processed envelope, receipts included. Acknowledging up to
   * `cursor` therefore acknowledges the acknowledgements: each receipt breeds another, and the
   * conversation never stops. Measured, in local production: ten envelopes in forty seconds for
   * two people saying nothing.
   *
   * A receipt says "I received your messages up to N", where N is a message. That is the only
   * cursor with a bound: protocol traffic does not move it, so it eventually goes quiet.
   */
  contentCursor: number;
  /** How far the user has actually seen the conversation on screen. */
  readCursor: number;
  /**
   * The server no longer holds envelopes we never read.
   *
   * Set when a fetch — or a gateway `gap` frame — reports an `oldest` sequence above our cursor
   * plus one. The server purges envelopes past thirty days once a group is more than five
   * hundred ahead, so a device left offline that long comes back to a mailbox with a hole in it.
   *
   * # Why this stops the loop rather than logging
   *
   * A missing envelope is a missing generation of the MLS application ratchet: nothing after it
   * decrypts, ever. Carrying on would produce one error per envelope, on every poll, for the
   * lifetime of the session — the "unreadable message does not block the conversation" rule in
   * `poll` is right for a single bad envelope and wrong for a severed ratchet. So the flag stops
   * the conversation being polled at all.
   *
   * Deliberately not persisted, like `gossiped` and `hydrated`: it is re-derived from the first
   * fetch of the next session, and persisting it would risk carrying a stale verdict past the
   * re-introduction that fixes it.
   *
   * **What it does not do**, and what a later lot owes the user: nothing renders it. The
   * conversation goes quiet rather than displaying an error, which is the lesser of two wrongs
   * and still a wrong. Recovery — restoring the content from the vault and asking to be re-added
   * to the group — is not implemented here either.
   */
  stale?: boolean;
  /** Peers currently typing, with their expiry timestamp. */
  typing: Typing[];
  /** Last time we emitted a typing indicator, for the debounce. */
  typingSentAt?: number;
  /**
   * Written here, not yet accepted by the server.
   *
   * Persisted, unlike the rest of the ephemeral state: a message the user typed is the one thing
   * on this screen they would be angry to lose, and losing it silently on a reload is exactly
   * what happened before.
   */
  outbox: Pending[];
  /**
   * Bumped whenever this thread changes.
   *
   * # Why a counter, on an object that is already the truth
   *
   * Because the object is the same object. Messages are pushed into `messages` in place, so
   * `conversations.get(key)` returns an identical reference before and after an arrival. React
   * cannot see that anything happened: a `useMemo` keyed on the view returns its first value for
   * ever, and a `memo`ised component never re-renders. Those are not hypothetical — they are the
   * two mistakes this field exists to make impossible.
   *
   * So anything derived from a thread — a virtualised layout, a search index, a preview line —
   * keys on `[view.key, view.revision]` and is correct by construction.
   *
   * # What it does not solve
   *
   * Granularity in the other direction. It moves for a received message and for a discarded
   * draft alike, so a consumer that only cares about one of the two recomputes for both. That is
   * cheaper than the alternative, which is a counter per concern and a rule about which one to
   * read.
   *
   * Not persisted: it is meaningless across sessions, and a restored thread starts at zero.
   */
  revision: number;
}

/**
 * Signalling state for a brand-new conversation.
 *
 * None of it is persisted: a receipt or a typing indicator means "right now". Restoring them
 * across sessions would show a state nobody has confirmed since.
 */
export function freshSignalState(): Pick<
  ConversationView,
  "receipts" | "contentCursor" | "readCursor" | "typing" | "outbox" | "revision"
> {
  return {
    receipts: new Map(),
    contentCursor: 0,
    readCursor: 0,
    typing: [],
    outbox: [],
    revision: 0,
  };
}

/**
 * The server failed to prove what it claims about an account key.
 *
 * # Why this is an error and not a banner
 *
 * It used to be only a banner. `resolve` recorded the anomaly and returned the account anyway,
 * so a conversation opened on a key the server had just failed to place in the log — which is
 * precisely the case the log exists to catch. The apparatus produced its signal and nothing
 * acted on it.
 *
 * The rule now matches the one already applied to unattested devices in `startConversation`,
 * and for the same stated reason: refusing to open beats quietly carrying on, because keeping
 * quiet cancels out the whole point of the machinery.
 *
 * # What it is deliberately not
 *
 * A **network** failure. A log that cannot be reached proves nothing either way, and treating
 * unreachable as hostile would make every outage look like an attack. That path stays a warning
 * and a retry, as before.
 *
 * # Why there is no way to override it
 *
 * An override would be clicked. This project already refuses to show a permanent warning on the
 * grounds that one taught to be ignored is inaudible on the day it matters; a "continue anyway"
 * button on the one alert that cannot be a false positive is the same mistake wearing a
 * different shape. A conversation already open is not cut off — `refreshAccounts` falls back to
 * the account it last verified — but a new one does not start.
 *
 * # The cost, stated rather than discovered
 *
 * Now that the anchor survives restarts, **wiping the server's database looks exactly like an
 * amputated log**, because from the client's side it is one: the head shrank. A developer who
 * resets Postgres while keeping a browser session will find every resolve refused, and the way
 * out is to erase the local identity. That is not a defect to work around — a client that
 * shrugged at a shrinking log would not be checking anything — but it is a real change in what
 * a local reset costs, and it should not be found out the hard way.
 */
/**
 * The stored state predates account ids, and is refused rather than reinterpreted.
 *
 * # Why this is an error and not a silent reset
 *
 * `profiles`, `petnames`, `verified` and `knownDevices` were `Record<handle, …>` on disk and are
 * keyed by account id now. Reading the old shape under the new key raises nothing — it simply
 * comes back empty. Petnames disappear, which is an annoyance; `verified` comes back empty, which
 * is a **false alarm**: every correspondent reads as never verified, and the banner that exists
 * to report a key substitution goes up on accounts that are entirely legitimate.
 *
 * A person whose verifications are gone has to be told, or they will believe they have checked
 * something they have not. So the failure is loud, and the interface says what was lost.
 */
export class StoredSessionTooOld extends Error {
  constructor() {
    super(
      "This device's saved session was written before accounts had identifiers of their own, " +
        "and cannot be read under the new one. Signing in again rebuilds it — nicknames and " +
        "verifications will have to be redone.",
    );
    this.name = "StoredSessionTooOld";
  }
}

export class LogProofRefused extends Error {
  /**
   * Declared and assigned rather than written as a constructor parameter property.
   *
   * The two are the same to a reader and not the same to the test runner: `node --test` runs with
   * `--experimental-strip-types`, which erases annotations without rewriting anything, and a
   * parameter property is the one piece of TypeScript that needs rewriting. One of them in this
   * file made the whole file unimportable from a test — including `freshPreferences` and
   * `freshSignalState`, which every conversation fixture needs.
   */
  readonly handle: string;

  constructor(handle: string, reason: string) {
    super(`The server failed to prove its key for @${handle}: ${reason}`);
    this.name = "LogProofRefused";
    this.handle = handle;
  }
}

/**
 * Per-conversation preferences.
 *
 * # Why every field is optional, and absence is the default
 *
 * Because the alternative is a migration. These are written into `StoredSession`, which two
 * different codecs read — a structured clone on the web and a hand-written one under Tauri that
 * **throws** on a version it does not recognise. A field that must be present is a field that
 * breaks every existing session the day it is added. A field whose absence means "the default"
 * is additive in both directions, forwards and backwards, for ever.
 *
 * The corollary is a rule for whoever adds the next one: **name the flag so that `undefined` is
 * the harmless answer.** `archived?: boolean` works because not-archived is the default;
 * `showInList?: boolean` would not, because absence would read as hidden.
 *
 * # Why one record and not three
 *
 * Pinning, archiving and muting are three questions and it is tempting to give each its own
 * `Record<string, …>`, next to `cursors` and `postingKeys`. The cost of a stored field is paid
 * per field — a line in the interface, a line in the encoder, a line in the decoder, a fallback
 * in each reader — so three records are three places to forget one. They travel together and
 * they are read together.
 *
 * # What this does not solve: other devices
 *
 * These stay on the machine that set them. There is no per-account opaque storage on the server
 * to sync them through, and the two ways to invent one both cost something real: the vault
 * refuses a group the caller is not a member of, and a group of one's own devices would spend an
 * envelope per preference change — envelopes that retention eventually collects, so a device
 * left off long enough would silently drift. Pinning something on a laptop therefore does
 * nothing to a phone, and the settings screen has to say so rather than let it be discovered.
 */
export interface ConversationFlags {
  /** Sorted above the rest of the list, whatever its last activity. */
  pinned?: boolean;
  /**
   * Out of the list, and silent.
   *
   * Strictly a display decision. An archived conversation **keeps polling and keeps advancing
   * its cursor**: not reading it would leave the ratchet behind, and once the server collects
   * envelopes past a retention window a conversation left archived long enough would come back
   * unreadable. Archiving must never be allowed to mean "stop syncing".
   */
  archived?: boolean;
  /** Epoch milliseconds until which notifications stay silent. Absent means not muted. */
  mutedUntil?: number;
  /**
   * Overrides the account-wide default for naming this conversation in a notification.
   *
   * Absent means "follow the account setting", which is why this is not a plain boolean with a
   * default — three states are needed and two of them are not "off".
   */
  discloseName?: boolean;
  /**
   * When explicitly `false`, bodies from this conversation are never deposited in the vault.
   *
   * Absent means "follow the account setting". Turning it off stops future deposits; it does not
   * remove what is already there, and the screen that offers it has to offer the deletion too or
   * it is claiming something it has not done.
   */
  archiveToVault?: boolean;
  /**
   * Lifetime in milliseconds for messages sent here, counted from the sender's `sentAt`.
   *
   * Not enforceable, and the interface must say so before the control rather than after: the
   * other side runs their own client, screenshots exist, and a recipient who wants to keep a
   * message keeps it. What it does buy is that the message never reaches the vault, so it is not
   * waiting on a server for the rest of time.
   */
  ephemeralMs?: number;
}

/**
 * Records that a thread changed.
 *
 * A free function rather than three characters written inline at each site, for one reason: it
 * is greppable. `touch(view)` finds every place a thread is mutated, which is exactly the list
 * someone needs when they wonder why a derived value went stale. `view.revision += 1` scattered
 * around does not answer that question.
 *
 * Call it after the mutation, not before. Nothing enforces that — this is a convention, and the
 * failure mode if it is broken is a value computed from the state before the change.
 */
export function touch(view: ConversationView): void {
  view.revision += 1;
}

/**
 * The stored preferences that are not about a single conversation, plus the map of the ones that
 * are.
 *
 * # Why they travel as one object
 *
 * Not for tidiness — to keep `persist()` and `open()` from becoming a merge conflict. Several
 * features are being built at once and every one of them wants a stored field; if each adds its
 * own line to the object literal in `persist` and its own line to the restoration in `open`,
 * every branch touches the same two places and every branch conflicts with every other. One
 * field that is read and written whole means a feature extends **this type** and its own
 * accessors, and never has to open `session.ts` at those two points again.
 *
 * # Why the collections are required and the scalars optional
 *
 * A missing record and an empty record mean the same thing — nothing was set — so defaulting to
 * empty at load costs nothing and spares every reader a `?? {}`. A missing scalar means
 * something different from any value it could hold: `locale` absent is "follow the system",
 * which is not the same as any particular language. Where absence carries meaning, it is kept.
 */
export interface Preferences {
  /** Per conversation, indexed by hex group id. */
  conversations: Record<string, ConversationFlags>;
  /** Interface language. Absent means "follow the system". */
  locale?: string;
  /** Which slice of each conversation the local search index has actually seen. */
  searchCoverage: Record<string, { from: number; to: number }>;
  /** A cache of the policy the server enforces. Absent until the account has been asked. */
  contactPolicy?: "open" | "known" | "closed";
  /** Handles this device declines to display. Hides; does not prevent. */
  blocked: string[];
  /**
   * Emoji recently reacted with or inserted, most recent first, base form without a skin tone.
   *
   * Kept here rather than in `localStorage`, where the theme preference lives, because the two
   * are not the same kind of fact. Which emoji somebody reaches for is a habit, and a habit is
   * exactly what a device seized after the fact should not read off the disk in the clear. In
   * this object it is sealed by `DeviceCipher` along with everything else.
   *
   * Stored untoned so that five variants of one thumb cannot crowd out the rest of the list; the
   * tone is applied on the way out by `applyTone`.
   */
  recentEmojis: string[];
  /**
   * The skin tone applied to emoji that take one, as an index into the five Unicode modifiers.
   *
   * Zero is the yellow glyph, which is the **absence** of a tone rather than one of them — hence
   * six values for five modifiers. Optional on top of that, and the difference matters: absent
   * means nobody has been asked, `0` means somebody chose yellow. Only the second is a decision
   * to preserve if a default ever changes.
   */
  skinTone?: 0 | 1 | 2 | 3 | 4 | 5;
}

/** The preferences of an account that has never expressed one. */
export function freshPreferences(): Preferences {
  return { conversations: {}, searchCoverage: {}, blocked: [], recentEmojis: [] };
}

/** The flags of one conversation, or an empty set if it has never had any. */
export function flagsOf(preferences: Preferences, key: string): ConversationFlags {
  return preferences.conversations[key] ?? {};
}
