/**
 * Local persistence.
 *
 * # Two implementations, one interface
 *
 * On the web, IndexedDB. Under Tauri, a file written by the Rust process — because a mobile
 * webview's storage **is not guaranteed**: iOS evicts WKWebView data after seven days of
 * inactivity, Android purges under memory pressure. And the loss is permanent: the MLS ratchet
 * destroys its keys as it goes.
 *
 * # Keys do not go through here
 *
 * `StoredSession` carries none. On the web they do exist in the same database — non-extractable
 * `CryptoKey` values, which IndexedDB accepts as-is and no file could hold — but that is the
 * store's business, not the session's. The session asks `DeviceCipher` to seal and never sees key
 * material, which is exactly what lets it be the same on both platforms.
 *
 * The MLS state is encrypted before it gets here (see `wrapState`).
 */
import { isTauri } from "./platform";
import type { DeviceKeys } from "./keys";
import type { LockEnvelope } from "./lock";
import type { ConversationFlags } from "./session-types";

const DB_NAME = "whispee";
const DB_VERSION = 1;
const STORE = "device";

interface StoredSession {
  deviceId: string;
  /** The account's handle. Plaintext server-side, like the MLS credential. */
  handle: string;
  /**
   * The account seed, **encrypted** with the same key as the MLS state.
   *
   * It is worth the whole account: it can attest new devices and revoke them. It is kept because
   * a device must be able to pair another without asking the user for the phrase again — but it
   * must never touch the disk in the clear, nor leave over the network other than sealed inside a
   * pairing blob.
   */
  accountSeed: Uint8Array;
  /**
   * The local lock, if enabled.
   *
   * Absent, the state is encrypted by the non-extractable key of `DeviceKeys`: that protects
   * against exfiltration by script, but not against whoever gets the browser session. Present,
   * the state is encrypted by a master key that only exists in memory once the password has been
   * entered.
   *
   * Nothing stored here is secret: the salt is public, and the master key appears encrypted.
   */
  lock?: LockEnvelope;
  /**
   * Is the history vault enabled?
   *
   * **Absent means enabled.** The vault is the default; this flag only records a refusal. Three
   * values, not two: `false` is a user decision and must be honoured, `undefined` is the absence
   * of a decision and is treated as a fresh account. Conflating them would turn backup back on
   * behind the back of someone who had turned it off.
   *
   * Only the flag is stored: the key is re-derived from the account seed, itself encrypted just
   * above. Keeping it here would make one more copy of a secret that opens the whole archived
   * past.
   */
  vaultEnabled?: boolean;
  /** Encrypted MLS state. Never in the clear on disk. */
  state?: Uint8Array;
  /** MLS storage cannot be enumerated: the group list is kept alongside it. */
  groupIds: Uint8Array[];
  /**
   * Account fingerprints already verified out of band, by handle.
   *
   * Keeping the verified value — rather than a mere boolean — is what makes it possible to
   * **detect a change**. The fingerprint covers the account key, not a device key: it does not
   * move when the correspondent adds a phone. If it changes anyway, it is either a recovery from
   * the phrase or a substitution by the server. One is rare, the other is the attack; only the
   * user can decide, but they have to be told first.
   */
  verified: Record<string, string>;
  /**
   * Last sequence processed per conversation, indexed by hex group id.
   *
   * Must be persisted with the MLS state, not recomputed at startup. Each message key is consumed
   * then destroyed on read: replaying the stream from the beginning would fail every message
   * already read, and the conversation would stay empty after a mere page reload.
   */
  cursors: Record<string, number>;
  /**
   * Devices known for each correspondent, by handle.
   *
   * Used to spot an addition: a device appearing on a peer is an event worth reporting, and it is
   * that notification — not the fingerprint, deliberately stable — that reveals a hostile device
   * legitimately attested by a compromised account.
   */
  knownDevices: Record<string, string[]>;
  /**
   * Signalling settings. Absent on earlier sessions, hence optional.
   *
   * They live here and nowhere else: they are local preferences, and telling the server about
   * them would amount to teaching it who refuses to be observed.
   */
  signals?: SignalSettings;
  /**
   * Posting key per conversation, indexed by hex group id.
   *
   * # Why persist it
   *
   * Without it, every page reload strips the client of its ability to post anonymously, until
   * another member rebroadcasts it — which assumes that member is online. Sealed sender and the
   * typing indicator silently fell back to "nothing" in the meantime: the hardest kind of failure
   * to see, since everything else works.
   *
   * # What it does not expose
   *
   * Nothing new. This key is already known to every group member **and to the server**, which has
   * to verify the MACs. It opens no content; it only proves membership. It sits in the encrypted
   * state at rest anyway, like the MLS keys, which are worth far more.
   */
  postingKeys?: Record<string, string>;
  /**
   * The last accepted head of the transparency log.
   *
   * # Why this has to survive a restart
   *
   * It is the anchor the consistency proof is measured against, and a consistency proof is the
   * only one of the three checks that says anything about the **past**: without it the server can
   * replace a key it already published and serve a log that is perfectly consistent with itself.
   *
   * Kept in memory only, the anchor was empty on every start, and `verifyAccount` skips the
   * consistency check when it has nothing to compare against. So the first resolve after each
   * reload accepted any signed, self-consistent log — which is the exact window the mechanism
   * exists to close. `transparency.ts` already described this field as "kept from one session to
   * the next"; this is what makes that true.
   *
   * Base64 rather than bytes, like `postingKeys`: the native store goes through a JSON codec,
   * and a `Uint8Array` handed to `JSON.stringify` comes back as an object keyed by strings.
   */
  logHead?: { size: number; root: string; logKey: string };
  /**
   * The recent thread of each conversation, **encrypted**, like the MLS state.
   *
   * The first decrypted content ever written to this disk. `history.ts` argues the trade in full;
   * the short version is that the plaintext was already being written down — into the server
   * vault, under a key that never rotates — and that a sealed local copy is the same data in the
   * better place. Without it a conversation opens empty and waits for the network, and offline
   * there is nothing to read at all.
   */
  history?: Uint8Array;
  /**
   * May a notification name the conversation it came from?
   *
   * **Absent means no**, unlike `vaultEnabled` a few fields up, and the asymmetry is deliberate:
   * this one discloses something to whoever picks the device up, so the default is the quiet one
   * and the flag only records a decision to say more.
   */
  discloseConversationName?: boolean;
  /**
   * Per-conversation preferences, indexed by hex group id.
   *
   * Same shape as `cursors` and `postingKeys` a few fields up, and for the same reason: the group
   * id is the only identifier that survives a reload, and a `Map` does not round-trip through
   * JSON. `session-types.ts` explains why one record holds every flag instead of one record per
   * flag, and why absence has to be the harmless answer for each of them.
   *
   * These never reach the server, exactly like `signals`: which conversations someone pinned or
   * muted is a ranking of the people they care about, and it would be a new fact about them
   * rather than one the server already holds.
   */
  conversationFlags?: Record<string, ConversationFlags>;
  /**
   * The language the interface was last shown in.
   *
   * Absent means "follow the system", which is the default and stays the default: a stored value
   * only ever records a decision to contradict the platform. That is the same three-state shape
   * as `discloseConversationName`, for the same reason — "not chosen" and "chosen to be the same
   * as the default" have to stay distinguishable, or changing the default silently overrides a
   * choice somebody made.
   */
  locale?: string;
  /**
   * How much of each conversation the local search index actually covers.
   *
   * **The coverage, not the index.** The index itself is far too large to live here: `persist()`
   * re-serialises this whole object on every send, so a field that grows with the history would
   * make each message cost a re-encryption of everything ever written. The index is stored per
   * conversation, elsewhere; this is the small map that says which slice of each thread was fed
   * to it.
   *
   * It exists so the interface can be honest. A search that answers "not found" for a message
   * that exists is worse than no search at all, so the only acceptable behaviour is to state what
   * was looked at — and that needs a record of what was looked at.
   */
  searchCoverage?: Record<string, { from: number; to: number }>;
  /**
   * Who is allowed to start a conversation with this account.
   *
   * Mirrors the column the server holds, so the interface can show the current setting without a
   * round trip. **The server is the enforcement point**, not this field: a copy kept locally is a
   * cache of a decision, never the decision itself.
   */
  contactPolicy?: "open" | "known" | "closed";
  /**
   * Handles this device refuses to display.
   *
   * Local, and therefore weak on purpose — it hides, it does not prevent. Anyone registered can
   * still add anyone to a group and have envelopes delivered to them; blocking on this side means
   * declining to read something that exists and is stored. That is why the screen offering it has
   * to offer `contactPolicy` in the same breath: without the server-side half, a block is a
   * courtesy to oneself rather than a barrier.
   */
  blocked?: string[];
  /**
   * Emoji recently used, most recent first, untoned. See `Preferences.recentEmojis`.
   *
   * Here rather than in `localStorage` because it is a habit, and this record is sealed.
   */
  recentEmojis?: string[];
  /**
   * The chosen skin tone, as an index into the five Unicode modifiers, `0` being the yellow
   * glyph. **Absent means nobody chose**, which is not the same as choosing yellow.
   */
  skinTone?: 0 | 1 | 2 | 3 | 4 | 5;
}

/** What the user agrees to emit. */
export interface SignalSettings {
  /**
   * Emit — and therefore see — read receipts.
   *
   * A single flag for both directions: reciprocity is the rule, and two separate flags would
   * invite seeing without being seen.
   */
  readReceipts: boolean;
  /** Emit the typing indicator. Receiving it stays possible: nothing to hide in going without. */
  typingIndicator: boolean;
  /**
   * Broadcast — and therefore see — presence.
   *
   * A single flag, as for read receipts, and for the same reason: two separate flags would invite
   * seeing without being seen. Reciprocity is moreover **enforced by the server**, which stops
   * recording as much as serving; this flag only avoids a pointless request and reflects the
   * state on screen.
   *
   * Absent means enabled: presence is the default, this flag only records a refusal.
   */
  presence?: boolean;
}

/**
 * Delay past which the open is considered stuck.
 *
 * IndexedDB does not always report `onblocked`: a database being deleted, or another tab holding
 * the old version, leaves the request silent — neither success nor error, indefinitely. Without
 * this guard, the application sits on "Loading…" with nothing to say why.
 */
const OPEN_TIMEOUT_MS = 5000;

const BLOCKED =
  "Local database unavailable. Another tab of the application is holding it: close it, then reload.";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    const timer = setTimeout(() => reject(new Error(BLOCKED)), OPEN_TIMEOUT_MS);
    const settle = <T>(run: () => T) => {
      clearTimeout(timer);
      return run();
    };

    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => settle(() => resolve(request.result));
    request.onerror = () => settle(() => reject(request.error));
    request.onblocked = () => settle(() => reject(new Error(BLOCKED)));
  });
}

function transact<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>) {
  return open().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const request = run(db.transaction(STORE, mode).objectStore(STORE));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      }),
  );
}

/**
 * Where the session is kept.
 *
 * Three operations and no more: everything that decides *what* to keep lives in `Session`, and
 * everything that decides *how to protect it* lives in `DeviceCipher`. A port that also knew how
 * to encrypt would have to know the keys, which is precisely what we are trying to avoid.
 */
export interface SessionStore {
  load(): Promise<StoredSession | undefined>;
  save(session: StoredSession): Promise<void>;
  /**
   * Erases everything.
   *
   * On the web, non-extractable keys disappear with the database: without them, any leftover
   * encrypted state is permanently unreadable, by us included.
   */
  clear(): Promise<void>;
}

/** What IndexedDB actually holds: the session, plus the keys only the store handles. */
interface StoredWithKeys extends StoredSession {
  keys: DeviceKeys;
}

/**
 * The browser store, which also keeps the device keys.
 *
 * It holds them because it is the only thing that can: they do not serialise, so they can only
 * live where structured cloning accepts them. The session ignores them — which is what lets it be
 * identical under Tauri, where they live in another process.
 */
export class IndexedDbStore implements SessionStore {
  private keys: DeviceKeys;

  constructor(keys: DeviceKeys) {
    this.keys = keys;
  }

  async load(): Promise<StoredSession | undefined> {
    const stored = await transact<StoredWithKeys | undefined>("readonly", (store) =>
      store.get("session"),
    );
    if (!stored) return undefined;

    // The keys read from storage override those received at construction: on reload, they are
    // the only ones that decrypt the state already written.
    this.keys = stored.keys;
    return stored;
  }

  async save(session: StoredSession): Promise<void> {
    await transact("readwrite", (store) => store.put({ ...session, keys: this.keys }, "session"));
  }

  async clear(): Promise<void> {
    await transact("readwrite", (store) => store.clear());
  }
}

/**
 * Reads the keys already kept in the database, if there are any.
 *
 * Separate from `load` because the order demands it: the keys are needed to build the cipher, and
 * the cipher to open the state. On the web both come out of the same database, which invites
 * confusing them — under Tauri they come from another process, and the confusion would cost.
 */
export async function readStoredKeys(): Promise<DeviceKeys | undefined> {
  const stored = await transact<StoredWithKeys | undefined>("readonly", (store) =>
    store.get("session"),
  );
  return stored?.keys;
}

export type { StoredSession };
