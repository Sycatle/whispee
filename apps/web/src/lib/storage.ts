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
