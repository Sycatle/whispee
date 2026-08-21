/**
 * What a session writes down, assembled apart from the class that owns it.
 *
 * # Why this left `session.ts`
 *
 * Not tidiness, and not line count. `Session.persist` read twenty-two private fields directly,
 * and that had two consequences worth separating.
 *
 * The first is that **no field could ever move**. Extracting anything else out of `Session` —
 * the vault, the lock, the naming — means the extracted piece has to contribute its own slice of
 * `StoredSession`, and it cannot while the writer names every field itself. So this is the lock
 * that had to be turned before any other extraction, rather than one extraction among several.
 *
 * The second is that the mapping was **untestable**, and it is the one piece of the session whose
 * failure is silent. `Session` cannot be instantiated under `node --test`: its constructor is
 * private, `open` calls `loadCrypto`, and the whole path wants WASM and IndexedDB. So the field
 * mapping — the part where forgetting one line loses somebody's petnames at the next reload, with
 * no error anywhere — had no coverage at all. Here it is an object in, an object out, and
 * `node --test` can ask it anything.
 *
 * # What did not change
 *
 * The **sequencing**, which is the part `docs/ARCHITECTURE.md` defends. There is still exactly one
 * `store.save`, still called from the same places, and the cursor and the MLS state still reach
 * the disk together. This function composes a value; it does not decide when that value is
 * written, and it cannot: it has no store.
 *
 * # What it does not solve
 *
 * The mapping is still written twice — once here, once in reverse in `Session.open` — and nothing
 * relates the two halves. A field added here and forgotten there still reads back as `undefined`,
 * and this file cannot see that. Closing it means a codec that owns both directions, which is
 * what `session-codec.ts` does for the part it covers.
 */
import { encodeHistory, type Cached } from "./history.ts";
import { toBase64 } from "./keys.ts";
import type { LockEnvelope } from "./lock";
import type { ConversationView } from "./session-types";
import type { SignalSettings, StoredSession } from "./storage";
import type { SeenHead } from "./transparency";

/**
 * Everything the stored shape is made of.
 *
 * Stated as data rather than reached for through a `Session`, which is what makes the mapping
 * answerable in a test. Adding a field to `StoredSession` should mean adding one here, and the
 * type will say so at both ends.
 */
export interface PersistInput {
  deviceId: string;
  handle: string;
  /**
   * The account seed and the MLS state, **in the clear**, as their owners export them.
   *
   * Sealed below rather than by the caller so that the pairing of the two — same key, same
   * moment — is a property of this function rather than a discipline at the call site. See
   * `seal`.
   */
  accountSeed: Uint8Array;
  mlsState: Uint8Array;
  /** MLS storage cannot be enumerated: the group list comes from the client, not the views. */
  groupIds: Uint8Array[];
  /**
   * The open conversations, by hex group id.
   *
   * A map rather than a list because the history is keyed by the map's key while the cursors are
   * keyed by `view.key`. The two agree in practice; taking the map preserves the distinction
   * rather than quietly deciding it.
   */
  conversations: ReadonlyMap<string, ConversationView>;
  lock: LockEnvelope | undefined;
  /** What `Archive` contributes, already mapped. */
  vault: Pick<StoredSession, "vaultEnabled">;
  /**
   * What `TrustStore` contributes, already mapped.
   *
   * The slice that costs the most to get wrong: `verified` is keyed by account, and read under a
   * key it was not written under it does not fail — it reports every checked correspondent as
   * unverified, or worse as changed. See `session-trust.ts`.
   */
  trust: Pick<StoredSession, "verified" | "knownDevices">;
  signals: SignalSettings;
  /**
   * What `PreferencesStore` contributes, already mapped.
   *
   * A slice rather than a `Preferences`, because the preferences own both directions of their own
   * mapping — `snapshot` here and `hydrate` in `Session.open` — and keeping the two together is
   * the only arrangement in which a test can assert they agree. See `session-preferences.ts`.
   */
  preferences: Partial<StoredSession>;
  /**
   * What `Names` contributes, already mapped.
   *
   * A slice for the same reason as `preferences`: the names own both directions of their own
   * mapping, and keeping the two together is the only arrangement in which a test can assert they
   * agree. It matters more here — two of those fields are keyed by account, so they are what a
   * change to how an account is identified has to travel through. See `session-naming.ts`.
   */
  names: Partial<StoredSession>;
  seenHead: SeenHead | undefined;
  /**
   * What encrypts the three things that must never touch the disk in the clear.
   *
   * Injected rather than taken as a `DeviceCipher` so that a test can watch what is sealed without
   * a key, and so that this file stays ignorant of whether a lock is engaged — that choice belongs
   * to whoever built the cipher.
   */
  seal(bytes: Uint8Array): Promise<Uint8Array>;
}

/**
 * Assembles the value to write.
 *
 * The conditional spreads are the subtle part and they are deliberate: a field written as
 * `undefined` and a field absent are the same to a reader and different to a store, and it is
 * absence that lets an account which never named itself keep the exact on-disk shape it had
 * before the feature existed. That is what makes an unchanged `VERSION` honest rather than merely
 * tolerated.
 */
export async function composeStored(input: PersistInput): Promise<StoredSession> {
  const views = [...input.conversations.values()];

  return {
    cursors: Object.fromEntries(views.map((view) => [view.key, view.cursor])),
    deviceId: input.deviceId,
    handle: input.handle,
    // The seed is encrypted like the MLS state: it is worth the whole account.
    accountSeed: await input.seal(input.accountSeed),
    lock: input.lock,
    ...input.vault,
    state: await input.seal(input.mlsState),
    groupIds: input.groupIds,
    ...input.trust,
    signals: input.signals,
    postingKeys: Object.fromEntries(
      views
        .filter((view) => view.postingKey)
        .map((view) => [view.key, toBase64(view.postingKey as Uint8Array)]),
    ),
    ...input.preferences,
    ...input.names,
    history: await input.seal(
      encodeHistory(
        new Map<string, Cached>(
          [...input.conversations].map(([key, view]) => [
            key,
            { messages: view.messages, outbox: view.outbox, readCursor: view.readCursor },
          ]),
        ),
      ),
    ),
    ...(input.seenHead
      ? {
          logHead: {
            size: input.seenHead.size,
            root: toBase64(input.seenHead.root),
            logKey: toBase64(input.seenHead.logKey),
          },
        }
      : {}),
  };
}
