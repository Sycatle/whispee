/**
 * Orchestration: WASM module, delivery service and local storage.
 *
 * Home of the decisions that are neither crypto nor transport, and that the protocol does not
 * settle: when to replenish KeyPackages, how a guest discovers the group waiting for it, when
 * to persist state.
 */
import { normalize as normalizeHandle, validate as validateHandle } from "./handle";
import * as mention from "./mention";
import { type ResolvedAccount, resolveAccount } from "./account";
import { Api, ApiError, type PostMac } from "./api";
import type { MembershipEvent } from "./content";
import { deviceNameCandidates, detectDeviceKind } from "./device";
import { type PairingCode, decodePairingCode } from "./pairing";
import { type AttachmentRef, downloadAndDecrypt, encryptAndUpload } from "./attachments";
import * as content from "./content";
import * as envelope from "./envelope";
import { type Cached, decodeHistory } from "./history";
import { PINNED_LOG_KEY } from "./pinning";
import * as derive from "./conversation-view.ts";
import { PresenceTracker } from "./session-presence.ts";
import { PreferencesStore } from "./session-preferences.ts";
import { Names, type Profile } from "./session-naming.ts";
import { TrustStore } from "./session-trust.ts";
import { Archive } from "./session-vault.ts";
import { Lockbox, type LockKit } from "./session-lock.ts";
import { LogWitness, type LogChecks } from "./session-log.ts";
import { composeStored } from "./session-persist.ts";
import { type SyncedSignals, importSyncKey, openSignals, sealSignals } from "./signal-sync.ts";
import { fromBase64, toHex } from "./keys";
import { changePassword, createLock, exportMaster, openLock } from "./lock";
import * as biometrics from "./biometrics";
import type { SignalSettings } from "./storage";
import { type Decision, type Steps, type Presence, decide, migrate } from "./migration";
import {
  type Anchor,
  currentAnchor,
  nativeAnchor,
  newAnchor,
  existingWebAnchor,
  clearAll,
} from "./persistence";
import { isTauri } from "./platform";
import { pending, record } from "./receipts";
import {
  TYPING_DEBOUNCE_MS,
  fresh,
  openTyping,
  sealTyping,
  showing,
  without,
} from "./signals";
import { LockedCipher } from "./cipher";
import { Gateway } from "./gateway";
import * as log from "./transparency";
import * as padding from "./padding";
import {
  type AccountKey,
  type AttestedDevice,
  type Client,
  type CreatedAccount,
  type Crypto,
  type Incoming,
  type Invitation,
  type Peer,
  type Sealed,
  loadCrypto,
} from "./wasm";

/**
 * The real lock operations, bound to the platform.
 *
 * `session-lock.ts` holds the policy and imports nothing but types, because Argon2id lives in the
 * WASM module and the biometric prompt is Tauri IPC — a module importing either cannot be loaded
 * by `node --test`. This object is the seam, and it belongs here, where the platform already is.
 */
const logChecks = (api: Api, crypto: Crypto): LogChecks => ({
  account: (account, identityKey, seen) =>
    log.verifyAccount(api, crypto, account, identityKey, seen, PINNED_LOG_KEY),
  extendsView: async (peer) => {
    const current = await api.logHead();
    return log.verifyExtends(api, crypto, { ...peer, logKey: current.logKey }, current);
  },
});

const deviceLock: LockKit = {
  create: createLock,
  open: openLock,
  rekey: changePassword,
  wrap: (signing, master) => new LockedCipher(signing, master),
  keepBiometric: async (master) => {
    await biometrics.enableBiometric(await exportMaster(master));
  },
  dropBiometric: () => biometrics.disableBiometric(),
};

/** How many KeyPackages we keep in stock on the server. */
const KEY_PACKAGE_TARGET = 10;
/** Replenishment threshold. At zero, nobody can reach us any more. */
const KEY_PACKAGE_LOW_WATER = 3;

/**
 * The conversation shapes now live in `session-types.ts`, and are re-exported here.
 *
 * Re-exported rather than moved outright so that no import anywhere else has to change: this
 * module has been the address of `Message` and `ConversationView` since they existed, and a
 * rename across thirty call sites would have buried the actual change in noise. The file that
 * holds them explains why they had to leave.
 */
export {
  LogProofRefused,
  freshSignalState,
  type ConversationFlags,
  type ConversationView,
  type Message,
  type Pending,
  type Roles,
  type VerificationState,
} from "./session-types";

import { isAccountId } from "./chain";
import {
  StoredSessionTooOld,
  freshSignalState,
  touch,
  type Preferences,
  type ConversationView,
  type Message,
  type Pending,
  type Roles,
  type VerificationState,
} from "./session-types";

export class Session {
  private constructor(
    readonly deviceId: string,
    /**
     * What identifies this account, everywhere the protocol has to be sure.
     *
     * The fingerprint of the account's genesis key — see `crates/attest/src/lib.rs::account_id`.
     * It is the subject of the MLS credential, the prefix of the device id, the subject of every
     * attestation, the key of the roster and of the roles, and the key of every record below that
     * used to be keyed by handle.
     *
     * **Persisted, never recomputed.** A rotation generates a fresh seed, so `account.id()` on the
     * account we hold after one returns a *different* id: it is a new genesis. What ties the two
     * together is the signed chain, not arithmetic on the key in hand — so the id is state, and
     * deriving it would silently rename the account on its first rotation.
     *
     * Named `accountId` and not `account` because `account` is already the *key*, a few lines
     * down. The two are not interchangeable and the collision would be the kind that type-checks.
     */
    readonly accountId: string,
    /**
     * The name this account answers to.
     *
     * A label, and only that, since `0014_account_identity.sql`: unique among the living, but
     * releasable and renameable. Nothing in the protocol is allowed to depend on it — it is here
     * so the interface has something to show, and so the account can say what it now goes by.
     */
    readonly handle: string,
    private readonly client: Client,
    private account: AccountKey,
    private readonly crypto: Crypto,
    private readonly api: Api,
    /**
     * Where the state is kept, and under which identity.
     *
     * One pair rather than two fields: the key that opens the state must be the one it was
     * sealed under, and splitting them would allow assembling a store with the other platform's
     * cipher — unreadable state, with no symptom beyond a decryption failure.
     */
    private readonly anchor: Anchor,
    /**
     * The local lock, and what encrypts the state at rest behind it.
     *
     * Holds both ciphers so that only one of them can move: the anchor's own signs and does not
     * switch — the server must see no difference between a locked device and an unlocked one —
     * while the sealing one is exactly what a lock replaces. See `session-lock.ts`.
     */
    private lockbox: Lockbox,
    /**
     * Vault key. Present by default; `null` only if the user turned backup off, or if deriving
     * it failed.
     *
     * Derived from the recovery phrase, so **stable over time**: that is what lets a new device
     * read the history back, and it is exactly what we give up by keeping it. See `vault.ts`.
     */
    private archive: Archive,
    readonly conversations: Map<string, ConversationView>,
    private trust: TrustStore,
    /**
     * Signalling settings.
     *
     * Read receipts are **on by default**, as in consumer apps: silently disabling them would
     * make the other side's display incomprehensible. It is a product choice, and one click
     * reverses it.
     */
    private signals: SignalSettings = { readReceipts: true, typingIndicator: true, presence: true },
    /**
     * When the settings above were last changed, on whichever device changed them.
     *
     * `undefined` reads as older than anything, so the first announcement a device hears wins.
     * That is the right default for an account upgrading from the per-device era: whatever is on
     * the device that speaks first becomes the account's, and one click changes it.
     */
    private signalsAt: number | undefined = undefined,
  ) {}

  /**
   * The key our own devices share, imported once.
   *
   * Derived on demand, like the vault key, and cached because every epoch of every conversation
   * asks for it. `null` until first use; the derivation cannot fail for an account that exists.
   */
  private syncKey: CryptoKey | null = null;

  /**
   * May a notification name the conversation?
   *
   * Off unless the user turned it on. Held here rather than in `SignalSettings`, which is about
   * what this device **emits** to others: this discloses nothing to anyone on the network, only
   * to whoever is standing in front of the screen.
   */
  get discloseConversationName(): boolean {
    return this.settings.discloseConversationName;
  }

  /** Records the choice, so a reload does not quietly return to the quiet default. */
  async setDiscloseConversationName(value: boolean): Promise<void> {
    this.settings.setDisclose(value);
    await this.persist();
  }

  /**
   * Everything else the user has chosen and expects to find again.
   *
   * Read it freely; to change it, go through `updatePreferences` so the change reaches disk. The
   * value is the store's own and mutable, which is unusual here and deliberate — `Preferences`
   * explains the trade in full.
   */
  get preferences(): Preferences {
    return this.settings.value;
  }

  /**
   * Applies a change and writes it down.
   *
   * Takes a mutator rather than a whole object so that two callers changing different preferences
   * cannot overwrite each other by handing back a stale copy — the mutation happens on the
   * current value, at the moment it is applied.
   *
   * The store does not write: persisting is ordered against the MLS state, and that decision
   * stays here.
   */
  async updatePreferences(change: (preferences: Preferences) => void): Promise<void> {
    this.settings.update(change);
    await this.persist();
  }

  /**
   * What is typed and not yet sent, per conversation.
   *
   * Switching conversation used to lose it: the text lived in the composer's own state, which is
   * unmounted the moment the other pane takes over. Half a sentence, gone for changing screen to
   * check something — the most ordinary thing anyone does mid-message.
   *
   * **Not persisted**, unlike the outbox. A draft is a thought in progress and the tab closing is
   * a fair end to it; the outbox holds messages someone decided to send. Keeping drafts would
   * also write the one thing nobody has committed to into a file they cannot see.
   */
  private readonly drafts = new Map<string, string>();

  draftIn(view: ConversationView): string {
    return this.drafts.get(view.key) ?? "";
  }

  setDraft(view: ConversationView, text: string): void {
    if (text === "") this.drafts.delete(view.key);
    else this.drafts.set(view.key, text);
  }

  /** Real-time session, when it is open. Its failure removes no feature. */
  private gateway?: Gateway;

  /**
   * Last accepted log head.
   *
   * Acts as an anchor: the server must prove its log extends it. With no memory, it could
   * rewrite an already published key and serve an equally consistent log.
   */
  private witness = new LogWitness();

  /** What this session's log checks are asked through. Built once: it closes over api and crypto. */
  private get checks(): LogChecks {
    return logChecks(this.api, this.crypto);
  }

  /**
   * Log anomalies seen since startup.
   *
   * Kept and displayed rather than discarded: a proof that does not verify is not a network
   * error to retry, it is exactly the signal this whole apparatus exists to produce.
   */
  get logAlerts(): string[] {
    return this.witness.alerts;
  }

  /**
   * The poll in flight, if any.
   *
   * Polling is driven by a `setInterval`: without this guard, a poll slower than the interval
   * races the next one. Both read the same cursor before either writes its own, reprocess the
   * same envelopes — and MLS refuses the second read, the keys having been destroyed. The
   * message is then lost for good.
   *
   * The symptom is confusing: everything works while the network is fast, then messages vanish
   * as soon as some operation makes a poll take longer.
   */
  private polling: Promise<void> | null = null;

  /** Account fingerprint, to be compared out of band with your correspondent. */
  accountFingerprint(): string {
    return this.account.fingerprint();
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
    return this.trust.verificationOf(account);
  }

  async markVerified(account: ResolvedAccount): Promise<void> {
    this.trust.markVerified(account);
    await this.persist();
  }

  /**
   * Creates a new account and its first device.
   *
   * Returns the recovery phrase **together with** the session: it only exists here and can never
   * be shown again. That is deliberate — a phrase the app can redisplay is a phrase anyone
   * holding the unlocked device can redisplay.
   */
  static async create(handle: string): Promise<[Session, string]> {
    const crypto = await loadCrypto();
    const created = crypto.AccountKey.generate() as CreatedAccount;

    // The id comes back from the server, which derives it from the key in this very request
    // rather than accepting one from us. Nothing is taken on trust by that: it is a hash of
    // `created.identityKey`, and the assertion below is what says so out loud.
    const id = await Api.createAccount(handle, created.identityKey);

    const account = crypto.AccountKey.restore(created.phrase);
    if (crypto.accountId(created.identityKey) !== id) {
      // Not a defensive flourish. If this ever fires, the server has named our account something
      // other than our key — which is the one substitution the whole identity design exists to
      // make impossible, and continuing would mean registering a device under somebody else's
      // name.
      throw new Error("The server named this account something other than its own key.");
    }

    const session = await Session.attach(crypto, account, id, handle);
    return [session, created.phrase];
  }

  /**
   * Attaches a new device to an existing account, from its recovery phrase.
   *
   * The device attests itself, which requires holding the account key. Without it the server
   * refuses the registration — that is what stops a third party from declaring itself a device
   * of an account whose handle is all it knows.
   *
   * What this path does not do: join existing conversations. They live in MLS groups this device
   * is not a member of; a device already present has to add it, which is what QR pairing does.
   */
  /**
   * Attaches this device to the account whose seed we just received by pairing.
   *
   * The normal way to add a device: the recovery phrase is never retyped, and so never has to be
   * exposed a second time.
   */
  static async fromSeed(handle: string, seed: Uint8Array, anchor?: Anchor): Promise<Session> {
    const crypto = await loadCrypto();
    return Session.attach(
      crypto,
      crypto.AccountKey.fromSeed(seed),
      await Api.resolveHandle(handle),
      handle,
      anchor,
    );
  }

  static async restoreFromPhrase(handle: string, phrase: string): Promise<Session> {
    const crypto = await loadCrypto();
    const account = crypto.AccountKey.restore(phrase.trim());
    // The directory, and the one moment this path has to consult it.
    //
    // The id cannot be derived from the phrase: after a rotation the phrase is the *new* one,
    // whose genesis is not the one the account is named after. So it is asked for — and the
    // answer needs no trust, because a wrong id makes the registration below fail: the server
    // verifies our attestation against that account's key, which we would not hold.
    return Session.attach(crypto, account, await Api.resolveHandle(handle), handle);
  }

  /** Registers a device under an account whose key we already hold. */
  private static async attach(
    crypto: Crypto,
    account: AccountKey,
    id: string,
    handle: string,
    /**
     * Anchor forced from outside, for migration: it registers a native device from a web device,
     * so the platform default does not say what to do.
     */
    imposed?: Anchor,
  ): Promise<Session> {
    // The anchor decides where the keys will live: in the native process under Tauri, in
    // IndexedDB elsewhere. Registration does not need to know which — it only handles the
    // public half.
    const anchor = imposed ?? (await newAnchor());
    const authKey = await anchor.cipher.authPublicKey();

    // The device id is qualified by the **account id**: without that the namespace would be
    // global and the first comer would grab "desktop" and "mobile" for everyone. The server
    // enforces this prefix, it is not a client-side convention.
    //
    // It used to be the handle, which meant every device id an account ever issued was tied to
    // whatever it was called at the time — and that was one of the reasons a handle could not be
    // renamed. An id never moves, so a rename now leaves every one of them intact.
    //
    // The name is detected, never asked for, and varied on collision: an account may legitimately
    // own two computers, and that is not the user's problem to solve.
    let client: Client | null = null;
    let deviceId = "";

    for (const name of deviceNameCandidates(detectDeviceKind())) {
      deviceId = `${id}:${name}`;

      // The MLS credential carries the **account id**, not the device id and no longer the
      // handle: it is the account that a peer is, and a credential naming something renameable
      // would report an identity change on every rename — MLS doing exactly its job, over a
      // cosmetic edit. A device is told apart by its signature key, and names itself in the
      // attestation.
      const candidate = crypto.Client.create(id);
      const mlsKey = candidate.signatureKey();

      // Both keys are attested together. Attesting them separately would allow recombining a
      // legitimate device's attestation with a hostile device's MLS key.
      const attestation = account.attest(id, deviceId, authKey, mlsKey);

      try {
        await Api.register(deviceId, id, authKey, mlsKey, attestation);
        client = candidate;
        break;
      } catch (error) {
        // 409: that name is already taken on this account. Any other error is real.
        if (!(error instanceof ApiError) || error.status !== 409) throw error;
      }
    }

    if (!client) {
      throw new Error("Too many devices with this name on this account.");
    }

    // With no lock, the state is encrypted by the anchor's own cipher; setting a lock wraps it
    // without touching the device identity.
    const api = new Api(deviceId, anchor.cipher);
    const session = new Session(
      deviceId,
      id,
      handle,
      client,
      account,
      crypto,
      api,
      anchor,
      // No lock at creation: the user sets one if they want to, from the app. Forcing it here
      // would put a password prompt right before the recovery phrase screen, which deserves all
      // the attention available.
      Lockbox.none(deviceLock, anchor.cipher),
      // Vault on from creation, so from the very first message.
      //
      // Giving up forward secrecy on history is a real concession — but a messenger whose
      // conversation restarts empty on every reload is not a messenger, and putting this choice
      // behind a settings screen amounted to refusing it for almost everyone. So the trade-off
      // is taken here, stated on the recovery phrase screen (which is also the vault key), and
      // reversible in settings.
      await Archive.open(() => account.vaultKey()),
      new Map(),
      new TrustStore(),
    );

    await session.replenishKeyPackages(KEY_PACKAGE_TARGET);
    await session.persist();
    return session;
  }

  /**
   * Registers a native device from this one, then erases itself.
   *
   * # Why the old device drives
   *
   * It alone is a member of the MLS groups. The new device cannot invite itself: MLS does not
   * catch up a member absent from the tree, a member has to add it. That is exactly what
   * `propagateOwnDevices` does on every poll, with nothing migration-specific about it.
   *
   * # The ordering lives in `migration.ts`
   *
   * Only the means to run it live here. The split is not cosmetic: the sequence is the one place
   * an interruption can damage, and it would not be testable tangled up with MLS, the network
   * and the webview.
   */
  async migrateToNative(
    decision: Decision,
    native: Anchor,
    onProgress?: (step: string) => void,
  ): Promise<Session> {
    // Opened first if it already exists: a resumed migration must not register again — the
    // server declines taken names, so a second registration would create one more device.
    let nextSession = await Session.open(native);

    const steps: Steps = {
      onProgress,
      registerNativeDevice: async () => {
        nextSession = await Session.fromSeed(this.handle, this.account.exportSeed(), native);
        return nextSession.deviceId;
      },
      propagateFromOld: () => this.poll(),
      progress: async () => {
        // The new session polls before being counted: groups do not arrive through the addition
        // itself, but through the Welcomes it has to go and fetch.
        await nextSession?.poll();
        return {
          joined: nextSession?.conversations.size ?? 0,
          expected: this.conversations.size,
        };
      },
      restoreHistory: async () => {
        for (const view of nextSession?.conversations.values() ?? []) {
          // A conversation whose history is missing stays usable: better a migration that
          // completes with an incomplete thread than an account stuck on one unreadable archive
          // entry.
          await nextSession?.hydrate(view).catch((error: unknown) => {
            console.warn("history not restored for one conversation", error);
          });
        }
      },
      revokeOld: (old) => {
        if (!nextSession) throw new Error("migration: no native device to hand over to");
        return nextSession.revokeOwnDevice(old);
      },
      forgetWeb: () => this.forget(),
    };

    await migrate(decision, steps, this.deviceId);

    if (!nextSession) throw new Error("migration: the native device was never registered");
    return nextSession;
  }

  /**
   * Whether a locked session is waiting for a password.
   *
   * Lets the interface ask for it **before** attempting a restore, rather than treating a
   * missing password as a decryption error.
   */
  static async isLocked(): Promise<boolean> {
    const anchor = await currentAnchor();
    const stored = await anchor?.store.load();
    return Boolean(stored?.state && stored.lock);
  }

  /**
   * Reloads the previous session, or `null` if there is none.
   *
   * `password` is required if a lock is set. A wrong password fails the AEAD: there is nothing
   * to compare, so no comparison to make constant-time, and no "password hash" stored alongside
   * offering one more target for an offline attack.
   */
  static async restore(opener?: string | CryptoKey): Promise<Session | null> {
    const anchor = await currentAnchor();
    return anchor === undefined ? null : Session.open(anchor, opener);
  }

  /**
   * Reloads the session kept in a specific anchor.
   *
   * Separate from `restore` for migration, which has to hold **both** sessions open at once: the
   * old one introduces the new one into the groups, and only the old one can — it alone is a
   * member.
   */
  static async open(
    anchor: Anchor,
    /**
     * What opens the lock, if there is one.
     *
     * Two shapes rather than one, because the two paths do not have the same input: a password
     * derives the master key, biometrics hand it over directly. Uniting them behind a string
     * would force encoding a key as text, i.e. pushing it through a format nobody needs.
     */
    opener?: string | CryptoKey,
  ): Promise<Session | null> {
    const stored = await anchor.store.load();
    if (!stored?.state) return null;

    /*
      The migration door, and it is deliberately shaped rather than versioned.

      Accounts used to be named by their handle: the MLS credential carried it, the device id was
      prefixed with it, and `profiles`, `petnames`, `verified` and `knownDevices` were all
      `Record<handle, …>` on disk. They are keyed by account id now, and a state written under the
      old key **does not fail to load** — it loads and comes back empty. Petnames vanish. Worse,
      `verified` comes back empty, which is not a missing feature but a false alarm: every
      correspondent shows as never verified, and the banner that exists to report a substitution
      goes up on accounts that are perfectly legitimate. Once people have learnt to click through
      that banner, it protects nobody.

      So the state is refused rather than reinterpreted, and refused loudly: the caller shows what
      was lost. Somebody whose verifications are gone has to know it in order to redo them.

      **Why the shape and not `VERSION`.** `VERSION` guards the native path only — `storage.ts`
      reads IndexedDB with a plain `get` and compares nothing, and `DB_VERSION` is the schema's,
      not the content's. A version field would work for the *next* migration and does nothing for
      this one, because the states that must be refused are precisely those that have no version
      to read. Absent has to mean old, not unknown. The field is written from now on so the next
      door can be a cheaper one.
    */
    if (stored.account === undefined || !isAccountId(stored.account)) {
      throw new StoredSessionTooOld();
    }

    const lockbox = await Lockbox.open(deviceLock, anchor.cipher, stored, opener);

    const crypto = await loadCrypto();
    const state = await lockbox.cipher.open(stored.state);
    const client = crypto.Client.restore(state, stored.groupIds);
    const account = crypto.AccountKey.fromSeed(await lockbox.cipher.open(stored.accountSeed));
    // The anchor's cipher, not `atRest`: the identity signs the requests, and it does not switch
    // with the lock — the server must see no difference.
    const api = new Api(stored.deviceId, anchor.cipher);

    // Decrypted before the views are built, so each one opens with its thread already in it
    // rather than with an empty list the network fills in a moment later.
    const cached = stored.history
      ? decodeHistory(await lockbox.cipher.open(stored.history))
      : new Map<string, Cached>();

    const conversations = new Map<string, ConversationView>();
    for (const groupId of stored.groupIds) {
      conversations.set(toHex(groupId), {
        groupId,
        key: toHex(groupId),
        messages: cached.get(toHex(groupId))?.messages ?? [],
        peers: client.peerFingerprints(groupId) as Peer[],
        accounts: [],
        epoch: client.epoch(groupId),
        cursor: stored.cursors?.[toHex(groupId)] ?? 0,
        // Sequences already processed are behind the cursor: nothing to remember on reload.
        mine: new Set<number>(),
        // Without this restore, anonymous posting and the typing indicator stay inert until some
        // other member re-shares the key — so possibly never.
        postingKey: stored.postingKeys?.[toHex(groupId)]
          ? fromBase64(stored.postingKeys[toHex(groupId)])
          : undefined,
        ...freshSignalState(),
        // After the spread: `freshSignalState` starts every conversation with an empty outbox,
        // and this is the one part of that state that must not be forgotten between sessions.
        outbox: cached.get(toHex(groupId))?.outbox ?? [],
        // Also after the spread, and for the same reason: what the user has already read is a
        // fact about this screen, not a claim made to anyone, so it belongs across sessions.
        readCursor: cached.get(toHex(groupId))?.readCursor ?? 0,
      });
    }

    const session = new Session(
      stored.deviceId,
      stored.account,
      stored.handle,
      client,
      account,
      crypto,
      api,
      anchor,
      lockbox,
      // Three values, not two, and that is the whole migration story for existing accounts:
      // `false` means the user explicitly turned backup off, and that is to be respected;
      // `undefined` means they never had to decide, so it is treated like a new account, so on.
      // Conflating the two would re-enable the vault behind the back of someone who refused it.
      stored.vaultEnabled === false
        ? Archive.off()
        : await Archive.open(() => account.vaultKey()),
      conversations,
      TrustStore.hydrate(stored),
      // A missing `presence` means enabled: that is the default, the flag only records a refusal.
      { readReceipts: true, typingIndicator: true, ...stored.signals },
      stored.signalsAt,
    );

    // Assigned after construction rather than passed in: the other entry points build a session
    // for an account that has never resolved anyone, so they have no anchor to hand over, and a
    // parameter they would all pass as `undefined` teaches nothing.
    session.settings = PreferencesStore.hydrate(stored);
    session.names = Names.hydrate(stored);
    // Conditional, unlike the two above: absent is what makes the interface fall back to
    // `@handle`, and an empty string present on the field would be a third state nobody handles.

    session.witness = LogWitness.hydrate(stored);

    return session;
  }

  /**
   * Who was last seen when.
   *
   * **Never persisted**, for the same reason as receipts and typing indicators: presence restored
   * across sessions would show as online someone nobody has seen since. It comes back on its own
   * at the first poll — which is why it could leave without `persist` changing at all.
   */
  private readonly presence = new PresenceTracker();

  /**
   * What the user has chosen, and both directions of how it reaches the disk.
   *
   * Replaced wholesale by `open`, hence not `readonly`: `hydrate` is a constructor in all but
   * name, and rebuilding is what keeps the absent-versus-`undefined` rule in one place instead of
   * spread between a default here and a read there.
   */
  private settings = new PreferencesStore();

  /**
   * What people are called, and both directions of how that reaches the disk.
   *
   * Replaced wholesale by `open`, like `settings`: `hydrate` is a constructor in all but name.
   */
  private names = new Names();

  /** Last activity of an account, or `undefined` if the server has nothing to say about it. */
  presenceOf(handle: string): number | undefined {
    return this.presence.lastSeen(handle);
  }

  /** Server clock at the last poll: the reference for judging freshness. */
  get presenceClock(): number {
    return this.presence.clock;
  }

  /** Is the vault on for this account? */
  get archiving(): boolean {
    return this.archive.enabled;
  }

  /**
   * Turns the vault back on after an explicit shutdown.
   *
   * Messages **already exchanged** will not be archived: their MLS keys are destroyed, and
   * nothing can reconstruct them. Archiving resumes now, never retroactively — the interface has
   * to say so, or the user will believe they recovered a past that no longer exists. That holds
   * for the whole period during which they had it off.
   */
  async enableVault(): Promise<void> {
    await this.archive.enable(this.account.vaultKey());
    await this.persist();
  }

  /**
   * Turns the vault off. **Does not erase what is already archived**: the server keeps the
   * entries, and the key that opens them is still derivable from the phrase.
   *
   * Saying so rather than implying an erasure: promising a deletion we do not control — the
   * server may keep copies — would be a security lie.
   */
  async disableVault(): Promise<void> {
    this.archive.disable();
    await this.persist();
  }

  /**
   * Reloads a conversation's archived history.
   *
   * Called on demand rather than at startup: restoring goes over the network and decrypts
   * message by message, which has no business delaying the display.
   */
  async restoreHistory(view: ConversationView): Promise<number> {
    const added = await this.archive.restore(this.api, view.groupId, view.messages);

    view.messages.push(...added);
    touch(view);
    return added.length;
  }

  /**
   * Pulls back the archived history, once per conversation per session.
   *
   * Called when a conversation is opened, not at startup: restoring goes over the network and
   * decrypts entry by entry, which has no business delaying the conversation list. And above all
   * not from the periodic poll, which sweeps **every** conversation every thirty seconds — that
   * would be one round trip per group, forever.
   *
   * # What it does not touch, and why
   *
   * Neither `contentCursor`, nor `readCursor`, nor `receipts`. A restored message was already
   * acknowledged in an earlier session; moving the announced cursor would re-emit a receipt on
   * every reload, and each receipt would breed another. This is the one path by which the loop
   * described in the README can come back to life.
   *
   * Nor `view.cursor`: it belongs to the MLS state, not to the display. The vault says nothing
   * about the ratchet.
   */
  async hydrate(view: ConversationView): Promise<number> {
    if (view.hydrated || !this.archive.enabled) return 0;

    // Set **before** awaiting: two renders in quick succession would otherwise start two
    // concurrent pulls for the same conversation.
    view.hydrated = true;
    return this.restoreHistory(view);
  }

  /** Is a lock set on this device? */
  get locked(): boolean {
    return this.lockbox.engaged;
  }

  /**
   * Sets a lock: the state moves from the IndexedDB key to a derived master key.
   *
   * The switch is a plain `persist()`: the state is re-encrypted under the new key, and the old
   * version is overwritten. The non-extractable key stays in IndexedDB — it still signs HTTP
   * requests — but no longer decrypts anything.
   */
  async enableLock(password: string): Promise<void> {
    await this.lockbox.enable(password);
    await this.persist();
  }

  /**
   * Removes the lock. Requires the current password.
   *
   * Without that requirement, anyone who finds an unlocked device disarms it for good in one
   * click — the lock would only protect until the first forgotten screen.
   */
  async disableLock(password: string): Promise<void> {
    await this.lockbox.disable(password);
    await this.persist();
  }

  /**
   * Hands the master key to the system, behind a fingerprint or a face.
   *
   * # What the user is trading
   *
   * Their password was nowhere; their master key will be somewhere. It is sealed by the native
   * process secrets, themselves in the clear in the app's private directory: the protection
   * becomes the system's and its prompt — solid against someone who picks up the device,
   * worthless against someone who extracts its storage. The interface has to say so first.
   *
   * # Why the password is not asked again
   *
   * It just was: without it, this session would not be open. Asking again would add no proof —
   * someone holding an unlocked device already reads everything — and would charge a security
   * gesture with friction that buys nothing.
   */
  async enableBiometric(): Promise<void> {
    await this.lockbox.enableBiometric();
  }

  /** Removes biometric unlock. The lock stays set, and the password still opens it. */
  async disableBiometric(): Promise<void> {
    await this.lockbox.disableBiometric();
  }

  /**
   * Changes the password without re-encrypting the state.
   *
   * Only the 32 bytes of the master key are re-sealed. The state, which weighs several kilobytes
   * and grows with the conversations, is untouched — so it never goes back through memory in the
   * clear at the most delicate moment.
   */
  async changeLockPassword(current: string, next: string): Promise<void> {
    await this.lockbox.changePassword(current, next);
    await this.persist();
  }

  /**
   * Erases this device's identity.
   *
   * # Why a flag, and not just a `clearSession`
   *
   * Erasure is followed by a page reload, which is not instantaneous. During that window, a poll
   * **already in flight** finishes and calls `persist()` — which writes back to the database the
   * identity we just erased. The reload then finds it intact.
   *
   * The observed symptom: the account creation screen appears, a new identity is created, and on
   * the next reload the old one is back. Nothing reports the failure.
   *
   * This is not a cosmetic defect: the user believes their keys destroyed while they are still
   * there. The flag condemns this instance for good — no write will ever leave it again,
   * whatever operation is still running.
   */
  private forgotten = false;

  async forget(): Promise<void> {
    this.forgotten = true;
    // Cleared in memory as well as on disk. The store is gone, but this instance stays alive for
    // as long as the page does, and `profiles` is the one field here that holds other people's
    // names in the clear — leaving it populated would keep an address book readable by anything
    // still holding the session after the user asked for it to be destroyed.
    this.names.forget();
    await this.anchor.store.clear();
  }

  /** Erases without holding a session — the case of a lock whose password was lost. */
  static async forget(): Promise<void> {
    await clearAll();
  }

  fingerprint(): string {
    return this.client.fingerprint();
  }

  /**
   * Persists the MLS state, encrypted.
   *
   * To be called after **every** operation that moves a group forward. A state persisted late
   * and then restored would roll epochs back and replay keys already used.
   *
   * **The recent thread goes through here too**, sealed by the same cipher as the state. That
   * used not to be true, and `history.ts` argues the change: the plaintext was already being
   * written down, into the server vault under a key that never rotates, and a sealed local copy
   * is the same data somewhere better. Only a window of it is kept — the vault remains the
   * archive, and `hydrate` still fetches what falls outside.
   */
  private async persist(): Promise<void> {
    // See `forget`: a write that won the race against the reload would resurrect an identity the
    // user believes destroyed.
    if (this.forgotten) return;

    // The MLS state and the group list are read here, together, before anything is awaited.
    // `Client.restore` consumes them as a pair, and they used to be read an `await` apart — the
    // list before the first seal, the state after it — so a commit landing in between would have
    // written a state describing groups the list did not mention.
    await this.anchor.store.save(
      await composeStored({
        deviceId: this.deviceId,
        account: this.accountId,
        handle: this.handle,
        accountSeed: this.account.exportSeed(),
        mlsState: this.client.exportState(),
        groupIds: this.client.conversationIds(),
        conversations: this.conversations,
        lock: this.lockbox.snapshot(),
        vault: this.archive.snapshot(),
        trust: this.trust.snapshot(),
        signals: this.signals,
        signalsAt: this.signalsAt,
        preferences: this.settings.snapshot(),
        names: this.names.snapshot(),
        log: this.witness.snapshot(),
        seal: (bytes) => this.lockbox.cipher.seal(bytes),
      }),
    );
  }

  /**
   * Refills the stock if needed.
   *
   * Called on every poll. The operation is idempotent and cheap: one counting request, then a
   * publish only when below the threshold.
   */
  private async replenishKeyPackagesIfLow(): Promise<void> {
    const { remaining } = await this.api.keyPackageStock();
    if (remaining <= KEY_PACKAGE_LOW_WATER) {
      await this.replenishKeyPackages(KEY_PACKAGE_TARGET - remaining);
    }
  }

  private async replenishKeyPackages(count: number): Promise<void> {
    if (count <= 0) return;
    const packages = Array.from({ length: count }, () => this.client.publishKeyPackage());
    await this.api.publishKeyPackages(packages);
  }

  /**
   * Resolves a handle into verified devices.
   *
   * Always goes through `resolveAccount`, which re-checks every attestation. The list comes from
   * the server: without that check, it would only have to slip in a device it controls to read
   * every conversation of the account.
   */
  async resolve(account: string): Promise<ResolvedAccount> {
    const resolved = await resolveAccount(this.api, this.crypto, account);

    // Our own account is where presence is settled, and the only one this field is served for.
    //
    // It is the one signalling setting the sealed announcement cannot carry on its own: a device
    // restored from the recovery phrase has no conversation yet, hence no channel, and would draw
    // the switch in its default position for an account the server already stopped recording. The
    // other two need no such repair — with no conversation there is nobody to emit them to.
    if (account === this.accountId && resolved.presenceOptout !== undefined) {
      const presence = !resolved.presenceOptout;
      if (this.signals.presence !== presence) {
        this.signals = { ...this.signals, presence };
        await this.persist();
      }
    }

    // Attestations prove a device belongs to the account. They say nothing about the ACCOUNT
    // key, which we are discovering here for the first time — that is the hole the log closes.
    if (await this.witness.check(this.checks, account, resolved.identityKey)) {
      await this.persist();
    }
    return resolved;
  }

  /**
   * Shares our view of the log with a peer.
   *
   * # What this adds to the proofs
   *
   * A server can keep **two logs** and serve one to each side. Every victim's proofs verify
   * perfectly: each sees a signed, consistent log. Nothing on the client side alone can detect
   * it.
   *
   * Comparing between two people can — provided it goes over a channel the server does not
   * control. That channel is the conversation itself: it carries the bytes without being able to
   * read or change them.
   *
   * # Why this is sparing
   *
   * One head per conversation per session is enough: the check is about the existence of a fork,
   * not its timing. Emitting one per message would add traffic and detect nothing more.
   */
  private async gossip(view: ConversationView): Promise<void> {
    const seen = this.witness.gossip();
    if (!seen || view.gossiped) return;
    view.gossiped = true;

    await this.sendContent(view, {
      kind: "gossip",
      head: seen,
    });
  }

  /**
   * Confronts a peer's view with ours.
   *
   * We do not compare the roots directly — our two logs have different sizes, and a size
   * difference is normal. We ask the server to **prove** that the log it serves us extends the
   * one it served the other side.
   *
   * If it served two distinct logs, it cannot: no consistency proof links two trees that have
   * forked. This is the only check that catches that case.
   */
  private checkGossip(head: content.GossipHead): Promise<void> {
    return this.witness.compare(this.checks, head);
  }

  /**
   * What it takes to post without identifying ourselves, if we hold the group key.
   *
   * `undefined` falls back to signed posting. That is not a failure: conversations created before
   * sealed sender have no key, and keeping them working beats striking them mute.
   */
  private posting(view: ConversationView): { key: Uint8Array; mac: PostMac } | undefined {
    if (!view.postingKey) return undefined;
    return { key: view.postingKey, mac: this.crypto.postMac };
  }

  /**
   * Same key as [`Session.posting`], **different domain**.
   *
   * The server checks signals under `wac-signal-mac-v1` and posts under `wac-post-v1`: reusing
   * the second for a signal yields a 403 that nothing explains client-side, the request being
   * fired without awaiting its response. The separation exists so that a signal MAC — whose
   * replay is not checked — cannot pass as a posting MAC.
   */
  private signalPosting(
    view: ConversationView,
  ): { key: Uint8Array; mac: PostMac } | undefined {
    if (!view.postingKey) return undefined;
    return { key: view.postingKey, mac: this.crypto.signalMac };
  }

  /**
   * Emits an ephemeral signal over the session, or over HTTP if it is closed.
   *
   * Both paths are **anonymous**: the server checks the same group MAC and learns that a member
   * is typing, never which one. The session only makes the trip cheaper — one frame instead of
   * one request, for an event that fires on every keystroke.
   *
   * The fallback is therefore not a privacy downgrade, and that is what makes it safe to take
   * rather than give the signal up.
   */
  private async emitSignal(
    groupId: Uint8Array,
    payload: Uint8Array,
    posting: { key: Uint8Array; mac: PostMac },
  ): Promise<void> {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const mac = posting.mac(posting.key, groupId, nonce, payload);

    if (this.gateway?.signal(groupId, nonce, mac, payload)) return;

    await this.api.postSignal(groupId, payload, posting);
  }

  /**
   * Passes the posting key to the other members of a group.
   *
   * Emitted once per session per group, by whoever holds it. A member who has not received it yet
   * posts in signed mode in the meantime — less discreet, but working. Doing the opposite,
   * refusing to write until the key arrives, would turn a privacy downgrade into an outage.
   */
  private async sharePostingKey(view: ConversationView): Promise<void> {
    if (!view.postingKey || view.postingKeyShared || view.peers.length === 0) return;
    view.postingKeyShared = true;

    await this.sendContent(view, { kind: "posting-key", key: view.postingKey });
  }

  /**
   * Looks for a conversation whose participants are exactly the ones asked for.
   *
   * Membership is read from the **MLS tree** (`view.peers`), not from a local field: the tree is
   * the authenticated state, and it decides who is a member. A local record would diverge at the
   * first missed removal.
   *
   * We compare sets, not lists: typing order must not produce two different groups. An account
   * with several devices appears several times in the tree, hence the `Set`.
   */
  /**
   * Opens a conversation with one or more accounts, adding **all** of their devices.
   *
   * # Parity
   *
   * A forgotten device is a device that receives nothing: the peer would see the conversation
   * appear on their phone and not on their tablet, with no explanation. Every device of an
   * account has the same access, everywhere — the invariant `addMissingDevices` then maintains
   * on every poll.
   *
   * # Flat or administered
   *
   * With two accounts the conversation is **flat**: admin roles would make no sense there, and a
   * flat group is the correct shape for a 1-to-1. Beyond that, the creator becomes the first
   * admin.
   */
  async startConversation(handles: string | string[]): Promise<ConversationView> {
    // The one boundary where a **handle** enters this class, and the only place the directory is
    // consulted. Everything downstream is an account id: a name is resolved once, here, rather
    // than carried through the protocol where it would have to be re-resolved — and re-resolving
    // is what would let the server change its mind about who somebody is between two calls.
    const named = [...new Set(typeof handles === "string" ? [handles] : handles)];
    const wanted = (await Promise.all(named.map((handle) => Api.resolveHandle(handle)))).filter(
      (account) => account !== this.accountId,
    );
    if (wanted.length === 0) throw new Error("no recipient given.");

    // One conversation per set of people, one group per membership.
    //
    // Without this lookup, retyping the same handle opens a second MLS group with the same
    // members: messages spread across the two depending on which one was selected, and the user
    // concludes messages are being lost. Nothing in the protocol forbids it — it is up to the
    // app to decide that a conversation is identified by its participants.
    const existing = derive.matchingConversation(this.conversations.values(), wanted, this.accountId);
    if (existing) return existing;

    const peers: ResolvedAccount[] = [];
    for (const account of wanted) {
      const peer = await this.resolve(account);

      if (peer.rejected.length > 0) {
        // We refuse to open the conversation rather than quietly drop the intruder. The server
        // served a device it could not have produced: that is the signal we were looking for, and
        // keeping quiet about it would cancel out the whole point of the machinery.
        throw new Error(
          `The server presented ${peer.rejected.length} unattested device(s) for that account. ` +
            "Conversation refused.",
        );
      }
      if (peer.devices.length === 0) {
        throw new Error("That account has no reachable device.");
      }
      peers.push(peer);
    }

    // A group is administered, a 1-to-1 is not. The creator is the first admin; they can appoint
    // others, but never step down alone — the policy refuses to leave a group without an admin,
    // which would freeze it for good.
    const groupId =
      peers.length > 1
        ? this.client.createGroup(this.accountId)
        : this.client.createConversation();

    const invited: string[] = [];
    /** Envelopes we posted ourselves, and must not read back. */
    const emitted = new Set<number>();

    // The group's posting key: it will let every member write without identifying themselves to
    // the server. Generated here, declared to the server at creation, then distributed to the
    // other members **through MLS** — sending it in the clear would amount to asking the server
    // to distribute the means of not talking to it.
    const postingKey = crypto.getRandomValues(new Uint8Array(32));

    for (const device of peers.flatMap((peer) => peer.devices)) {
      const claimed = await this.api.claimKeyPackage(device.id);
      const invitation = this.client.invite(groupId, claimed.package) as Invitation;

      // The server must know the member before any message flows: it is what controls access to
      // the mailbox. The posting key is only accepted on the first call, the one that creates the
      // group.
      await this.api.addMembers(
        groupId,
        [this.deviceId, device.id],
        invited.length === 0 ? postingKey : undefined,
      );

      // Publish the commit BEFORE applying it.
      //
      // Every addition moves the group one epoch forward, and members already present must apply
      // that commit or stay behind. If publishing failed after applying, we would have changed
      // epoch with the commit existing nowhere: the group would die in silence.
      //
      // On the first pass there is nobody to inform, which hides the problem until a peer has two
      // devices.
      if (invited.length > 0) {
        const posted = await this.api.postEnvelope(groupId, envelope.encodeMls(invitation.commit));
        emitted.add(posted.seq);
      }

      // The ratchet tree only exists once the commit is applied: before that it does not contain
      // the new member and its Welcome would be rejected.
      const tree = this.client.applyPending(groupId);
      const welcomed = await this.api.postEnvelope(
        groupId,
        envelope.encodeWelcome(invitation.welcome, tree),
      );
      emitted.add(welcomed.seq);
      invited.push(device.id);
    }

    for (const peer of peers) {
      this.trust.noteDevices(
        peer.handle,
        peer.devices.map((device) => device.id),
      );
    }

    const view: ConversationView = {
      groupId,
      key: toHex(groupId),
      messages: [],
      peers: this.client.peerFingerprints(groupId) as Peer[],
      accounts: peers,
      epoch: this.client.epoch(groupId),
      cursor: 0,
      mine: emitted,
      postingKey,
      ...freshSignalState(),
    };

    this.conversations.set(view.key, view);
    this.syncScope();
    await this.persist();
    return view;
  }

  /**
   * Resolves every peer of a conversation, ourselves excluded.
   *
   * A network failure must not empty the displayed list: we keep what we had rather than make the
   * verification state vanish at the first dropped connection.
   */
  private async resolvePeers(view: ConversationView): Promise<ResolvedAccount[]> {
    const handles = [...new Set(view.peers.map((peer) => peer.name))].filter(
      (account) => account !== this.accountId,
    );

    const resolved: ResolvedAccount[] = [];
    for (const handle of handles) {
      // A failure here must not empty a conversation that is already running, and since this
      // commit it can also be a `LogProofRefused` rather than a network error. The fallback is
      // the same either way, and it is the safe one: the account as it was **last verified**. We
      // do not carry forward whatever the server just failed to prove — we keep what it did
      // prove, earlier. The alert is already raised, and `startConversation` is where the refusal
      // bites.
      try {
        resolved.push(await this.resolve(handle));
      } catch (error) {
        console.warn(`account @${handle} not resolved`, error);
        const previous = view.accounts.find((account) => account.handle === handle);
        if (previous) resolved.push(previous);
      }
    }
    return resolved;
  }

  /**
   * Whether this conversation is an administered group, as opposed to a flat one-to-one.
   *
   * **Not the number of people in it**, which is what five call sites used to ask and is the bug
   * that produced this method: a group of three whose third member is removed still has two, and
   * counting made the interface reclassify it as a one-to-one — no roles, no way to leave, and an
   * "add" button that would have started a *new* conversation instead of growing this one. The
   * group had not become anything; only its size had changed.
   *
   * The distinction is decided once, at creation, and lives in the MLS group context: a group has
   * a roster, a one-to-one does not. That is authenticated state, so it cannot drift with the
   * membership — which is exactly the property the count lacked.
   */
  isGroup(view: ConversationView): boolean {
    return this.roles(view) !== null;
  }

  /**
   * A conversation's roles, or `null` if it is flat (the one-to-one case).
   *
   * The `?? null` is the whole point of this method existing rather than the call being inlined.
   * The binding returns **`undefined`** for a conversation with no roster, and the cast here used
   * to claim it returned `null` — a lie about a boundary, and the kind that costs nothing until
   * somebody writes the obvious guard against it.
   *
   * Two of them did. `isGroup` compares with `!== null` and therefore called every one-to-one a
   * group; `ConversationHeader` guarded `roles !== null` and then read `roles.admin`, which threw
   * and took the whole screen with it. Every other caller happens to write `if (!roles)`, which
   * is why this survived: the two shapes are indistinguishable to a truthiness test and the type
   * said only one of them was possible.
   *
   * Normalised here, once, so that the type is true at the one place that can make it true.
   */
  roles(view: ConversationView): Roles | null {
    return (this.client.roster(view.groupId) as Roles | undefined) ?? null;
  }

  /**
   * Replaces a group's roles.
   *
   * The roster lives in the MLS group context, so in the authenticated state: it is neither
   * replayable nor forgeable on its own. **MLS does not enforce it, though** — clients refuse an
   * unauthorised commit, each on its own. A client applying a different rule would not raise an
   * error but silently fork the group.
   *
   * Passing an `admin` different from the current one **hands the group over**, with no way back.
   */
  async setRoles(view: ConversationView, admin: string, moderators: string[]): Promise<void> {
    const commit = this.client.setRoles(view.groupId, admin, moderators);
    await this.publishAndApply(view, commit);
    this.refreshView(view);
    await this.persist();
  }

  /** Appoints or removes a moderator. Only the admin has that power. */
  async setModerator(view: ConversationView, handle: string, moderator: boolean): Promise<void> {
    const roles = this.roles(view);
    if (!roles) throw new Error("this conversation has no roles.");

    const moderators = roles.moderators.filter((m) => m !== handle);
    if (moderator) moderators.push(handle);

    await this.setRoles(view, roles.admin, moderators);
  }

  /**
   * Removes a whole account from a group, all its devices at once.
   *
   * Parity forces the "all": leaving one device of an evicted account would keep giving it
   * access, and the interface would have lied.
   */
  /**
   * Adds an account, and all of its devices, to a group that already exists.
   *
   * # Why this is short
   *
   * Every cryptographic step here was already being taken on every poll. `addMissingDevices`
   * claims a KeyPackage, builds an `Invitation`, tells the server, publishes the commit and posts
   * the Welcome — it does that whenever a member of an existing conversation appears with a new
   * device, which is the same operation as this one with a different reason for running. What was
   * missing was never the protocol work; it was a caller, the guards, and the two consequences
   * below.
   *
   * # What a new member can read, which is the part to be honest about
   *
   * MLS gives them the group secret from **their own commit onward and nothing before it**. They
   * see what is said after they arrive and cannot decrypt a line of what came before, no matter
   * what the server still holds. That is a property of the ratchet rather than a policy this
   * client enforces, so it cannot be softened by a setting — and it is why the confirmation says
   * it plainly rather than leaving the reader to assume either way.
   *
   * # The posting key, which is the part that would have broken quietly
   *
   * A group's posting key is what lets a member write without identifying themselves to the
   * server. It is distributed *through* MLS, in a message sent once per session by whoever holds
   * it — so a member who joins afterwards never sees that message: it predates their commit, and
   * the paragraph above is exactly why they cannot read it.
   *
   * Left alone, the new member would post in signed mode: working, and a silent downgrade of the
   * one property sealed sender exists to provide. Clearing `postingKeyShared` makes the next poll
   * re-share the key, and this time the new member is in the tree to receive it. The window
   * between the two is the same one a member always has before the key arrives, which the client
   * already handles by falling back to signed posts.
   *
   * # What this does not do
   *
   * It does not ask the person being added. There is no invitation to accept: they are in the
   * group from the commit, and the first they know of it is the conversation appearing. Nothing
   * in the protocol carries a request, and adding one would be a feature of its own.
   */
  async addAccount(view: ConversationView, handle: string): Promise<void> {
    // The second and last boundary where a handle enters this class — `startConversation` is the
    // other. Resolved once, here, and everything past this line is an account id.
    const account = await Api.resolveHandle(handle);

    if (account === this.accountId) throw new Error("You are already in this conversation.");
    if (view.accounts.some((member) => member.handle === account)) {
      throw new Error(`@${handle} is already in this conversation.`);
    }

    // A one-to-one has no roles and no admin: turning one into a group by adding a third person
    // would leave a conversation nobody administers, which the policy treats as frozen. Starting
    // a new conversation with all three is the operation that exists for that.
    if (this.roles(view) === null) {
      throw new Error("This conversation cannot take new members. Start a new one instead.");
    }

    const peer = await this.resolve(account);

    // The same refusal `startConversation` makes, for the same reason: the server served a device
    // it could not have produced. Quietly dropping the intruder and adding the rest would cancel
    // out the machinery that caught it.
    if (peer.rejected.length > 0) {
      throw new Error(
        `The server presented ${peer.rejected.length} unattested device(s) for @${handle}. ` +
          "Not added.",
      );
    }
    if (peer.devices.length === 0) throw new Error(`@${handle} has no reachable device.`);

    for (const device of peer.devices) {
      const claimed = await this.api.claimKeyPackage(device.id);
      const invitation = this.client.invite(view.groupId, claimed.package) as Invitation;

      await this.api.addMembers(view.groupId, [device.id]);

      // Publish before applying, as everywhere else: a commit that exists nowhere while we have
      // already moved epoch would leave the group behind us with no way to catch up.
      const tree = await this.publishAndApply(view, invitation.commit);

      const welcomed = await this.api.postEnvelope(
        view.groupId,
        envelope.encodeWelcome(invitation.welcome, tree),
      );
      view.mine.add(welcomed.seq);
    }

    // See the note above: without this the new member writes in signed mode for as long as this
    // session lasts, and nothing anywhere says so.
    view.postingKeyShared = false;

    this.trust.noteDevices(
        peer.handle,
        peer.devices.map((device) => device.id),
      );
    view.accounts = [...view.accounts, peer];
    this.refreshView(view);
    await this.persist();

    // Announced after the commit, deliberately: sent before, it would predate the new member's
    // own arrival in the tree and be the one line about them they could not read.
    await this.announce(view, "joined", handle);
  }

  /**
   * Says in the thread that the membership changed.
   *
   * Failure is swallowed. The change has already happened — the commit is out, the tree has
   * moved — and throwing here would report a *failed removal* to somebody whose removal
   * succeeded, which is a worse lie than a missing line. The line is a courtesy to the reader;
   * the roster is the record.
   */
  private async announce(
    view: ConversationView,
    event: MembershipEvent,
    handle: string,
  ): Promise<void> {
    try {
      await this.sendContent(view, { kind: "membership", event, handle });
    } catch (error) {
      console.warn(`membership notice not sent (${event} ${handle})`, error);
    }
  }

  async removeAccount(view: ConversationView, handle: string): Promise<void> {
    const account = view.accounts.find((candidate) => candidate.handle === handle);
    if (!account) throw new Error(`@${handle} is not in this conversation.`);

    for (const device of account.devices) {
      const commit = this.client.removeMember(view.groupId, device.mlsKey);
      await this.publishAndApply(view, commit);
      await this.api.removeGroupMembers(view.groupId, [device.id]);
    }

    view.accounts = view.accounts.filter((candidate) => candidate.handle !== handle);
    this.refreshView(view);
    await this.persist();

    // The people still here are the audience: whoever was removed is out of the tree by now and
    // will not receive this, which is the right outcome — they were not told twice, and the room
    // that is left knows what happened to it.
    await this.announce(view, "removed", handle);
  }

  /**
   * Picks the successor of a departing admin.
   *
   * # The constraint that dictates the rule
   *
   * Succession must be computable **identically by every client**. Two clients picking different
   * successors would not raise an error: they would install two incompatible rosters and the
   * group would silently fork.
   *
   * Hence the MLS tree order, the only chronology everyone shares without exchanging anything.
   *
   * # The approximation, and why it is accepted
   *
   * MLS **reuses freed leaves**: a late arrival can inherit a departed member's slot and end up
   * first. Tree order therefore approximates seniority without reproducing it. Real seniority
   * would require tracking arrival order in the roster and updating it on every addition — one
   * more commit per join. The choice here favours determinism, which is what guards against
   * forks.
   */
  /**
   * Asks to leave a group.
   *
   * # Leaving is a request, not a fact
   *
   * RFC 9420 forbids removing yourself in a commit you generate: it is signed under the secret of
   * the epoch it produces, precisely the one you have just been excluded from. Another member has
   * to pick the proposal up.
   *
   * A consequence to display honestly rather than hide: **until another member has committed, the
   * departure has not happened.** Making the conversation disappear from the screen would suggest
   * otherwise to someone who is still being read.
   *
   * # Handing over admin, before leaving
   *
   * A group without an admin is frozen: nobody can add, remove, or even appoint an admin, the
   * extension itself being under their control. So the policy refuses to remove the last admin.
   *
   * The transfer happens **before** the leave request, and by us: we are still admin, so still
   * allowed to change the roster. Doing it afterwards would be impossible, and doing it in the
   * same commit would ask the successor to validate a succession rule rather than a roster — more
   * surface to diverge on, for no gain.
   */
  async requestLeave(view: ConversationView): Promise<void> {
    const roles = this.roles(view);

    if (roles !== null && roles.admin === this.accountId) {
      const heir = derive.successorOf(view, roles, this.accountId);
      if (heir === null) {
        throw new Error(
          "You are the admin and the last member: leaving means deleting the conversation.",
        );
      }

      // The successor is promoted to admin and leaves the moderator list: they are above it now,
      // and leaving them there would make the roster ambiguous.
      await this.setRoles(
        view,
        heir,
        roles.moderators.filter((m) => m !== heir),
      );
    }

    // Before the proposal, and that ordering is the whole reason this works: leaving is a
    // request another member commits, so between the proposal and the commit we are still in the
    // group — but only just, and a client that committed quickly would take our ability to write
    // with it. Said first, the line is always sent by somebody who is still a member.
    await this.announce(view, "left", this.accountId);

    const proposal = this.client.leaveGroup(view.groupId);
    const posted = await this.api.postEnvelope(view.groupId, envelope.encodeMls(proposal));
    view.mine.add(posted.seq);
    await this.persist();
  }

  /**
   * Deletes the conversations we are the last member of.
   *
   * A group with a single member is no longer a conversation: it is an MLS group nobody will ever
   * read, which would nonetheless keep showing up in the list, being polled and accepting
   * messages. Leaving it would promise someone on the other end who no longer exists.
   *
   * The deletion is **local**. The server keeps the mailbox: nothing would prove it actually
   * erased it, and claiming so would be worse than saying nothing. Our envelopes stay there,
   * encrypted under keys nobody holds any more.
   */
  private async dropEmptyConversations(): Promise<void> {
    let removed = 0;

    for (const [key, view] of this.conversations) {
      if (view.peers.length > 0) continue;

      await this.api.removeGroupMembers(view.groupId, [this.deviceId]).catch(() => {
        // Removing ourselves from the delivery list is a nicety: the conversation disappears on
        // our side either way.
      });
      this.conversations.delete(key);
      removed += 1;
    }

    if (removed > 0) await this.persist();
  }

  /**
   * Revokes one of our devices: signed certificate, then MLS removal from every group.
   *
   * # What this protects against, and what it does not
   *
   * Against a **lost or dead** device, it is the right answer: it stops receiving, and the removal
   * commit re-keys the tree, so it decrypts nothing further.
   *
   * Against a **stolen** device, it is not enough. Every device of an account holds the seed —
   * that is the condition of their parity — so the thief holds the account and attests a new
   * device moments later. The only answer is [`Session.rotateAccount`].
   */
  async revokeOwnDevice(deviceId: string): Promise<void> {
    if (deviceId === this.deviceId) {
      throw new Error("a device cannot revoke itself: revoke it from another one.");
    }

    const revokedAt = Math.floor(Date.now() / 1000);
    const certificate = this.account.revoke(this.accountId, deviceId, BigInt(revokedAt));

    await this.api.revokeDevice(deviceId, certificate, revokedAt);

    // Removal from the groups follows at the next poll: `reconcileMembers` will do it by reading
    // the certificate we just posted, exactly as any other member would. Going through the same
    // path rather than a shortcut guarantees that path really is exercised.
    await this.poll();
  }

  /**
   * Changes the account identity key. **The only real answer to a stolen device.**
   *
   * # Why revocation is not enough
   *
   * Every device holds the account seed: that is what gives them all the same rights, with no
   * hierarchy and no "main" device. The flip side is that a stolen device holds the whole
   * account. Revoking it does not stop it from attesting a new one a second later.
   *
   * # What rotation does, almost for free
   *
   * Changing the key makes **every existing attestation unverifiable** at once, since each client
   * recomputes them against the account's current key. Total revocation is not a separate
   * mechanism: it is a consequence. This device re-attests itself immediately; the others,
   * legitimate ones, will have to be re-paired by QR.
   *
   * # The three prices, to be announced before and not after
   *
   * The account fingerprint changes, so every peer sees the identity-change warning. It is
   * **correct**: the key really did change. And the thief holds the same key we do — they can
   * rotate first. The server cannot tell them apart and applies the first valid rotation it gets.
   *
   * The third arrived with the vault-by-default: its key derives from the recovery phrase, so
   * **all the already archived history becomes permanently unreadable**. While the vault was
   * optional, whoever rotated their key knew they had one; that is no longer true, and the
   * interface has to say so before offering the button.
   *
   * Returns the new recovery phrase. The old one is worthless.
   */
  async rotateAccount(): Promise<string> {
    const created = this.crypto.AccountKey.generate() as CreatedAccount;
    const rotatedAt = Math.floor(Date.now() / 1000);

    // Signed by the OLD key: it is the one that names its replacement. Without that continuity,
    // anyone could take over someone else's handle.
    const signature = this.account.rotate(this.accountId, created.identityKey, BigInt(rotatedAt));

    await this.api.rotateAccount(this.accountId, created.identityKey, signature, rotatedAt);

    this.account = this.crypto.AccountKey.restore(created.phrase);

    // Immediate re-attestation. Without it, this device would be rejected by every client —
    // including by ourselves at the next poll — since its attestation carries the signature of a
    // dead key.
    const authKey = await this.anchor.cipher.authPublicKey();
    const mlsKey = this.client.signatureKey();
    await Api.register(
      this.deviceId,
      this.accountId,
      authKey,
      mlsKey,
      this.account.attest(this.accountId, this.deviceId, authKey, mlsKey),
    );

    // The vault is encrypted under a key derived from the old seed: the entries already stored
    // become unreadable, permanently. Saying so beats letting someone discover an empty history.
    if (this.archive.enabled) {
      await this.archive.enable(this.account.vaultKey());
    }

    await this.persist();
    return created.phrase;
  }

  /**
   * Pairs a new device from the code shown on its screen.
   *
   * Seals the account seed under the X25519 secret and deposits it. Without it, the new device
   * could neither attest itself nor attest the next ones — it would stay subordinate to this one,
   * which is fragile for an account meant to outlive its devices.
   *
   * Returns the confirmation code, to be compared with the one shown on the other side.
   */
  async pairDevice(code: string): Promise<string> {
    const offer: PairingCode = decodePairingCode(code);

    const sealed = this.crypto.sealPairing(
      offer.publicKey,
      offer.id,
      this.account.exportSeed(),
    ) as Sealed;

    await this.api.depositPairing(offer.id, sealed.payload);
    return sealed.confirmation;
  }

  /**
   * Adds our other devices to every ongoing conversation.
   *
   * Called on every poll, and **idempotent** by construction: MLS does not catch up a member
   * absent from the tree, and a device that was paired but never added would see its conversation
   * list without being able to decrypt a single line. The originating device may close mid-way
   * through the propagation; there is no reason to leave a conversation orphaned until someone
   * thinks of it again.
   */
  private async propagateOwnDevices(): Promise<void> {
    if (this.conversations.size === 0) return;

    const mine = await this.resolve(this.accountId);
    const others = mine.devices.filter((device) => device.id !== this.deviceId);
    if (others.length === 0) return;

    for (const view of this.conversations.values()) {
      await this.addMissingDevices(view, others);
      this.refreshView(view);
    }

    await this.persist();
  }

  /**
   * Adds to a conversation the devices that should be in it and are not.
   *
   * # The parity invariant
   *
   * Every device of an account has the same access everywhere. A device missing from a
   * conversation is not "behind": it is broken. It sees the conversation in its list and decrypts
   * not one line of it, with no error to say why — MLS does not catch up a member absent from the
   * tree.
   *
   * Hence a reconciliation on every poll, **idempotent**: it compares the tree with the verified
   * device list and closes the gap. The originating device may close mid-way; the next poll picks
   * up where it left off.
   */
  private async addMissingDevices(
    view: ConversationView,
    devices: AttestedDevice[],
  ): Promise<void> {
    // The MLS tree is the truth about who is a member. Relying on a local record would diverge at
    // the first network failure.
    const present = new Set(view.peers.map((peer) => peer.fingerprint));

    for (const device of devices) {
      if (present.has(this.crypto.accountFingerprint(device.mlsKey))) continue;

      try {
        const claimed = await this.api.claimKeyPackage(device.id);
        const invitation = this.client.invite(view.groupId, claimed.package) as Invitation;

        await this.api.addMembers(view.groupId, [device.id]);

        const tree = await this.publishAndApply(view, invitation.commit);

        const welcomed = await this.api.postEnvelope(
          view.groupId,
          envelope.encodeWelcome(invitation.welcome, tree),
        );
        view.mine.add(welcomed.seq);
      } catch (error) {
        // KeyPackage stock exhausted, or device already a member: we retry at the next poll rather
        // than abort the whole reconciliation.
        console.warn(`adding ${device.id} deferred`, error);
      }
    }
  }

  /**
   * Evicts from the tree the devices whose revocation has been verified.
   *
   * # Why the server does not do it
   *
   * The server does stop serving envelopes to a revoked device, but that filter takes **nothing**
   * away from it: it holds the group secrets and would decrypt anything it obtained by another
   * route. Only the removal commit re-keys the tree. That is post-compromise security, and it
   * starts at the commit, not at the revocation.
   *
   * # Why any member can do it
   *
   * The certificate is verifiable by everyone. Reserving eviction to admins would leave a
   * non-admin's stolen device in the group until an admin came back online — exactly the delay
   * revocation exists to remove.
   *
   * # What this does not solve
   *
   * A stolen device holds the account seed, so it can attest itself a new one. Removal only helps
   * against loss; against theft, the only answer is [`Session.rotateAccount`].
   */
  private async reconcileMembers(): Promise<void> {
    for (const view of this.conversations.values()) {
      // Every verified revocation, across all accounts — ours included.
      const revoked = new Map<string, string>();
      for (const account of [...view.accounts, await this.resolve(this.accountId)]) {
        for (const device of account.revoked) {
          revoked.set(this.crypto.accountFingerprint(device.mlsKey), device.id);
        }
      }
      if (revoked.size === 0) continue;

      const keys = this.client.peerSignatureKeys(view.groupId) as Uint8Array[];

      for (const key of keys) {
        const deviceId = revoked.get(this.crypto.accountFingerprint(key));
        if (deviceId === undefined) continue;

        try {
          const commit = this.client.removeMember(view.groupId, key);
          await this.publishAndApply(view, commit);
          await this.api.removeGroupMembers(view.groupId, [deviceId]);
        } catch (error) {
          // Another member may have beaten us to it: the device is then out of the tree and the
          // intended state is reached. Otherwise we retry on the next pass.
          console.warn(`eviction of ${deviceId} deferred`, error);
        }
      }

      this.refreshView(view);
    }

    await this.persist();
  }

  /**
   * Publishes a commit **then** applies it, and returns the up-to-date ratchet tree.
   *
   * The order is not a style detail. Applying before publishing is unrecoverable: if publishing
   * fails, we have changed epoch while the others stay behind, and the commit that would have
   * reconciled them exists nowhere. The group dies in silence — nobody decrypts, and nothing says
   * why.
   *
   * This helper exists so there is only one place where that order can be inverted.
   */
  private async publishAndApply(view: ConversationView, commit: Uint8Array): Promise<Uint8Array> {
    const posted = await this.api.postEnvelope(view.groupId, envelope.encodeMls(commit));

    // Already applied locally: we note it so as not to read it back, without moving the cursor
    // past it — the envelopes in between still have to be processed.
    view.mine.add(posted.seq);

    return this.client.applyPending(view.groupId);
  }

  /** Resynchronises the displayed view with the real group state. */
  private refreshView(view: ConversationView): void {
    view.peers = this.client.peerFingerprints(view.groupId) as Peer[];
    view.epoch = this.client.epoch(view.groupId);
  }

  /**
   * Reports the devices that have appeared on a peer's account since last time.
   *
   * It is **this notification, not the fingerprint, that detects a hostile device**. The
   * fingerprint covers the account key and stays deliberately stable: making it change on every
   * added device would force a re-verification after every legitimate event, and would be ignored
   * within weeks.
   *
   * What this does not cover: a device added by a genuinely compromised account. It is duly
   * attested, so indistinguishable from a legitimate addition. Only the user can say whether they
   * actually own that device — hence the display, rather than an automatic verdict.
   */
  async newDevicesOf(handle: string): Promise<string[]> {
    const peer = await this.resolve(handle);
    const fresh = this.trust.newDevicesIn(
      handle,
      peer.devices.map((device) => device.id),
    );

    if (fresh.length > 0) await this.persist();
    return fresh;
  }

  /**
   * Sends a message, showing it before the server has agreed to it.
   *
   * # Why the bubble appears first
   *
   * It used to appear last: the field emptied, the request went out, and the text existed nowhere
   * until the answer came back. On a slow network that was a message the user had written and
   * could no longer see; on a failure it was a red banner at the bottom of the application and
   * the text gone for good.
   *
   * # Why this cannot throw
   *
   * A failure is now a state of the message, not an exception at the call site. The composer has
   * nothing left to do about it — the text is safe in the outbox, the bubble says it did not go,
   * and the retry belongs next to the bubble rather than in a banner that names no message.
   */
  async send(view: ConversationView, text: string): Promise<void> {
    const entry: Pending = {
      // `randomUUID` rather than a counter: the outbox survives a reload, and a counter restarting
      // at zero would collide with what is already in it.
      localId: crypto.randomUUID(),
      text: this.address(view, text),
      sentAt: Date.now(),
      state: "sending",
    };

    view.outbox.push(entry);
    touch(view);
    await this.persist();
    await this.flush(view, entry);
  }

  /**
   * Tries one queued message.
   *
   * The stamp is the one taken when it was written, not now: a message composed offline and sent
   * twenty minutes later was written twenty minutes ago, and dating it to the moment the network
   * came back would misreport the only thing the stamp is for.
   */
  private async flush(view: ConversationView, entry: Pending): Promise<void> {
    entry.state = "sending";
    touch(view);

    try {
      await this.sendContent(view, { kind: "text", text: entry.text }, entry.sentAt);
      view.outbox = view.outbox.filter((queued) => queued.localId !== entry.localId);
    } catch (error) {
      entry.state = "failed";
      console.warn("message not sent", error);
    }

    touch(view);

    await this.persist();
  }

  /** Retries one message the user asked to send again. */
  async retry(view: ConversationView, localId: string): Promise<void> {
    const entry = view.outbox.find((queued) => queued.localId === localId);
    if (entry) await this.flush(view, entry);
  }

  /** Drops one, when the user would rather rewrite it than send it. */
  async discard(view: ConversationView, localId: string): Promise<void> {
    view.outbox = view.outbox.filter((queued) => queued.localId !== localId);
    touch(view);
    await this.persist();
  }

  /**
   * Retries everything queued, in order.
   *
   * Called when the network comes back rather than on a timer: retrying on a schedule would keep
   * hammering a server that is down, and the events that matter — a reconnection, a resume — are
   * already reported by `lifecycle.ts`.
   *
   * Serially, and stopping at the first failure: the order of a conversation is the order it was
   * written in, and pushing on past a failure would let the second message overtake the first.
   */
  async flushOutbox(): Promise<void> {
    for (const view of this.conversations.values()) {
      for (const entry of [...view.outbox]) {
        await this.flush(view, entry);
        if (entry.state === "failed") break;
      }
    }
  }

  /**
   * Encrypts the file, uploads it, then sends its descriptor in an MLS message.
   *
   * Order matters: the attachment must exist on the server before the message referencing it
   * leaves, otherwise the recipient gets a link to a missing file.
   */
  async sendAttachment(view: ConversationView, file: File): Promise<void> {
    const ref = await encryptAndUpload(this.api, view.groupId, file);
    await this.sendContent(view, { kind: "attachment", ref });
  }

  /** Fetches and decrypts a received attachment. */
  openAttachment(view: ConversationView, ref: AttachmentRef): Promise<Blob> {
    return downloadAndDecrypt(this.api, view.groupId, ref);
  }

  /**
   * Marks the conversation as seen up to its last message.
   *
   * Called by the display, not by the poll: "read" means what a person has had in front of them.
   * The receipt itself goes out on the next pass, with the others.
   */
  markRead(view: ConversationView): void {
    const advanced = view.contentCursor > view.readCursor;
    view.readCursor = Math.max(view.readCursor, view.contentCursor);

    // Written only when it moves. This runs on every render of an open thread and on every tab
    // focus; persisting each time would re-seal the whole state for a number that did not change.
    if (advanced) void this.persist();
  }

  /**
   * How many messages have arrived in this conversation since the user last looked.
   *
   * Counted from the thread rather than from the difference between two cursors, because the
   * cursors advance on **envelopes** and a run of receipts would otherwise read as unread
   * messages. Our own are excluded: nobody is behind on what they wrote themselves.
   */
  unreadIn(view: ConversationView): number {
    return derive.unreadIn(view);
  }

  /**
   * When this conversation last had something in it, for ordering the list.
   *
   * The declared stamp when there is one, and `0` otherwise — an older thread with no stamps
   * sinks rather than floating to the top on a value invented for it. A queued message counts:
   * the conversation you just wrote in is the one you are in.
   */
  lastActivityIn(view: ConversationView): number {
    return derive.lastActivityIn(view);
  }

  /** State to show on a message we sent: sent, delivered, read. */
  statusOf(view: ConversationView, seq: number): "sent" | "delivered" | "read" {
    return derive.deliveryStatus(view, seq, this.accountId, this.signals.readReceipts);
  }

  /** Peers currently typing, expired ones excluded — and nobody at all when we do not emit. */
  typingIn(view: ConversationView): string[] {
    view.typing = fresh(view.typing, Date.now());
    return showing(view.typing, this.accountId, this.signals.typingIndicator);
  }

  /**
   * Signals that we are typing.
   *
   * # What does not happen here
   *
   * Nothing is stored, neither by us nor by the server. The signal is encrypted under the group's
   * epoch key, posted without a device signature, relayed to connected members, then forgotten.
   * That is the point of the separate channel: an envelope survives thirty days at minimum and
   * indefinitely in a conversation shorter than five hundred messages, so routing keystrokes
   * through it would keep a record of who hesitated for as long as the conversation lasts.
   *
   * # What the server learns anyway
   *
   * That a post is happening towards this group. With two people, it infers that one of the two is
   * typing. Sealed sender hides *who*, not *that* — only the setting truly removes it.
   */
  async notifyTyping(view: ConversationView): Promise<void> {
    if (!this.signals.typingIndicator) return;

    const posting = this.signalPosting(view);
    // Without a posting key we would have to sign the request: the server would learn who is
    // typing, in real time, for a comfort feature. We abstain instead.
    if (!posting) return;

    const now = Date.now();
    if (view.typingSentAt !== undefined && now - view.typingSentAt < TYPING_DEBOUNCE_MS) {
      return;
    }
    view.typingSentAt = now;

    const key = this.client.signalKey(view.groupId);
    const payload = await sealTyping(key, this.accountId);
    await this.emitSignal(view.groupId, payload, posting);
  }

  /**
   * Opens a signal received over the real-time stream.
   *
   * An unreadable signal is the ordinary case — it was emitted under the previous epoch and
   * arrived after the commit — and so is not surfaced as an error.
   */
  async absorbSignal(groupId: Uint8Array, payload: Uint8Array): Promise<void> {
    const view = this.conversations.get(toHex(groupId));
    if (!view) return;

    // The setting cuts reception as well as emission, and it cuts it here rather than only at
    // display: an indicator nobody will ever be shown has no business being recorded, and the
    // shortest path to never showing it is never keeping it. `signals.showing` refuses it a
    // second time, deliberately — the reciprocity has to hold even if one of the two is
    // forgotten, which is the arrangement `acknowledge` and `statusOf` already use for receipts.
    if (!this.signals.typingIndicator) return;

    const account = await openTyping(this.client.signalKey(view.groupId), payload);
    if (account === undefined || account === this.accountId) return;

    const now = Date.now();
    view.typing = [...without(fresh(view.typing, now), account), { account, at: now }];
  }

  /**
   * Reacts to a message, or removes the reaction with an empty emoji.
   *
   * Unlike receipts, a reaction **is** a message: it is displayed, it is archived, and its author
   * owns it. That is why it does not go through `isControl`.
   */
  reactTo(view: ConversationView, target: number, emoji: string): Promise<void> {
    return this.sendContent(view, { kind: "reaction", target, emoji });
  }

  /** Replies by quoting an earlier message. */
  replyTo(view: ConversationView, target: number, text: string): Promise<void> {
    return this.sendContent(view, { kind: "reply", target, text: this.address(view, text) });
  }

  /**
   * Turns the handles a writer typed into the accounts they meant.
   *
   * # Why here and not in the composer
   *
   * The field holds a handle because that is what a person can read: an id is thirty-two
   * hexadecimal characters, and a `<textarea>` has no way to draw one as anything else. The wire
   * has to hold the id, because a handle can be renamed and a mention carrying a renameable thing
   * is orphaned by the next rename — the same argument `lib/mention.ts` makes against carrying a
   * display name, one level down. So the substitution happens once, at the boundary between the
   * two, which is this line.
   *
   * The directory is **this conversation's members**, never the server's. A handle naming nobody
   * in the room stays exactly as typed: it addresses somebody who will never read it, and
   * inventing an id for them would be worse than leaving prose.
   *
   * It runs on the queued text rather than at flush, so the pending bubble already shows the
   * mention resolved. A message that looked different before and after the server acknowledged it
   * would read as the app having second thoughts.
   */
  private address(view: ConversationView, text: string): string {
    const members = new Set([...view.accounts.map((a) => a.handle), ...view.peers.map((p) => p.name)]);
    const claimed = this.names.handles;

    const directory = new Map<string, string>();
    for (const account of members) {
      const handle = claimed[account];
      if (handle !== undefined) directory.set(handle, account);
    }
    // Our own handle is in the directory too. Addressing yourself is ordinary — a note, a
    // correction — and leaving it out would make one name in every room behave unlike the others.
    directory.set(this.handle, this.accountId);

    return mention.resolve(text, directory);
  }

  /**
   * Records that an emoji was just used, so the picker can offer it first next time.
   *
   * The tone is stripped before storing: what is remembered is the emoji, and the tone is a
   * separate preference applied on the way out. Without that, choosing a tone once fills the list
   * with five variants of the same thumb and pushes everything else off it.
   *
   * Twenty-four is two rows of twelve at the width the picker uses. A longer list is not a longer
   * memory, it is a second grid nobody scrolls.
   */
  async noteEmojiUse(emoji: string): Promise<void> {
    if (this.settings.noteEmoji(emoji)) await this.persist();
  }

  /** Signalling settings, as they apply right now. */
  signalSettings(): SignalSettings {
    return { ...this.signals };
  }

  /**
   * Changes a signalling setting.
   *
   * Turning read receipts off also stops showing other people's: seeing without being seen would
   * be exactly what the setting claims to prevent.
   *
   * Presence is the only one of these settings that must **reach the server**: it alone can stop
   * recording. A setting that merely stopped displaying would let the register fill up anyway,
   * which is not what the user asked for.
   */
  async setSignalSetting<K extends keyof SignalSettings>(
    key: K,
    value: SignalSettings[K],
  ): Promise<void> {
    if (key === "presence") {
      await this.api.setPresenceOptout(!value);
      // What the server has just erased must not stay on screen until the next poll.
      this.presence.clear();
    }

    this.signals[key] = value;
    this.signalsAt = Date.now();
    await this.persist();

    // Told to our other devices immediately, rather than waiting for the next epoch of each
    // conversation. An epoch can sit still for days in a quiet room, and a setting that takes
    // days to reach the phone in your pocket is one the phone spends those days contradicting.
    await this.announceSignalsEverywhere();
  }

  /**
   * Tells our own devices the settings, in every conversation.
   *
   * # Why every conversation and not one
   *
   * There is no group that holds an account's devices and nothing else. They meet inside the
   * conversations they share with other people — see `propagateOwnDevices` and the parity
   * invariant it states — so "everywhere" is the only address available. A device that is in one
   * conversation and not another does not exist; that is what parity means.
   *
   * # Why failure is swallowed
   *
   * The setting has already been applied and persisted locally when this runs. A conversation
   * whose send fails is one whose other devices learn at the next epoch instead, which is the
   * path they were on before this method existed. Letting the rejection through would report a
   * network error for a switch that did move, on the device that moved it.
   */
  private async announceSignalsEverywhere(): Promise<void> {
    for (const view of this.conversations.values()) {
      try {
        await this.emitSignals(view);
      } catch (error) {
        console.warn("settings announcement deferred", error);
      }
    }
  }

  /**
   * Posts the settings to one conversation, sealed for our own devices.
   *
   * Silent in a room we are alone in: `peers` is every member of the tree except this device, so
   * an empty one means there is no other device of ours to tell and no peer to carry the message
   * for us. It costs an envelope and reaches nobody.
   */
  private async emitSignals(view: ConversationView): Promise<void> {
    if (view.peers.length === 0) return;

    const signals: SyncedSignals = {
      readReceipts: this.signals.readReceipts,
      typingIndicator: this.signals.typingIndicator,
      // Absent means enabled, here as everywhere else: the flag only ever records a refusal.
      presence: this.signals.presence !== false,
      at: this.signalsAt ?? Date.now(),
    };

    const sealed = await sealSignals(await this.deviceSyncKey(), signals);
    await this.sendContent(view, { kind: "signals", sealed });
  }

  /** The key our own devices share, imported once and kept. */
  private async deviceSyncKey(): Promise<CryptoKey> {
    this.syncKey ??= await importSyncKey(this.account.deviceSyncKey());
    return this.syncKey;
  }

  /**
   * Applies settings announced by another of our devices.
   *
   * Last writer wins on the **clamped** time, exactly as a profile does. The comparison is `>`
   * and not `>=`: an announcement carrying the stamp we already hold is the periodic re-send of
   * a state we agree on, and rewriting it would persist the session on every epoch of every
   * conversation for no change.
   *
   * `presence` is applied to the local flag only. The server holds the truth for it — the column
   * is what stops the recording — so this keeps the switch on this device honest about a decision
   * taken elsewhere, and changes nothing about what is recorded.
   */
  private async absorbSignals(sealed: Uint8Array): Promise<void> {
    const opened = await openSignals(await this.deviceSyncKey(), sealed, Date.now());
    // Not ours to read, or a shape a later build of ours writes. Both are ordinary.
    if (opened === null) return;
    if (this.signalsAt !== undefined && opened.at <= this.signalsAt) return;

    this.signals = {
      readReceipts: opened.readReceipts,
      typingIndicator: opened.typingIndicator,
      presence: opened.presence,
    };
    this.signalsAt = opened.at;
    await this.persist();
  }

  private async sendContent(
    view: ConversationView,
    body: content.Content,
    /**
     * When it was written, if that is not now.
     *
     * Passed in for a queued message: one composed offline and sent twenty minutes later was
     * written twenty minutes ago. Defaulted otherwise — this device's clock is the only one
     * available, the server's is deliberately not asked for, and a clock that is wrong here shows
     * as wrong to the recipient rather than being silently corrected. `encode` drops the stamp for
     * control traffic on its own.
     */
    writtenAt?: number,
  ): Promise<void> {
    const sentAt = writtenAt ?? Date.now();

    // Padded **before** encryption: it is the plaintext size that determines the ciphertext size.
    // Padding afterwards would hide nothing more and cost as much.
    const encoded = padding.pad(content.encode(body, sentAt));

    const ciphertext = this.client.encrypt(view.groupId, encoded);
    const { seq } = await this.api.postEnvelope(
      view.groupId,
      envelope.encodeMls(ciphertext),
      this.posting(view),
    );

    // We note the sequence so as not to try reading it back, without touching the cursor: the
    // envelopes posted in the meantime by others still have to be processed.
    view.mine.add(seq);

    // The throttle resets: after a send, the next keystroke opens a new message and must be
    // announced right away. Leaving it under the threshold would make the peer wait up to a second
    // and a half before seeing that we are answering again.
    view.typingSentAt = undefined;

    // Protocol traffic joins neither the thread nor the vault. It rides the same encrypted channel
    // as messages — that is the whole point — but it is not a conversation.
    if (content.isControl(body)) {
      await this.persist();
      return;
    }

    const message: Message = { seq, sender: this.deviceId, content: body, mine: true, sentAt };
    view.messages.push(message);
    touch(view);
    // Same order as the poll, for the same reason: the write goes first, and the upload after.
    // See `pollOnce`.
    await this.persist();
    await this.archive.store(this.api, view.groupId, [message]);
  }

  /**
   * Polls for new messages and joins the conversations we have been added to.
   *
   * The polling is deliberately simple. A real client would use a WebSocket or push — which would
   * change nothing about the cryptography, only latency and battery.
   */
  /**
   * Opens the real-time stream, and keeps it up.
   *
   * # What this does not change
   *
   * Correctness. The stream only triggers earlier a poll that would have happened anyway. A
   * browser that blocks the connection, a proxy that cuts it, a server that refuses it: the app
   * keeps working, simply at the pace of the periodic poll.
   *
   * That is a design constraint, not an observation: the moment the stream became necessary for
   * correctness, it would have to be made reliable — and we would have rebuilt a transport on top
   * of the transport.
   */
  startStream(onChange: () => void): void {
    this.gateway?.close();

    this.gateway = new Gateway(
      this.api,
      {
        onEnvelope: (groupId) => {
          // We do not trust the announced number: we poll through the normal path, which re-checks
          // membership and moves the cursor with a single hand.
          if (!this.conversations.has(toHex(groupId))) return;
          void this.poll().then(onChange).catch(() => {});
        },
        onSignal: (groupId, payload) => {
          void this.absorbSignal(groupId, payload).then(onChange).catch(() => {});
        },
        onGap: (groupId, oldest) => {
          // The frame arrives before the sequence announcements for that group, so flagging here
          // is what stops the poll they would otherwise trigger. Rechecked against the cursor
          // rather than trusted outright: the session is never load-bearing, and a cursor that
          // advanced between reconnection and this frame must not be overruled by a stale
          // announcement.
          const view = this.conversations.get(toHex(groupId));
          if (!view || view.cursor >= oldest - 1) return;

          console.warn(
            `conversation ${view.key} interrupted: the server holds nothing before ${oldest}`,
          );
          view.stale = true;
          onChange();
        },
      },
      // Evaluated on every (re)connection, never frozen: between two attempts the poll may have
      // advanced, and a stale cursor would re-announce sequences already read.
      () =>
        [...this.conversations.values()].map((view) => ({
          groupId: view.groupId,
          seq: view.cursor,
        })),
      this.crypto.gatewayChallenge,
    );

    this.gateway.start();
    this.syncScope();
  }

  stopStream(): void {
    this.gateway?.close();
    this.gateway = undefined;
  }

  /**
   * Aligns the session's scope with the known conversations.
   *
   * Replaces the full reopen that the SSE stream forced, whose server froze the list at connection
   * time. The adjustment is incremental: a newly discovered conversation costs one frame, instead
   * of a reconnection with its challenge, its signature and its catch-up.
   *
   * Without this call: a conversation created after the stream opened is never subscribed, and its
   * typing indicators never arrive — a silent failure, since everything else keeps working through
   * the poll.
   */
  private syncScope(): void {
    if (!this.gateway) return;

    for (const view of this.conversations.values()) this.gateway.subscribe(view.groupId);
  }

  poll(): Promise<void> {
    // A poll already running is handed back as is: the caller waits on that one, rather than
    // starting a competing one.
    this.polling ??= this.pollOnce().finally(() => {
      this.polling = null;
    });
    return this.polling;
  }

  private async pollOnce(): Promise<void> {
    // The stock of welcome keys refills itself. Without that, it runs out in silence and the
    // device becomes unreachable with nothing to say so — exactly the kind of housekeeping a user
    // should never have to carry.
    await this.replenishKeyPackagesIfLow().catch((error) => {
      console.warn("could not replenish welcome keys", error);
    });

    const known = this.conversations.size;
    await this.discoverNewConversations();

    // A newly discovered conversation must enter the session's scope, or its typing indicators
    // would never arrive. `subscribe` being idempotent, we can resynchronise without comparing.
    if (this.conversations.size !== known) this.syncScope();

    // Catches up the account devices missing from a conversation. Idempotent: without this catch-up
    // an interrupted propagation would leave a device deaf indefinitely.
    await this.propagateOwnDevices().catch((error: unknown) => {
      console.warn("propagation to our other devices deferred", error);
    });

    // Evicts the devices whose revocation is certified. After the propagation: adding first avoids
    // making a legitimate device wait one more pass behind a failing eviction.
    await this.reconcileMembers().catch((error: unknown) => {
      console.warn("eviction of revoked devices deferred", error);
    });

    // After the evictions: a group may have just lost its last other member.
    await this.dropEmptyConversations();

    // One head per conversation per session: the check is about the existence of a fork, not its
    // timing.
    for (const view of this.conversations.values()) {
      await this.gossip(view).catch((error: unknown) => {
        console.warn("log head gossip deferred", error);
      });

      await this.sharePostingKey(view).catch((error: unknown) => {
        console.warn("posting key sharing deferred", error);
      });

      // The one hook the display name needs, and the reason it needs no other. A conversation
      // just created, one just joined, and one that just gained a member all arrive here with an
      // epoch this view has never announced under — the third because adding a member *is* an
      // epoch change. `announceProfile` compares and stays quiet otherwise.
      await this.announceProfile(view).catch((error: unknown) => {
        console.warn("display name announcement deferred", error);
      });
    }

    for (const view of this.conversations.values()) {
      // A severed ratchet does not heal by being asked again. See `ConversationView.stale`.
      if (view.stale) continue;

      const page = await this.api.fetchEnvelopes(view.groupId, view.cursor);

      // `oldest - 1` because the cursor names the last sequence we hold: the next one we expect
      // is `cursor + 1`, and the history is intact exactly while the server still has it.
      if (view.cursor < page.oldest - 1) {
        console.warn(
          `conversation ${view.key} interrupted: the server holds nothing before ${page.oldest}`,
        );
        view.stale = true;
        continue;
      }

      const envelopes = page.envelopes;
      const before = view.messages.length;

      for (const row of envelopes) {
        try {
          if (!view.mine.has(row.seq)) this.absorb(view, row.seq, row.payload);
        } catch (error) {
          // An unreadable message does not block the conversation. The cursor advances anyway: an
          // envelope we cannot read today — an already processed message, a corrupt envelope, a
          // commit we emitted ourselves — will not become readable tomorrow, and stopping there
          // would freeze the conversation for good.
          console.warn(`envelope ${row.seq} skipped`, error);
        }
        view.cursor = Math.max(view.cursor, row.seq);
      }

      view.epoch = this.client.epoch(view.groupId);
      view.peers = this.client.peerFingerprints(view.groupId) as Peer[];

      // Persist HERE, before any further network call.
      //
      // `process` moves the ratchet forward even when it ends up failing. If a later error — an
      // account resolution, a dropped connection — prevented recording the cursor, the MLS state
      // would restart ahead of it: we would read back envelopes the ratchet has already passed, and
      // MLS would refuse them for good. The message would be lost with nothing to report it.
      //
      // The cursor belongs to the cryptographic state, not to the display. The two advance together
      // or not at all.
      await this.persist();

      // The archive upload sits below that write, and the order is a principle rather than a
      // reaction to a failure anybody observed. `Archive.store` swallows its own errors today, so
      // nothing here can skip the persist — but that is a property of the archive, not of this
      // loop, and a caller that persists after a network call depends on a guarantee it does
      // not hold. The ratchet and the cursor reach the disk before anything else can fail.
      await this.archive.store(this.api, view.groupId, view.messages.slice(before));

      // Resolving accounts is cosmetic and goes over the network: it comes after, and its failure
      // must undo nothing.
      try {
        view.accounts = await this.resolvePeers(view);
      } catch (error) {
        console.warn("accounts not resolved for this conversation", error);
      }

      // Last: a receipt is an envelope, and emitting it before everything is absorbed would
      // announce a number we have not processed yet.
      await this.acknowledge(view).catch((error: unknown) => {
        console.warn("receipt deferred", error);
      });
    }

    await this.refreshPresence().catch((error: unknown) => {
      console.warn("presence not polled", error);
    });
  }

  /**
   * Polls the presence of every known peer, in one request.
   *
   * # Why this is here and not on a timer of its own
   *
   * Because a dedicated timer would hand the server back the second-by-second activity log that
   * the stream had precisely taken away from it — for one coloured dot. The poll already exists,
   * it runs every thirty seconds, and that is an honest granularity for this information.
   *
   * And not over the stream either: the green dot would depend on it, and a stream blocked by a
   * proxy would then show everyone offline. A wrong interface is worse than a late one.
   */
  private async refreshPresence(): Promise<void> {
    if (!this.signals.presence) return;

    const handles = [
      ...new Set(
        [...this.conversations.values()]
          .flatMap((view) => view.accounts.map((account) => account.handle))
          .filter((account) => account !== this.accountId),
      ),
    ];
    await this.presence.refresh(this.api, handles);
  }

  /**
   * Announces what we received, and what we read.
   *
   * # Why nothing goes out most of the time
   *
   * `pending` only yields a number if it exceeds what **our account** has already acknowledged —
   * and our own receipts come back to us like everyone else's. A poll with nothing new therefore
   * emits nothing, which is the only thing keeping the conversation from feeding on itself
   * indefinitely.
   */
  private async acknowledge(view: ConversationView): Promise<void> {
    const delivered = pending(view.receipts, this.accountId, "delivered", view.contentCursor);
    if (delivered !== undefined) {
      record(view.receipts, this.accountId, "delivered", delivered);
      await this.sendContent(view, { kind: "receipt", state: "delivered", seq: delivered });
    }

    // The setting cuts emission at the source. It also cuts the display, in `statusOf`: the
    // reciprocity must hold even if one of the two places is forgotten.
    if (!this.signals.readReceipts) return;

    const read = pending(view.receipts, this.accountId, "read", view.readCursor);
    if (read !== undefined) {
      record(view.receipts, this.accountId, "read", read);
      await this.sendContent(view, { kind: "receipt", state: "read", seq: read });
    }
  }

  private absorb(view: ConversationView, seq: number, payload: Uint8Array): void {
    const parsed = envelope.decode(payload);

    // A Welcome for a group we have already joined: nothing to do.
    if (parsed.kind === "welcome") return;

    // The **verified** revoked keys of every account in the conversation. Without them, the group
    // policy refuses the removal of a stolen device committed by a non-admin — that is, precisely
    // the case it exists to allow.
    const revoked = view.accounts.flatMap((account) => account.revokedKeys);

    const incoming = this.client.process(view.groupId, parsed.payload, revoked) as Incoming;
    if (incoming.kind !== "application") return;

    const { body: decode, sentAt } = content.decode(padding.unpad(incoming.plaintext));

    // Protocol traffic is processed then kept out of the thread: showing it would drown the
    // conversation in empty bubbles.
    if (content.isControl(decode)) {
      if (decode.kind === "gossip") void this.checkGossip(decode.head);
      // The posting key comes from MLS, so from an authenticated member: the server carried it
      // without being able to read or replace it.
      if (decode.kind === "posting-key") view.postingKey ??= decode.key;
      // The handle comes from the MLS credential, not from the message body: a member cannot
      // acknowledge on behalf of another. It is also what makes deduplication work between the
      // devices of one account — they carry the same handle.
      if (decode.kind === "receipt" && incoming.sender) {
        record(view.receipts, incoming.sender, decode.state, decode.seq);
      }
      // Same authentication argument as the receipt just above: the handle comes from the MLS
      // credential, so no member can rename another. What it does not establish is that the name
      // is *true* — it is self-declared, and a petname is the only answer to that.
      if (decode.kind === "profile" && incoming.sender) {
        this.absorbProfile(incoming.sender, decode.name, decode.at);
      }
      // The same authentication and the same limit: the *account* comes from the credential, so
      // nobody can claim a handle on somebody else's behalf; whether they actually hold the one
      // they claim is a question only the server's directory answers, and asking it at render
      // time is precisely what this design refuses.
      if (decode.kind === "handle" && incoming.sender) {
        if (this.names.absorbHandle(incoming.sender, decode.handle, decode.at)) {
          for (const view of this.conversations.values()) touch(view);
        }
      }
      // Settings announced by another of our own devices. The account comes from the MLS
      // credential, as above, and the check is what makes this cheap: every peer in the room
      // receives this message and would otherwise attempt a decryption certain to fail, once per
      // conversation per epoch. The seal is what makes it *safe* — the check is only economy.
      if (decode.kind === "signals" && incoming.sender === this.accountId) {
        void this.absorbSignals(decode.sealed).catch((error: unknown) => {
          console.warn("settings announcement not applied", error);
        });
      }
      return;
    }

    // The author has just sent: they are no longer typing. No "stopped typing" signal is needed —
    // the message itself is the proof, and it cannot get lost since we are not waiting for it.
    // Without this, the sender appears to keep typing for the whole TTL after pressing Enter.
    if (incoming.sender) view.typing = without(view.typing, incoming.sender);

    view.messages.push({
      seq,
      sender: incoming.sender,
      content: decode,
      mine: false,
      // Absent when the sender did not stamp — an older client, or a build from before stamping.
      // The thread renders that as a message with no time rather than inventing one: guessing
      // "now" for something received during a catch-up would date a week-old message to today.
      ...(sentAt === undefined ? {} : { sentAt }),
    });

    touch(view);

    // Only messages move this cursor. See its definition: it is what stops receipts from breeding
    // one another.
    view.contentCursor = Math.max(view.contentCursor, seq);
  }

  /**
   * Detects the groups the server has declared us a member of, and looks for **our** Welcome.
   *
   * A group contains several as soon as an account has several devices: one per added member. They
   * are indistinguishable from the outside — deliberately, the server has no business knowing
   * which one addresses whom. So they all have to be tried, keeping the one that opens.
   *
   * Taking the first one fails with "No matching key package was found": the Welcome was encrypted
   * for another device's KeyPackage.
   */
  private async discoverNewConversations(): Promise<void> {
    const groups = await this.api.listGroups();

    for (const hex of groups) {
      if (this.conversations.has(hex)) continue;

      const groupId = hexToBytes(hex);
      const { envelopes } = await this.api.fetchEnvelopes(groupId, 0);

      // No gap check here: a purged Welcome shows up as "no Welcome found", which this loop
      // already handles by leaving the group undiscovered. Flagging a conversation we have never
      // opened would mean creating one in order to declare it broken.
      for (const row of envelopes) {
        let parsed: envelope.Parsed;
        try {
          parsed = envelope.decode(row.payload);
        } catch {
          continue;
        }
        if (parsed.kind !== "welcome") continue;

        try {
          const joined = this.client.join(parsed.welcome, parsed.ratchetTree);
          this.conversations.set(hex, {
            groupId: joined,
            key: hex,
            messages: [],
            peers: this.client.peerFingerprints(joined) as Peer[],
            accounts: [],
            epoch: this.client.epoch(joined),
            cursor: row.seq,
            mine: new Set<number>(),
            ...freshSignalState(),
            ...freshSignalState(),
          });
          break;
        } catch {
          // Welcome meant for another device: nothing unusual, we try the next one.
        }
      }
    }
  }

  /**
   * The name this account shows to the people it talks to, if it has set one.
   *
   * Public and mutable in the same spirit as `preferences`, and read-only in practice: everything
   * that changes it goes through `setDisplayName`, which is the only path that also cleans it,
   * writes it down and tells the other members. Absent means never set, and the display falls
   * back to `@handle` — which always exists, and is the thing that actually identifies somebody.
   */
  get displayName(): string | undefined {
    return this.names.mine;
  }

  /**
   * The names other people have declared for themselves, by handle.
   *
   * Self-declared, therefore **not evidence**. Two people can claim the same name, and one of
   * them can pick it precisely because the other has it. Nothing here disambiguates them; the
   * handle shown alongside does, and `petnames` is how somebody overrules the claim entirely.
   */
  get profiles(): Record<string, Profile> {
    return this.names.profiles;
  }

  /**
   * Names this device has given other people, by handle.
   *
   * Never emitted. A petname is a note the reader took about somebody, and handing it back to its
   * subject would be a disclosure nobody asked for.
   */
  get petnames(): Record<string, string> {
    return this.names.petnames;
  }

  /**
   * The handle each account claims for itself, keyed by account id.
   *
   * What the interface draws where it used to draw the credential's subject. It is a claim, not
   * evidence — see `TYPE_HANDLE` in `lib/content.ts` — and `naming.ts` falls back to a short form
   * of the id for anybody whose claim has not arrived.
   */
  get handles(): Readonly<Record<string, string>> {
    return this.names.handles;
  }

  /**
   * Sets — or clears — the name this device gives somebody else.
   *
   * The counterpart to `setDisplayName`, and its opposite in every way that matters. A display
   * name is asserted by its subject and broadcast; a petname is asserted by the reader and goes
   * nowhere. That is exactly why it outranks the display name on screen: it is the one string in
   * the naming chain that no peer, and no server, can influence.
   *
   * Cleaned and bounded by the same rules as a display name, because it lands in the same slots
   * of the same layouts — a petname that overflowed a bubble author would be a petname that broke
   * a thread. It is **not** broadcast, and there is deliberately no code path that could: handing
   * somebody the note you took about them is a disclosure nobody asked for.
   *
   * An empty result removes the entry rather than storing an empty string, so that "no petname"
   * has one representation and `naming.ts` has one thing to test for.
   */
  async setPetname(handle: string, name: string): Promise<void> {
    this.names.setPetname(handle, name);
    await this.persist();

    // Every view, for the same reason `absorbProfile` touches every view: the person is drawn in
    // the thread, the conversation list and the member roster, and the revision counter is per
    // view. Renaming somebody in one pane and not the others is the bug this avoids.
    for (const view of this.conversations.values()) touch(view);
  }

  /**
   * Sets — or clears — the name this account shows, and tells everyone it talks to.
   *
   * Cleaned before it is judged, because a name is refused for what it means and not for what the
   * keyboard put in it: rejecting "Charlie " for a trailing space the user cannot see would be an
   * error message about nothing. `validate` then answers with a code, and the code is thrown as
   * is — the caller is at the display boundary and knows what language to say it in. Callers are
   * expected to validate first; this is the barrier for the ones that do not.
   *
   * An empty result clears the name rather than failing, and the clear is broadcast like any
   * other change. Not broadcasting it would leave the old name standing on every peer's screen
   * for as long as their session lives, which is the one outcome somebody removing their name is
   * trying to avoid.
   */
  /**
   * Takes a new handle, and gives up the old one.
   *
   * # What moves, and what conspicuously does not
   *
   * The name, and nothing else. Not the account, not its key, not its devices, not their ids, not
   * their attestations, not a single thing in any conversation. That is the whole point of
   * anchoring identity on a key: before `0014_account_identity.sql` this operation did not exist,
   * because it would have meant a new MLS credential everywhere and a "the fingerprint changed"
   * banner on every correspondent's screen — MLS doing exactly its job, over a cosmetic edit.
   *
   * # The old name does not come back
   *
   * The server tombstones it. Every stale reference to it — a bookmark, a screenshot, a mention
   * in a message written last year — would otherwise name whoever claimed it next, and that is an
   * impersonation nobody has to mount: it arrives on its own, on a schedule the attacker picks by
   * waiting.
   *
   * # Correspondents hear it from us
   *
   * Not from the directory. Re-announced into every conversation, as a claim, the way a display
   * name is — see `TYPE_HANDLE` in `lib/content.ts`. Reading it back from the server at render
   * time would hand it the one power this design took away, on every screen, forever.
   *
   * A conversation whose announcement fails keeps showing the old name until the next epoch
   * re-announces it. That is a stale label, not a lost rename: the server has already recorded
   * it, and it is what the next device to sign in will read.
   */
  async renameHandle(handle: string): Promise<void> {
    const wanted = normalizeHandle(handle);
    const problem = validateHandle(wanted);
    if (problem !== null) throw new Error(problem);
    if (wanted === this.handle) return;

    await this.api.renameAccount(this.accountId, wanted);

    // `handle` is `readonly` on the instance and this is the one operation that changes it. The
    // cast is confined here rather than the field being widened: every other site in this file
    // reads it, and a mutable one would invite a second writer.
    (this as { handle: string }).handle = wanted;
    await this.persist();

    for (const view of this.conversations.values()) {
      touch(view);
      await this.emitProfile(view).catch((error: unknown) => {
        console.warn(`handle not announced in ${view.key}`, error);
      });
    }
  }

  async setDisplayName(name: string): Promise<void> {
    this.names.setMine(name);
    await this.persist();

    for (const view of this.conversations.values()) {
      // Our own name is drawn on our own messages too, so the same re-render is owed here as on
      // receiving somebody else's: the revision counter is per view, and nothing else bumps it.
      touch(view);

      // One failure must not swallow the rest. A conversation whose post is refused keeps the old
      // name until the next epoch re-announces it, which is a stale label — not a lost rename.
      await this.emitProfile(view).catch((error: unknown) => {
        console.warn(`display name not announced in ${view.key}`, error);
      });
    }
  }

  /**
   * Announces the name in a conversation, unless it has already been announced at this epoch.
   *
   * Called from the poll loop beside `gossip` and `sharePostingKey`, which is the hook that
   * already exists for "say this once per group". The epoch is the right unit rather than the
   * session: it moves when the roster does, so a member who joins after us gets the name without
   * anyone having to notice that they arrived.
   *
   * Silent when no name is set. An account that never named itself must not spend an envelope per
   * group announcing the fact — the absence is the default everywhere, and saying it out loud
   * would be pure traffic.
   */
  private async announceProfile(view: ConversationView): Promise<void> {
    if (view.profileEpoch === view.epoch) return;

    await this.emitProfile(view);
  }

  /**
   * Posts the profile, guard rail included.
   *
   * The epoch is recorded **before** the send and not after, exactly as `gossip` and
   * `sharePostingKey` set their flags first: a send that throws would otherwise be retried on
   * every poll for the lifetime of the conversation, which turns one failed announcement into a
   * permanent stream of them. A name that failed to go out is picked up again at the next epoch.
   */
  private async emitProfile(view: ConversationView): Promise<void> {
    // Nobody to tell. A group we are alone in is one whose other members have all left; it costs
    // an envelope and reaches no one.
    if (view.peers.length === 0) return;

    view.profileEpoch = view.epoch;

    const at = Date.now();

    /*
      The handle goes out unconditionally; the display name only if there is one.

      They are not the same kind of absence. Having no display name is a choice — the interface
      falls back to the handle, which is exactly what someone who set none is asking for. Having
      no handle is not a state an account can be in, and a member who never hears ours is left
      showing a thirty-two character hexadecimal string where a name belongs. Since the credential
      stopped carrying it, this message is the only way it reaches the room at all.
    */
    await this.sendContent(view, { kind: "handle", handle: this.handle, at });

    if (this.displayName !== undefined) {
      await this.sendContent(view, { kind: "profile", name: this.displayName, at });
    }

    // And the signalling settings, for our own devices rather than for the room. Sent from here
    // because the trigger is the same one: the epoch moves when somebody joins, and a device of
    // ours that just joined is precisely who has never heard these. Unconditional, unlike the
    // display name — there is no such thing as an account without settings, and a device that
    // never hears them keeps the defaults, which is to say keeps emitting what its owner refused.
    await this.emitSignals(view);
  }

  /**
   * Records the name a peer has declared for themselves.
   *
   * `sanitize` runs here and not in `content.ts`, which decodes bytes and has no notion of a
   * screen. This is the receiving end of the contract that module states: a name from a peer is
   * not less hostile than one typed locally, it is more so — nobody chose those code points by
   * accident.
   *
   * Last writer wins on the **clamped** time, so a peer cannot pin their name by dating it far
   * ahead; `content.ts` does the clamping. Ties keep what is already stored, which makes a
   * replayed message a no-op rather than a flicker.
   *
   * A name that cleans away to nothing removes the entry instead of storing an empty string. The
   * absence is what the display falls back on, and one representation of "no name" is enough.
   */
  private absorbProfile(handle: string, declared: string, at: number): void {
    if (!this.names.absorb(handle, declared, at)) return;

    // Every conversation, not only the one the message arrived in. The name is drawn wherever the
    // person is — the thread, the conversation list, the member roster — and the revision counter
    // is per view, so touching only the receiving one would leave the same person renamed in one
    // place and not in another.
    for (const view of this.conversations.values()) touch(view);

    // No write from here. `absorb` runs inside the poll loop, which persists once the whole page
    // of envelopes has been applied — and it has to be that one write, because the cursor and the
    // MLS ratchet must reach the disk together. A second, concurrent seal of the same state would
    // race it for nothing more than a name.
  }
}

function hexToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export { fromBase64 };



/**
 * What startup offers: a migration, which it does not carry out.
 *
 * It registers a device and **revokes another**. Those are account-level acts, visible to the
 * server and to peers, and nothing about "opening the app" asks for them. Running them
 * automatically would decide on behalf of someone who asked for nothing.
 *
 * Deferring costs nothing: the app carries on exactly as before, and the offer comes back at the
 * next startup.
 */
export interface ProposedMigration {
  /**
   * Has it already started?
   *
   * Changes what to say, not what to do: two devices are then active — a healthy state, merely
   * redundant — and the user deserves to know why they see two of them in their settings.
   */
  resume: boolean;
  execute(onProgress?: (step: string) => void): Promise<Session>;
}

/**
 * What to do at startup.
 *
 * # Why this is not in `Session.restore`
 *
 * A migration holds **two** sessions open at once — the old one is the only member of the groups,
 * so the only one able to introduce the new one — and `restore` returns one.
 *
 * # Falling back is not a silent failure
 *
 * When migration is impossible — vault turned off, or native storage occupied by another account —
 * the app carries on with IndexedDB and `fallback` carries the reason. Keeping quiet about it
 * would suggest a durability that does not exist.
 */
export async function start(
  /**
   * What opens the lock: the password that was typed, or the master key handed back by the system
   * prompt. Both lead to the same place, by paths that do not share an input.
   */
  opener?: string | CryptoKey,
): Promise<{ session: Session | null; migration?: ProposedMigration; fallback?: string }> {
  if (!isTauri()) return { session: await Session.restore(opener) };

  const native = nativeAnchor();
  const web = await existingWebAnchor();

  const decision = decide(await presenceOf(web), await presenceOf(native));

  if (decision.kind === "fallback") {
    return { session: web ? await Session.open(web, opener) : null, fallback: decision.reason };
  }

  if (decision.kind !== "start" && decision.kind !== "resume") {
    return { session: await Session.restore(opener) };
  }

  // The old session has to be open: it alone is a member of the groups. A lock in place therefore
  // forces offering the migration after the password is typed, not before.
  const previous = web ? await Session.open(web, opener) : null;
  if (!previous) return { session: await Session.restore(opener) };

  return {
    session: previous,
    migration: {
      resume: decision.kind === "resume",
      execute: (onProgress) => previous.migrateToNative(decision, native, onProgress),
    },
  };
}

/** What an anchor reveals without being opened: enough to decide, and nothing more. */
async function presenceOf(anchor: Anchor | undefined): Promise<Presence | undefined> {
  const stored = await anchor?.store.load();
  if (!stored?.state) return undefined;

  return { handle: stored.handle, vaultEnabled: stored.vaultEnabled };
}
