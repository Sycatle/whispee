/* tslint:disable */
/* eslint-disable */

/**
 * Handle on the pseudonymous account.
 *
 * Kept separate from [`Client`] on purpose: an account outlives its devices, and a device can
 * exist for the duration of a pairing without ever holding the account key. Merging them
 * would suggest one implies the other.
 *
 * **This object holds the account's root key.** Losing it means losing the account;
 * disclosing it means giving the account away.
 */
export class AccountKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Signs a device's membership of this account.
     */
    attest(handle: string, device_id: string, auth_key: Uint8Array, mls_key: Uint8Array): Uint8Array;
    /**
     * Seed to hand to a device being paired. **It is worth the whole account.**
     */
    exportSeed(): Uint8Array;
    /**
     * The account fingerprint, to be compared out of band.
     *
     * Stable when the account gains or loses a device: a hostile device is caught by the
     * device-added notification, not by a fingerprint change that would be ignored from
     * happening legitimately too often.
     */
    fingerprint(): string;
    /**
     * Rebuilds the account from the seed received during a pairing.
     */
    static fromSeed(seed: Uint8Array): AccountKey;
    /**
     * Creates an account and returns `{phrase, identityKey}`.
     */
    static generate(): any;
    identityKey(): Uint8Array;
    /**
     * Rebuilds the account from its recovery phrase.
     */
    static restore(phrase: string): AccountKey;
    /**
     * Signs the revocation of a device of this account.
     *
     * The certificate is verifiable by anyone holding the account's public key: that is what
     * lets **another** group member commit the removal without taking the server's word for
     * it.
     */
    revoke(handle: string, device_id: string, revoked_at: bigint): Uint8Array;
    /**
     * Signs this account's move to a new identity key.
     *
     * Call it on the **old** account, which thereby names its successor.
     *
     * This is the only real answer to a stolen device: it holds the seed, hence the whole
     * account, and revoking it does not stop it from attesting a new one. Rotation, on the
     * other hand, invalidates every attestation at once.
     */
    rotate(handle: string, new_identity_key: Uint8Array, rotated_at: bigint): Uint8Array;
    /**
     * Symmetric key of the backup vault, derived on demand.
     */
    vaultKey(): Uint8Array;
}

/**
 * The single JavaScript-side handle: one device identity and its conversations.
 *
 * Conversations are indexed by group id rather than exposed as separate objects. Juggling
 * two paired handles from JS — an identity and a conversation — invites mixing them up, and
 * encrypting with the wrong identity fails silently.
 */
export class Client {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Applies the commit prepared by `invite`, once it has been published.
     *
     * Returns the up-to-date ratchet tree, to hand to the invitee along with their Welcome. It
     * cannot be produced any earlier: until the commit is applied, the tree does not contain
     * the new member and their Welcome would be rejected.
     */
    applyPending(group_id: Uint8Array): Uint8Array;
    /**
     * Commits the pending proposals — typically a member's request to leave.
     */
    commitPending(group_id: Uint8Array): Uint8Array;
    /**
     * Ids of the open conversations, to persist next to the state so they can be reloaded
     * through [`Client::restore`].
     */
    conversationIds(): Uint8Array[];
    /**
     * Creates a device identity.
     *
     * `name` travels in the clear inside the MLS credential and is visible to the server and
     * to every group member. Put nothing sensitive in it.
     */
    static create(name: string): Client;
    /**
     * Creates a conversation and returns its group id.
     */
    createConversation(): Uint8Array;
    /**
     * Creates an administered group. The creator is its one and only admin.
     *
     * Reserve this for real groups. A 1-to-1 must go through `createConversation`: roles make
     * no sense there, and the flat group is the correct shape.
     */
    createGroup(admin: string): Uint8Array;
    encrypt(group_id: Uint8Array, plaintext: Uint8Array): Uint8Array;
    /**
     * The group's current epoch. Two members at different epochs cannot read each other:
     * it is the first thing to look at when a message does not go through.
     */
    epoch(group_id: Uint8Array): bigint;
    /**
     * Exports the complete session state.
     *
     * **This blob contains the private keys in the clear.** It must never reach
     * `localStorage`, a backup, or the server. Encrypt it first with a non-extractable
     * `CryptoKey` held in IndexedDB.
     *
     * Never restore an *old* state: it rolls the group back an epoch and replays keys already
     * used, destroying forward secrecy.
     */
    exportState(): Uint8Array;
    fingerprint(): string;
    /**
     * Prepares the addition of a member. Returns `{commit, welcome}` **without applying
     * anything**.
     *
     * The two halves go to different places: the `commit` to the members already present, the
     * `welcome` to the invitee alone.
     *
     * The group stays at its current epoch until [`Client::applyPending`]. Publish first,
     * apply second: the reverse breaks the group beyond repair if publication fails — the
     * sender would have changed epoch, the others not, and the commit would be lost.
     */
    invite(group_id: Uint8Array, key_package: Uint8Array): any;
    /**
     * Joins a conversation from a Welcome. Returns the group id.
     */
    join(welcome: Uint8Array, ratchet_tree: Uint8Array): Uint8Array;
    /**
     * Asks to leave the group. Returns a **proposal**, not a commit.
     *
     * RFC 9420 forbids removing yourself in a commit you generate: another member has to pick
     * it up through `commitPending`. Display the consequence honestly — until someone
     * commits, the departure has not happened and the conversation is still being read.
     */
    leaveGroup(group_id: Uint8Array): Uint8Array;
    /**
     * This device's name, as written into the MLS credential.
     */
    name(): string;
    /**
     * The other members' fingerprints, to be compared out of band.
     *
     * The interface must make that comparison possible and understandable. Without it, a
     * malicious server can sit in the middle of two perfectly encrypted sessions with no
     * cryptographic check catching it.
     */
    peerFingerprints(group_id: Uint8Array): any;
    /**
     * The other members' MLS signature keys, as they appear in the tree.
     *
     * Comes from the authenticated state, not from the server. This is what lets the client
     * notice that a member of the tree is no longer among its account's active devices.
     */
    peerSignatureKeys(group_id: Uint8Array): any;
    /**
     * Processes an incoming message: application data or a group change.
     *
     * The result must be handled in both cases. Ignoring a `groupChanged` leaves the device at
     * a stale epoch, and everything that follows becomes undecryptable.
     */
    process(group_id: Uint8Array, message: Uint8Array, revoked: Uint8Array[]): any;
    /**
     * Produces a KeyPackage to publish on the server.
     *
     * **Single use.** The server must remove it from the pool as soon as it serves it, and
     * the caller must restock regularly: with an empty pool, nobody can open a conversation
     * with this device any more.
     */
    publishKeyPackage(): Uint8Array;
    /**
     * Prepares the removal of a member, designated by their MLS signature key.
     *
     * It is this removal — not server-side filtering — that actually cuts the device off from
     * what follows: the commit re-keys the tree. Same discipline as `invite`: publish, then
     * `applyPending`.
     */
    removeMember(group_id: Uint8Array, mls_key: Uint8Array): Uint8Array;
    /**
     * Rebuilds a client from an exported state.
     *
     * `groupIds` is the list of conversations to reload. MLS storage offers no enumeration:
     * keeping that list, alongside the state, is the caller's job.
     *
     * **Never** restore a state older than the last one exported: groups would roll back an
     * epoch and replay keys already used. An MLS state is not an ordinary backup — only one
     * live copy may exist.
     */
    static restore(state: Uint8Array, group_ids: Uint8Array[]): Client;
    /**
     * The group roster: `{admin, moderators}`, or `null` if the group is flat.
     */
    roster(group_id: Uint8Array): any;
    /**
     * Replaces the group's roles. Like every commit, publish it before `applyPending`.
     *
     * Passing an `admin` different from the current one **hands the group over**: the sender
     * cannot take it back.
     */
    setRoles(group_id: Uint8Array, admin: string, moderators: string[]): Uint8Array;
    /**
     * Symmetric key of this group's ephemeral channel, for the current epoch.
     *
     * **These bytes must only serve throwaway signals.** They do not go through the
     * application ratchet, so they offer no forward secrecy within an epoch, and they do not
     * authenticate the sender — the key belongs to the group. Routing a message through them
     * would forfeit both properties MLS was chosen for.
     *
     * The key changes on every commit: a removed member loses this channel along with the
     * rest, with no special handling.
     */
    signalKey(group_id: Uint8Array): Uint8Array;
    /**
     * This device's fingerprint, to display so the peer can compare it.
     * This device's MLS signature public key.
     *
     * It must be attested by the account **at the same time** as the HTTP authentication
     * key: attested separately, a legitimate device's attestation could be recombined with a
     * hostile device's MLS key.
     */
    signatureKey(): Uint8Array;
}

/**
 * Pairing offer held by the **new** device.
 *
 * The new device shows the QR, the old one scans it. That direction is mandatory: a QR can be
 * photographed, so it must contain no secret. Here it carries only an ephemeral public key
 * and a drop address.
 */
export class Pairing {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Pairing id: the drop address on the server. Public, worthless on its own.
     */
    id(): Uint8Array;
    constructor();
    /**
     * Opens the packet dropped by the original device.
     *
     * Consumes the offer: the ephemeral secret is single-use, which forbids replaying an old
     * packet against the same key. A second call fails, deliberately.
     */
    open(sealed: Uint8Array): any;
    /**
     * Ephemeral public key to publish in the QR.
     */
    publicKey(): Uint8Array;
}

/**
 * Fingerprint of an account we only hold the public key of.
 */
export function accountFingerprint(identity_key: Uint8Array): string;

/**
 * Derives the local unlock key from a password.
 *
 * Argon2id, 64 MiB, 3 passes. **About one second**: that is the price paid once per unlock,
 * and on every attempt by an attacker who got hold of the database.
 *
 * This function does not exist in WebCrypto. PBKDF2 does — but it only costs computation,
 * which a GPU does by the billion. Argon2id's memory cost is what brings a parallel attack
 * back down to the level of an ordinary processor.
 *
 * Calling this function freezes the thread of execution for its duration. Run it from a
 * Worker if the interface must stay responsive.
 */
export function deriveUnlockKey(password: string, salt: Uint8Array): Uint8Array;

/**
 * Message to sign in order to open a gateway session.
 *
 * Returns the bytes to sign, **not the signature**: the device's authentication key is a
 * non-extractable WebCrypto key that never leaves the browser and therefore never enters this
 * module. The split is deliberate — it is what stops a bug here from leaking the key.
 *
 * Same argument as [`post_mac`] about where the computation lives: the canonical format is in
 * the `attest` crate, and rewriting it in JavaScript would duplicate it. One byte of
 * divergence and no session opens.
 */
export function gatewayChallenge(device_id: string, nonce: Uint8Array): Uint8Array;

/**
 * Leaf hash of a log entry, as the server must have computed it.
 *
 * The client recomputes it from the handle and the key it is served: accepting the hash the
 * server provides would amount to asking it to prove what it claims with what it claims.
 */
export function logLeaf(handle: string, identity_key: Uint8Array): Uint8Array;

/**
 * Authenticates an envelope post without revealing who posts.
 *
 * # What this MAC tells the server
 *
 * That the poster holds the group key, hence that they are a member. Nothing more. The server
 * never needed to know **who** posts — only that the poster is allowed to, so it does not act
 * as an open mailbox. Those are two distinct things, and the second one is enough.
 *
 * The real sender stays authenticated **by MLS**, inside the ciphertext: the recipients read
 * it, the server does not.
 *
 * # Why the computation happens here and not in JavaScript
 *
 * The authenticated message has a canonical format, shared with the verifier. Rewriting it on
 * the client would duplicate the definition — exactly what the `attest` crate exists to
 * remove. One byte of divergence and every post is refused.
 */
export function postMac(posting_key: Uint8Array, group_id: Uint8Array, nonce: Uint8Array, body: Uint8Array): Uint8Array;

/**
 * Seals a packet for the new device, from the values read in the QR.
 *
 * Returns `{payload, confirmation}`. The confirmation code must be **displayed on both sides
 * and compared by the user**: that is what attests that the two devices are talking about the
 * same exchange.
 */
export function sealPairing(offer_public: Uint8Array, offer_id: Uint8Array, plaintext: Uint8Array): any;

/**
 * MAC accompanying the post of an **ephemeral signal**.
 *
 * Twin of [`post_mac`], up to the domain — see `attest::signal_message` for the reason behind
 * that separation. It proves the same thing: group membership, not identity.
 */
export function signalMac(posting_key: Uint8Array, group_id: Uint8Array, nonce: Uint8Array, body: Uint8Array): Uint8Array;

/**
 * Verifies a device attestation served by the server.
 *
 * **Always re-check this on the client.** The server already verifies on write, but the
 * server is precisely who we suspect: its check is an early filter, never a guarantee. See
 * the test `a_ghost_device_injected_in_sql_does_not_pass_client_verification`.
 */
export function verifyAttestation(identity_key: Uint8Array, handle: string, device_id: string, auth_key: Uint8Array, mls_key: Uint8Array, attestation: Uint8Array): boolean;

/**
 * Checks that the current log **extends** the one already seen, with no rewriting.
 *
 * Without this check, the server could replace an already published key and serve a log just
 * as coherent: the log would no longer prove anything about the past.
 */
export function verifyConsistency(from: number, old_root: Uint8Array, to: number, new_root: Uint8Array, proof: Uint8Array[]): boolean;

/**
 * Checks that a key really is in the log, at the announced index.
 *
 * **This is what closes the first-contact hole.** Attestations stop the server from adding a
 * device; they do not stop it from serving its own account key to someone with nothing to
 * compare against. An inclusion proof, by contrast, cannot be forged.
 */
export function verifyInclusion(leaf: Uint8Array, index: number, size: number, proof: Uint8Array[], root: Uint8Array): boolean;

/**
 * Verifies a revocation certificate served by the server.
 *
 * **Always call this.** A client that took the server's word for it would hand the server the
 * power to evict any device it chose — targeted censorship, durable, and indistinguishable
 * from a legitimate revocation.
 */
export function verifyRevocation(identity_key: Uint8Array, handle: string, device_id: string, revoked_at: bigint, revocation: Uint8Array): boolean;

/**
 * Checks that a tree head really was signed by the log.
 *
 * **What this proves is narrow**: that the head comes from the log. Not that it is the only
 * head the log ever emitted. A server running two logs signs two equally valid heads; only
 * comparison between clients catches it.
 */
export function verifyTreeHead(log_key: Uint8Array, size: bigint, root: Uint8Array, timestamp: bigint, signature: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_accountkey_free: (a: number, b: number) => void;
    readonly __wbg_client_free: (a: number, b: number) => void;
    readonly __wbg_pairing_free: (a: number, b: number) => void;
    readonly accountFingerprint: (a: number, b: number, c: number) => void;
    readonly accountkey_attest: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => void;
    readonly accountkey_exportSeed: (a: number, b: number) => void;
    readonly accountkey_fingerprint: (a: number, b: number) => void;
    readonly accountkey_fromSeed: (a: number, b: number, c: number) => void;
    readonly accountkey_generate: (a: number) => void;
    readonly accountkey_identityKey: (a: number, b: number) => void;
    readonly accountkey_restore: (a: number, b: number, c: number) => void;
    readonly accountkey_revoke: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => void;
    readonly accountkey_rotate: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => void;
    readonly accountkey_vaultKey: (a: number, b: number) => void;
    readonly client_applyPending: (a: number, b: number, c: number, d: number) => void;
    readonly client_commitPending: (a: number, b: number, c: number, d: number) => void;
    readonly client_conversationIds: (a: number, b: number) => void;
    readonly client_create: (a: number, b: number, c: number) => void;
    readonly client_createConversation: (a: number, b: number) => void;
    readonly client_createGroup: (a: number, b: number, c: number, d: number) => void;
    readonly client_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_epoch: (a: number, b: number, c: number, d: number) => void;
    readonly client_exportState: (a: number, b: number) => void;
    readonly client_fingerprint: (a: number, b: number) => void;
    readonly client_invite: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_join: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_leaveGroup: (a: number, b: number, c: number, d: number) => void;
    readonly client_name: (a: number, b: number) => void;
    readonly client_peerFingerprints: (a: number, b: number, c: number, d: number) => void;
    readonly client_peerSignatureKeys: (a: number, b: number, c: number, d: number) => void;
    readonly client_process: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly client_publishKeyPackage: (a: number, b: number) => void;
    readonly client_removeMember: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_restore: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly client_roster: (a: number, b: number, c: number, d: number) => void;
    readonly client_setRoles: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly client_signalKey: (a: number, b: number, c: number, d: number) => void;
    readonly client_signatureKey: (a: number, b: number) => void;
    readonly deriveUnlockKey: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly gatewayChallenge: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly logLeaf: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly pairing_id: (a: number, b: number) => void;
    readonly pairing_new: () => number;
    readonly pairing_open: (a: number, b: number, c: number, d: number) => void;
    readonly pairing_publicKey: (a: number, b: number) => void;
    readonly postMac: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly sealPairing: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly signalMac: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly verifyAttestation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => number;
    readonly verifyConsistency: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly verifyInclusion: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly verifyRevocation: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => number;
    readonly verifyTreeHead: (a: number, b: number, c: bigint, d: number, e: number, f: bigint, g: number, h: number) => number;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
