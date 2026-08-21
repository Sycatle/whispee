/**
 * The local lock, and what it does and does not change.
 *
 * # The invariant this file exists to hold
 *
 * A session has two ciphers and they must never be confused. One **signs**: it is the device's
 * identity, the key the server authenticates every request against, and it does not move when a
 * lock is set — the server must see no difference between a locked device and an unlocked one. The
 * other **seals**: it encrypts the state at rest, and it is exactly what a lock replaces.
 *
 * The failure that guards against is quiet. State sealed under one cipher and opened with the
 * other does not report a mismatch, it reports a decryption failure — and a decryption failure on
 * the opening path looks like a corrupted profile, not like a bug in whoever swapped the wrong
 * field.
 *
 * # Why the operations arrive as a port
 *
 * Not for taste, and not for layering. The real ones reach Argon2id through WASM and the
 * biometric prompt through Tauri IPC, and a module that imports either cannot be loaded by
 * `node --test` at all. This class is **policy**: a lock cannot be removed without its password, a
 * key kept for biometrics must not outlive the lock that justified it, biometrics hold a key and
 * do not create one. Those rules are worth testing and none of them needs a real key derivation.
 *
 * So the derivation, the wrapping and the biometric store come in as `LockKit`, and everything
 * imported here is a type. The one place the real implementations are named is `session.ts`, which
 * is where the platform lives anyway.
 *
 * # What a lock is worth, and what it is not
 *
 * It protects the state **at rest**. It is not a recovery factor: the password exists nowhere but
 * in its owner's head, which is what makes the state unreadable to whoever walks off with the
 * disk, and also what means forgetting it recovers nothing on its own.
 *
 * # What it does not solve
 *
 * Nothing about the running session. Once the state is open the keys are in memory and the lock
 * has done everything it can — see `docs/THREAT-MODEL.md` on MLS keys living in WASM linear
 * memory, reachable by the page's own JavaScript on every platform.
 *
 * And enabling biometrics is **strictly weaker than the password alone**: it writes the master key
 * onto the device, sealed by native secrets that are themselves in the clear in the application's
 * private directory. That is not a reason to refuse the feature — a lock removed because it is
 * tiresome protects less than a lukewarm one that stays on — it is a reason to say so first, which
 * the settings screen does.
 */
import type { DeviceCipher } from "./cipher";
import type { LockEnvelope } from "./lock";
import type { StoredSession } from "./storage";

/**
 * What a lock needs done, and nothing else.
 *
 * Every member of this is a boundary to something this file must not import: `create`, `open` and
 * `rekey` reach Argon2id inside the WASM module, `wrap` builds a cipher from a module that talks
 * to Tauri, and the biometric pair is Tauri IPC outright.
 */
export interface LockKit {
  /** Derives a master key from a password and returns the envelope that will re-derive it. */
  create(password: string): Promise<[LockEnvelope, CryptoKey]>;
  /** Re-derives the master key. Rejects on a wrong password, which is how one is checked. */
  open(envelope: LockEnvelope, password: string): Promise<CryptoKey>;
  /** Re-seals the master key under a new password. The state itself is untouched. */
  rekey(envelope: LockEnvelope, current: string, next: string): Promise<LockEnvelope>;
  /** Wraps the signing cipher so that sealing goes through the master key. */
  wrap(signing: DeviceCipher, master: CryptoKey): DeviceCipher;
  /** Hands the master key to the system, behind a fingerprint or a face. */
  keepBiometric(master: CryptoKey): Promise<void>;
  /** Takes it back. */
  dropBiometric(): Promise<void>;
}

/** Raised when a stored session is locked and nothing was offered to open it. */
export class LockedSession extends Error {
  constructor() {
    super("This session is locked: a password is required.");
    this.name = "LockedSession";
  }
}

export class Lockbox {
  /**
   * What seals the state at rest.
   *
   * The signing cipher when no lock is set; a wrapped one otherwise. The signing cipher itself is
   * never held here — it is passed in and handed back out, so nothing in this class is in a
   * position to replace it.
   */
  private sealing: DeviceCipher;

  private envelope: LockEnvelope | undefined;

  /**
   * The master key, while the session is open.
   *
   * Kept rather than dug back out of the sealing cipher when biometrics ask for it. Reaching into
   * the cipher meant an `instanceof` against a concrete class, which is a test of how the lock is
   * implemented standing in for a test of whether one is set.
   */
  private master: CryptoKey | undefined;

  /**
   * Declared and assigned rather than written as constructor parameter properties.
   *
   * `node --test` runs with `--experimental-strip-types`, which erases annotations without
   * rewriting anything, and a parameter property is the one construct that needs rewriting. One of
   * them here would make this file — the whole point of which is to be testable — unloadable by
   * the runner that tests it.
   */
  private readonly kit: LockKit;
  private readonly signing: DeviceCipher;

  private constructor(kit: LockKit, signing: DeviceCipher) {
    this.kit = kit;
    this.signing = signing;
    this.sealing = signing;
  }

  /**
   * Opens the lock a stored session was carrying.
   *
   * `opener` has two shapes rather than one because the two paths do not have the same input: a
   * password derives the master key, biometrics hand it over directly. Uniting them behind a
   * string would force encoding a key as text, which is pushing a secret through a format nobody
   * needs.
   *
   * Throws `LockedSession` when there is a lock and nothing to open it with — a distinct type
   * rather than a message, so a caller can tell that case from a wrong password and know whether
   * to show a prompt or an error.
   */
  static async open(
    kit: LockKit,
    signing: DeviceCipher,
    stored: Pick<StoredSession, "lock">,
    opener?: string | CryptoKey,
  ): Promise<Lockbox> {
    const lockbox = new Lockbox(kit, signing);
    if (!stored.lock) return lockbox;
    if (opener === undefined) throw new LockedSession();

    const master = typeof opener === "string" ? await kit.open(stored.lock, opener) : opener;

    lockbox.envelope = stored.lock;
    lockbox.master = master;
    lockbox.sealing = kit.wrap(signing, master);

    return lockbox;
  }

  /** A lockbox for a device that has never had one. */
  static none(kit: LockKit, signing: DeviceCipher): Lockbox {
    return new Lockbox(kit, signing);
  }

  /** Is a lock set on this device? */
  get engaged(): boolean {
    return this.envelope !== undefined;
  }

  /** What seals the state at rest, right now. */
  get cipher(): DeviceCipher {
    return this.sealing;
  }

  /**
   * What this contributes to the stored session.
   *
   * Nothing here is secret: the salt is public and the master key appears encrypted. What is
   * secret is the password, and that is not in this object either.
   */
  snapshot(): Pick<StoredSession, "lock"> {
    return { lock: this.envelope };
  }

  /**
   * Sets a lock: the state moves from the device key to a derived master key.
   *
   * **Does not write.** The switch only takes effect when the caller persists, which re-encrypts
   * the state under the new key and overwrites the old version. Persisting here would put that
   * write outside the caller's ordering, and that ordering is the one thing this class must not
   * own.
   */
  async enable(password: string): Promise<void> {
    if (this.envelope) throw new Error("A lock is already set.");

    const [envelope, master] = await this.kit.create(password);
    this.envelope = envelope;
    this.master = master;
    this.sealing = this.kit.wrap(this.signing, master);
  }

  /**
   * Removes the lock. Requires the current password.
   *
   * Without that requirement, anyone who finds an unlocked device disarms it for good in one
   * click — the lock would only protect until the first forgotten screen.
   *
   * The password is checked **before** anything moves, so a refused attempt leaves a working lock
   * rather than a half-removed one.
   */
  async disable(password: string): Promise<void> {
    if (!this.envelope) return;

    await this.kit.open(this.envelope, password);

    this.envelope = undefined;
    this.master = undefined;
    this.sealing = this.signing;

    // The key kept for biometrics has nothing left to open, and leaving it would be worse than
    // useless: it would outlive the lock that justified it.
    await this.kit.dropBiometric().catch(() => {});
  }

  /**
   * Changes the password without re-encrypting the state.
   *
   * Only the thirty-two bytes of the master key are re-sealed. The state, which weighs several
   * kilobytes and grows with the conversations, is untouched — so it never goes back through
   * memory in the clear at the most delicate moment. The sealing cipher does not change either:
   * the master key behind it is the same one.
   */
  async changePassword(current: string, next: string): Promise<void> {
    if (!this.envelope) throw new Error("No lock to change.");

    this.envelope = await this.kit.rekey(this.envelope, current, next);
  }

  /**
   * Hands the master key to the system, behind a fingerprint or a face.
   *
   * The password is not asked again, and that is deliberate: it just was, or this session would
   * not be open. Asking twice would add no proof — somebody holding an unlocked device already
   * reads everything — and would charge a security gesture with friction that buys nothing.
   *
   * Refused without a lock, because there would be no master key to keep. Biometrics hold a key;
   * they do not create one.
   */
  async enableBiometric(): Promise<void> {
    if (!this.master) {
      throw new Error("Set a lock first: biometrics keep your key, they do not create one.");
    }

    await this.kit.keepBiometric(this.master);
  }

  /** Removes biometric unlock. The lock stays set, and the password still opens it. */
  async disableBiometric(): Promise<void> {
    await this.kit.dropBiometric();
  }
}
