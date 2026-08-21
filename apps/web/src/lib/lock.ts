/**
 * Local lock: encryption of state at rest, under a password.
 *
 * # The indirection, and why it is not a refinement
 *
 * ```
 * password --Argon2id--> unlock key --encrypts--> master key --encrypts--> state
 * ```
 *
 * The master key is random and does not depend on the password. Changing the password therefore
 * re-encrypts 32 bytes, never the whole state — which weighs several kilobytes and grows with the
 * number of conversations. Without this indirection, a password change would mean decrypting then
 * re-encrypting all the state: a long operation, done at the worst moment (the user suspects a
 * compromise), leaving the state in the clear in memory for its whole duration.
 *
 * # What changes compared to the non-extractable key
 *
 * Until now state was encrypted by a non-extractable `CryptoKey` stored in IndexedDB. That
 * protects against exfiltration by script — the key cannot be read — but **not against whoever
 * gets the browser session**: they only have to call the decryption API. With the lock, the master
 * key only exists in memory, after an entry.
 */
import { fromBase64, toBase64 } from "./keys";
import { loadCrypto } from "./wasm";

/** See the note on `buffer` in `keys.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

const SALT_LEN = 16;
const IV_LEN = 12;

/** What is stored in the clear next to the state. Nothing here is secret. */
export interface LockEnvelope {
  /** Argon2id salt. Public: its role is to rule out precomputed tables. */
  salt: string;
  /** Master key encrypted under the unlock key: `iv ‖ ciphertext`. */
  wrapped: string;
}

/** Creates a fresh lock: random master key, sealed under the password. */
export async function createLock(password: string): Promise<[LockEnvelope, CryptoKey]> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const master = crypto.getRandomValues(new Uint8Array(32));

  const envelope = { salt: toBase64(salt), wrapped: await seal(password, salt, master) };
  return [envelope, await importRawMaster(master)];
}

/**
 * Opens the lock. Rejects if the password is wrong.
 *
 * The failure comes from the AEAD: without the right key, decrypting the master key does not
 * produce wrong bytes, it fails. So there is nothing to compare and no risk of a non-constant
 * comparison — that property is what lets us do without a "password hash" stored alongside, which
 * would be one more target for an offline attack.
 */
export async function openLock(envelope: LockEnvelope, password: string): Promise<CryptoKey> {
  const salt = fromBase64(envelope.salt);
  const blob = fromBase64(envelope.wrapped);

  const unlock = await unlockKey(password, salt);
  const master = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(blob.slice(0, IV_LEN)) },
      unlock,
      buffer(blob.slice(IV_LEN)),
    ),
  );

  return importRawMaster(master);
}

/**
 * Changes the password without touching the encrypted state.
 *
 * Requires the old one: without it the master key cannot be recovered, and replacing it with a
 * fresh one would make all the state unreadable. Someone who finds an unlocked device therefore
 * cannot change its password to appropriate its contents.
 */
export async function changePassword(
  envelope: LockEnvelope,
  before: string,
  after: string,
): Promise<LockEnvelope> {
  const master = await openLock(envelope, before);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", master));

  // Fresh salt: reusing the old one would let an attacker who captured both versions attack both
  // passwords for the same derivation work.
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  return { salt: toBase64(salt), wrapped: await seal(after, salt, raw) };
}

async function seal(password: string, salt: Uint8Array, master: Uint8Array): Promise<string> {
  const unlock = await unlockKey(password, salt);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(iv) }, unlock, buffer(master)),
  );

  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  return toBase64(out);
}

/**
 * Derives the unlock key. **Blocks for about a second.**
 *
 * Argon2id comes from the WebAssembly module: WebCrypto only offers PBKDF2, which costs compute
 * alone and parallelises on GPUs for almost nothing. Argon2id's memory cost is what makes an
 * offline attack genuinely expensive.
 */
async function unlockKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const crypt = await loadCrypto();
  const derived = crypt.deriveUnlockKey(password, salt);

  // Non-extractable: once imported, this key can no longer leave the browser.
  return crypto.subtle.importKey("raw", buffer(derived), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * The master key is imported **extractable**, because a password change has to be able to re-seal
 * it. It is the only secret in the system in that position, and it never leaves memory: it is
 * neither persisted in the clear nor transmitted.
 */
function importRawMaster(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buffer(raw), "AES-GCM", true, ["encrypt", "decrypt"]);
}

/**
 * The raw bytes of the master key.
 *
 * # Why this door exists
 *
 * Biometric unlock has to hand the key to the native process, which seals it and only returns it
 * after the system prompt. Without an export there would be nothing to hand over.
 *
 * # Why it is narrow
 *
 * A single caller, in `Session.enableBiometric`, and it immediately pushes the bytes across the
 * boundary. Any other use would call into question the fact that the master key only exists in
 * memory — the property that makes the lock hold.
 */
export function exportMaster(master: CryptoKey): Promise<Uint8Array> {
  return crypto.subtle.exportKey("raw", master).then((raw) => new Uint8Array(raw));
}

/** Re-imports a master key returned by the native process. */
export function importMaster(raw: Uint8Array): Promise<CryptoKey> {
  return importRawMaster(raw);
}
