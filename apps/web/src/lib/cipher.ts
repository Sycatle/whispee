/**
 * What a device can do with its secrets, without ever showing them.
 *
 * # A capability, not a key holder
 *
 * `DeviceKeys` — two `CryptoKey`s passed from function to function — required the secret to
 * circulate, even in a form WebCrypto refuses to export. This interface requires the opposite:
 * the caller asks for a signature or a decryption, and never sees key material.
 *
 * The distinction is not cosmetic. It is what will let the key live somewhere other than the
 * webview — in the Rust process, then in the system keychain — without the rest of the code
 * knowing anything changed.
 *
 * # The problem this prepares for
 *
 * MLS state is currently persisted in IndexedDB. On mobile that storage is **not guaranteed**:
 * iOS evicts WKWebView data after seven days of inactivity, Android purges under memory pressure.
 * And losing it is **final** — the MLS ratchet destroys its keys as it goes, so history becomes
 * unreadable and conversations have to be recreated.
 *
 * Moving the state alone would not be enough: the device's authentication key is at least as
 * fatal to lose, and worse, it is non-extractable and the server **refuses to change it** (see the
 * `auth_key` clause in `register_device`). Saved state whose authentication key has vanished is
 * useless: the device can no longer issue a request.
 *
 * Hence an interface that covers both — signing and sealing — rather than a plain storage port.
 *
 * # What "non-extractable" protects, and what it does not
 *
 * It prevents key material from being exfiltrated. It does **not** prevent a hostile script from
 * using it while the page is open. The distinction matters: a stolen key is permanent, abuse ends
 * with the session. A key held by the Rust process and exposed over IPC offers exactly the same
 * property, guaranteed this time by a process boundary rather than by a JavaScript engine policy.
 */
import { invoke } from "@tauri-apps/api/core";

import {
  type DeviceKeys,
  fromBase64,
  sign as signWithWebCrypto,
  toBase64,
  unwrapState,
  wrapState,
} from "./keys";

export interface DeviceCipher {
  /** The public authentication key, as bytes — the only half that leaves the device. */
  authPublicKey(): Promise<Uint8Array>;

  /** Signs a request message. Returns the signature in base64, ready for the header. */
  sign(payload: Uint8Array): Promise<string>;

  /** Encrypts for local persistence. */
  seal(plaintext: Uint8Array): Promise<Uint8Array>;

  /** Decrypts what `seal` produced. */
  open(blob: Uint8Array): Promise<Uint8Array>;
}

/**
 * The original implementation, backed by the non-extractable `CryptoKey`s in IndexedDB.
 *
 * Still the only path on the web, where there is nothing better: the browser is the only party
 * able to keep a secret out of reach of the script it runs.
 */
export class WebCryptoCipher implements DeviceCipher {
  private readonly keys: DeviceKeys;

  constructor(keys: DeviceKeys) {
    this.keys = keys;
  }

  async authPublicKey(): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.exportKey("raw", this.keys.auth.publicKey));
  }

  sign(payload: Uint8Array): Promise<string> {
    return signWithWebCrypto(this.keys, payload);
  }

  /**
   * Encrypts under the non-extractable key stored next to the identity keys.
   *
   * It protects against exfiltration by script, not against whoever gets the browser session.
   * That is exactly what the local lock fixes — see `LockedCipher`.
   */
  seal(plaintext: Uint8Array): Promise<Uint8Array> {
    return wrapState(this.keys.wrap, plaintext);
  }

  open(blob: Uint8Array): Promise<Uint8Array> {
    return unwrapState(this.keys.wrap, blob);
  }
}

/**
 * The same capabilities, provided by the native process.
 *
 * # What it changes, and what it does not
 *
 * The keys live on the Rust side, in the application's private directory — only purged on
 * uninstall, where a mobile webview's storage is evicted without warning. Durability is what
 * we are after here.
 *
 * It is **not** a hardening measure against a hostile script. It could already use the
 * non-extractable `CryptoKey`s without extracting them; it can still call these commands. What
 * changes is the guarantee that prevents extraction: a process boundary instead of a JavaScript
 * engine policy.
 *
 * # Why nothing uses it yet
 *
 * Switching an existing installation over to these keys would break it: the native keys are new,
 * so state encrypted under the old key becomes unreadable and the server no longer recognises the
 * device's signature. The switch is inseparable from the migration, and the migration hits a hard
 * point — the current authentication key is non-extractable and `register_device` refuses to
 * change it, so already-registered devices cannot move it.
 *
 * Wiring it up before settling that would not save time: it would lose accounts.
 */
export class NativeCipher implements DeviceCipher {
  async authPublicKey(): Promise<Uint8Array> {
    return fromBase64(await invoke<string>("device_public_key"));
  }

  /** Already returns base64: the native command signs and encodes, there is nothing to convert. */
  sign(payload: Uint8Array): Promise<string> {
    return invoke<string>("device_sign", { payload: toBase64(payload) });
  }

  async seal(plaintext: Uint8Array): Promise<Uint8Array> {
    return fromBase64(await invoke<string>("state_seal", { plaintext: toBase64(plaintext) }));
  }

  async open(blob: Uint8Array): Promise<Uint8Array> {
    return fromBase64(await invoke<string>("state_open", { blob: toBase64(blob) }));
  }
}

/**
 * A device whose state at rest is protected by a password.
 *
 * # What changes, and what does not
 *
 * The identity does not move: signing stays the base layer's job, so the server sees nothing
 * and setting or removing a lock is never an account event. Only the key that protects state on
 * disk swaps out.
 *
 * # Why it wraps instead of replacing
 *
 * The lock is orthogonal to where the keys live. A locked web device and a locked native device
 * pose the same problem — encrypting under a master key that only exists in memory once
 * entered — and there is no reason to write two versions of it.
 *
 * # The base layer does not seal on top
 *
 * State is encrypted under the master key, full stop. Delegating to the base layer afterwards
 * would add a layer, change the format already written on existing installations, and bring
 * nothing against the only attacker this lock targets: the one holding the device without the
 * password. Without the password, the state is unreadable either way.
 */
export class LockedCipher implements DeviceCipher {
  private readonly base: DeviceCipher;
  private readonly master: CryptoKey;

  constructor(base: DeviceCipher, master: CryptoKey) {
    this.base = base;
    this.master = master;
  }

  authPublicKey(): Promise<Uint8Array> {
    return this.base.authPublicKey();
  }

  sign(payload: Uint8Array): Promise<string> {
    return this.base.sign(payload);
  }

  seal(plaintext: Uint8Array): Promise<Uint8Array> {
    return wrapState(this.master, plaintext);
  }

  open(blob: Uint8Array): Promise<Uint8Array> {
    return unwrapState(this.master, blob);
  }

  /**
   * The master key, to hand over to the native process.
   *
   * The only legitimate caller is enabling biometric unlock, which has to get it sealed where the
   * system prompt keeps it. Any other use would undo what makes the lock hold: that this key only
   * exists in memory, and only after an entry.
   */
  masterKey(): CryptoKey {
    return this.master;
  }
}

/** Re-exported so callers do not have to import `keys.ts` just to encode. */
export { toBase64 };
