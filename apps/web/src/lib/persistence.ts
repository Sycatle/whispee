/**
 * Where the session is kept, and under which key.
 *
 * # Why both together
 *
 * A store and a cipher are not chosen separately: the key that opens the state has to be the one
 * it was sealed under, and the order matters — the keys are needed to build the cipher, and the
 * cipher to open what the store returns. Delivering them as a pair rules out the only wrong
 * assembly possible, the one that would make a state unreadable while saying nothing beyond a
 * decryption error.
 *
 * # Two anchors, not two sessions
 *
 * On the web, keys live in IndexedDB next to the state; under Tauri, in the native process, with
 * the state in a file. `Session` does not know which one serves it, and that is the point: the
 * difference is contained entirely here.
 */
import { NativeCipher, WebCryptoCipher, type DeviceCipher } from "./cipher";
import { generateDeviceKeys, type DeviceKeys } from "./keys";
import { isTauri } from "./platform";
import { IndexedDbStore, readStoredKeys, type SessionStore } from "./storage";
import { NativeStore, tauriBridge } from "./storage-native";

export interface Anchor {
  store: SessionStore;
  /**
   * The **base** cipher: the one that carries the device identity.
   *
   * Distinct from the at-rest key, which the local lock replaces. Setting a lock does not change
   * the identity — the server sees nothing — so it is the base that is kept here.
   */
  cipher: DeviceCipher;
}

/** The native anchor. Nothing to load: the keys are already in the process. */
export function nativeAnchor(): Anchor {
  const cipher = new NativeCipher();
  return { store: new NativeStore(cipher, tauriBridge()), cipher };
}

/**
 * The browser anchor, if it already exists.
 *
 * `undefined` when the database holds no keys: that is a fresh install, and creating keys here
 * would write them before an account exists.
 */
export async function existingWebAnchor(): Promise<Anchor | undefined> {
  const keys = await readStoredKeys();
  return keys === undefined ? undefined : webAnchor(keys);
}

export function webAnchor(keys: DeviceKeys): Anchor {
  return { store: new IndexedDbStore(keys), cipher: new WebCryptoCipher(keys) };
}

/** Brand-new browser keys, for a device that does not exist yet. */
export async function newWebAnchor(): Promise<Anchor> {
  return webAnchor(await generateDeviceKeys());
}

/**
 * The anchor for a new device on this platform.
 *
 * Under Tauri, native: that is the whole point, since a mobile webview's storage is evicted
 * without warning and a lost MLS state is lost for good. Elsewhere, IndexedDB, for want of
 * better — the browser is still the only thing able to keep a secret out of reach of the script
 * it runs.
 */
export function newAnchor(): Promise<Anchor> {
  return isTauri() ? Promise.resolve(nativeAnchor()) : newWebAnchor();
}

/**
 * The anchor of the session already installed, if there is one.
 *
 * Under Tauri, native is asked first: a native session being present means the migration is
 * done, and any surviving web session is only a leftover to erase. The other order would restart
 * the app on the old, revoked device.
 */
export async function currentAnchor(): Promise<Anchor | undefined> {
  if (isTauri()) {
    const native = nativeAnchor();
    if (await native.store.load()) return native;
  }

  return existingWebAnchor();
}

/**
 * Erases everything kept, on both sides.
 *
 * For the case where the lock password is lost: there is then no session to open, hence no way
 * to know which of the two exists. Erasing both is the only complete answer — forgetting one
 * would let the app restart on the identity the user believes destroyed.
 */
export async function clearAll(): Promise<void> {
  if (isTauri()) await nativeAnchor().store.clear();

  const web = await existingWebAnchor();
  await web?.store.clear();
}
