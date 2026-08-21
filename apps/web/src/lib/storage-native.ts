/**
 * The session kept by the native process rather than by the webview.
 *
 * # What that buys
 *
 * Durability, and nothing else. A mobile webview's storage **is not guaranteed**: iOS evicts
 * WKWebView data after seven days of inactivity, Android purges under memory pressure. And the
 * loss is permanent — the MLS ratchet destroys its keys as it goes, so history becomes
 * unreadable and conversations have to be recreated. The app's private directory, by contrast,
 * is only purged on uninstall.
 *
 * # Encryption stays here, not on the Rust side
 *
 * `session_save` writes the bytes it is given, without looking at them. That is deliberate:
 * encryption goes through `DeviceCipher`, the same abstraction as on the web, so the on-disk
 * format does not depend on the platform and the day a local lock changes the at-rest key, there
 * is only one place to touch.
 *
 * # Why the bridge is injected
 *
 * `invoke` only exists inside a Tauri webview. Passing it as a parameter makes this class
 * testable without an app — and the test that matters here is a full round trip, sealing
 * included, since it is the codec → encryption → file chain that can lose an account, not any
 * one of its links.
 */
import { invoke } from "@tauri-apps/api/core";

import { fromBase64, toBase64 } from "./keys.ts";
import { decodeSession, encodeSession } from "./session-codec.ts";
import type { SessionStore, StoredSession } from "./storage.ts";
import type { DeviceCipher } from "./cipher.ts";

/**
 * The three native commands the store needs.
 *
 * Deliberately narrower than the full command set: what handles keys goes through
 * `DeviceCipher`, what handles the file goes through here, and neither can do the other's job.
 */
export interface SessionBridge {
  /** The sealed blob, in base64, or `null` on first launch. */
  load(): Promise<string | null>;
  save(content: string): Promise<void>;
  clear(): Promise<void>;
}

/**
 * The real bridge, backed by Tauri's IPC.
 *
 * `invoke` is imported statically: `cipher.ts` already does it, so deferring it here would take
 * nothing out of the bundle — it would only create the illusion that the module loads without
 * Tauri. The call itself only happens if someone builds this bridge.
 */
export function tauriBridge(): SessionBridge {
  return {
    load: () => invoke<string | null>("session_load"),
    save: (content) => invoke<void>("session_save", { content }),
    clear: () => invoke<void>("session_clear"),
  };
}

/**
 * The native store.
 *
 * # The same port as the browser store
 *
 * `StoredSession` carries no keys: the browser's are kept by `IndexedDbStore`, these live in the
 * native process. That is what lets both stores satisfy the same interface, and the session
 * ignore which of the two serves it.
 *
 * # An existing install does not switch over as it is
 *
 * Its keys are locked inside IndexedDB, non-extractable, and the server **refuses to change
 * them** (the `auth_key` clause in `register_device`). A native store backed by fresh native keys
 * could neither read its old state nor prove its identity: a new device has to be registered and
 * the old one revoked. See `migration.ts`.
 */
export class NativeStore implements SessionStore {
  // Declared fields rather than parameter properties: Node's test runner only strips types, and
  // a parameter property would require a transform.
  private readonly cipher: DeviceCipher;
  private readonly bridge: SessionBridge;

  constructor(cipher: DeviceCipher, bridge: SessionBridge) {
    this.cipher = cipher;
    this.bridge = bridge;
  }

  async load(): Promise<StoredSession | undefined> {
    const sealed = await this.bridge.load();
    // `null` is a first launch, not a failure. Confusing the two would create a fresh account on
    // top of a state that is still there, which is irreversible.
    if (sealed === null) return undefined;

    return decodeSession(await this.cipher.open(fromBase64(sealed)));
  }

  async save(session: StoredSession): Promise<void> {
    const sealed = await this.cipher.seal(encodeSession(session));
    await this.bridge.save(toBase64(sealed));
  }

  /**
   * Erases the session, **and not the secrets**.
   *
   * The native command deliberately stops there: forgetting a session leaves a registered device
   * that starts over, erasing the secrets leaves an identity the server still knows about but
   * that nobody can prove any more. The second erasure exists, and it is another call.
   */
  async clear(): Promise<void> {
    await this.bridge.clear();
  }
}
