/**
 * What we are running on.
 *
 * # Detected at run time, not at build time
 *
 * `apps/web` produces **one** `dist/`, served by the web and bundled into the desktop binary
 * alike (`frontendDist` in `tauri.conf.json`). Producing two separate bundles would mean two
 * builds, two verification chains and two artefacts to sign, to settle a case that three bytes
 * settle.
 *
 * The accepted cost: the native code ends up in the web bundle, where it is dead. It is small.
 */

/**
 * True when the page is served by Tauri.
 *
 * Tests for the object Tauri injects into the webview before any script on the page.
 * Deliberately not `navigator.userAgent`, which webviews disguise, nor the protocol, which
 * differs by system — `tauri://localhost` on Linux and macOS, `http://tauri.localhost` on
 * Windows and Android.
 */
export function isTauri(): boolean {
  return "__TAURI_INTERNALS__" in globalThis;
}
