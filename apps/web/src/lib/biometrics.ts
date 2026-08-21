/**
 * Unlocking with a fingerprint or a face.
 *
 * # What this trades, and who needs to know
 *
 * A password is stored nowhere: it exists only in its owner's head, and that is what makes the
 * state unreadable to whoever walks off with the disk. Turning biometrics on **writes the master
 * key to the device**, sealed by the native process's secrets — which are themselves in the
 * clear in the app's private directory.
 *
 * The protection therefore becomes the system's: the private directory, plus the system prompt
 * in front of the key. That is solid against someone picking the phone up; worth nothing against
 * someone extracting its storage — a `root`, an unencrypted backup, a disk image.
 *
 * It is **strictly weaker** than the password alone. That is not a reason to do without it: a
 * lock removed because it is annoying protects less than a lukewarm lock that is kept. But it is
 * a reason to say so up front, and not in a footnote.
 *
 * # Where the prompt is triggered
 *
 * In the native process, on the path to the key — not here. A prompt raised in JavaScript before
 * the call would be a courtesy a hostile script skips; this one it can only submit to. So this
 * module does nothing but call commands, and holds no security logic: that is intentional, and
 * it is what to check when reading it.
 */
import { invoke } from "@tauri-apps/api/core";

import { fromBase64, toBase64 } from "./keys";
import { isTauri } from "./platform";

/**
 * Can the device offer this unlock?
 *
 * Two conditions, both checked natively: the platform exposes the prompt, and the user has
 * enrolled a fingerprint or a face. A phone where nobody set biometrics up answers no — offering
 * the setting there would give a button that fails in use.
 */
export async function biometricAvailable(): Promise<boolean> {
  if (!isTauri()) return false;

  return invoke<boolean>("biometric_available");
}

/** Is biometric unlock enabled? Raises no prompt. */
export async function biometricEnabled(): Promise<boolean> {
  if (!isTauri()) return false;

  return invoke<boolean>("master_present");
}

/** Stores the master key so the prompt can hand it back. */
export async function enableBiometric(master: Uint8Array): Promise<void> {
  await invoke("master_seal", { master: toBase64(master) });
}

/**
 * Asks for the master key, behind the system prompt.
 *
 * `null` if no key is stored. A refused prompt **throws**: failure has to be distinguishable
 * from absence, otherwise a refusal would send the user back to the password field as if
 * biometrics had never been turned on.
 */
export async function unlockWithBiometric(): Promise<Uint8Array | null> {
  const master = await invoke<string | null>("master_open");
  return master === null ? null : fromBase64(master);
}

/**
 * Removes biometric unlock. The lock stays on; the password still opens it.
 *
 * A no-op outside Tauri rather than an error: removal is called by removing the lock, which
 * exists on every platform, and failing where there is nothing to remove would turn a successful
 * operation into an incident.
 */
export async function disableBiometric(): Promise<void> {
  if (!isTauri()) return;

  await invoke("master_clear");
}
