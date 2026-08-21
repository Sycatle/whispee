/**
 * Turning the session into bytes, for the stores that can only hold bytes.
 *
 * # Why this module exists on its own
 *
 * IndexedDB takes a `StoredSession` as it is: structured cloning carries a `Uint8Array`, and
 * even a non-extractable `CryptoKey`. A file knows none of that. The native store therefore
 * needs a translation, and that translation is the only place where the session's shape
 * invariants are written down — which is worth being able to test without a database or a Rust
 * process.
 *
 * # What the codec does not carry
 *
 * The keys. `StoredSession` holds none: on the web they live in the same database, but it is the
 * store that puts them there, not the session. A file could not receive them — non-extractable
 * `CryptoKey`s do not serialise, by construction — and it does not have to: under Tauri they
 * live in the native process, behind `NativeCipher`.
 *
 * # The field that justifies the tests
 *
 * `vaultEnabled` has **three** states, not two: absent means "on" — the vault is the default —
 * while `false` is an explicit refusal by the user. A codec that normalised absence to `false`
 * would cut backup off for a fresh account; a codec that normalised `false` to absent would turn
 * it back on behind the back of someone who had turned it off. The second mistake is the worse
 * one, and neither is visible to the naked eye. Same reasoning for `signals.presence`.
 */
import { fromBase64, toBase64 } from "./keys.ts";
import type { StoredSession } from "./storage";

/**
 * On-disk format version.
 *
 * Present from the first version: adding it after the fact would mean guessing the age of a file
 * that does not say.
 */
const VERSION = 1;

/**
 * Encodes to UTF-8 JSON.
 *
 * Bytes become base64 rather than an array of numbers — a `Uint8Array` handed to `JSON.stringify`
 * becomes an object keyed by strings, which reads back as an object and not as a byte array. The
 * breakage would be silent: `state` would come back as an empty object rather than failing.
 */
export function encodeSession(session: StoredSession): Uint8Array {
  const raw = {
    v: VERSION,
    deviceId: session.deviceId,
    handle: session.handle,
    accountSeed: toBase64(session.accountSeed),
    lock: session.lock,
    vaultEnabled: session.vaultEnabled,
    state: session.state === undefined ? undefined : toBase64(session.state),
    groupIds: session.groupIds.map(toBase64),
    verified: session.verified,
    cursors: session.cursors,
    knownDevices: session.knownDevices,
    signals: session.signals,
    postingKeys: session.postingKeys,
  };

  return new TextEncoder().encode(JSON.stringify(raw));
}

/**
 * Reads back what `encodeSession` produced, or throws.
 *
 * Throwing rather than returning a partial session: an MLS state stripped of its cursor would
 * replay already-consumed keys, and the conversation would stay empty after a simple reload. An
 * error visible at startup beats a session that seems to work.
 */
export function decodeSession(bytes: Uint8Array): StoredSession {
  const raw: unknown = JSON.parse(new TextDecoder().decode(bytes));

  if (typeof raw !== "object" || raw === null) {
    throw new Error("unreadable session: the root is not an object");
  }

  const field = raw as Record<string, unknown>;

  if (field.v !== VERSION) {
    throw new Error(`session is version ${String(field.v)}, expected ${VERSION}`);
  }

  return {
    deviceId: requireString(field.deviceId, "deviceId"),
    handle: requireString(field.handle, "handle"),
    accountSeed: fromBase64(requireString(field.accountSeed, "accountSeed")),
    // Optionals are spread conditionally rather than assigned `undefined`: a property that is
    // present and holds `undefined` is not the same as an absent one for `Object.keys`, for a
    // structural comparison, or for a future `in`. Since the whole subtlety of `vaultEnabled` is
    // the absent / `false` distinction, the shape read back should be exactly the one written.
    ...(field.lock === undefined ? {} : { lock: field.lock as StoredSession["lock"] }),
    ...(field.vaultEnabled === undefined ? {} : { vaultEnabled: field.vaultEnabled as boolean }),
    ...(field.state === undefined
      ? {}
      : { state: fromBase64(requireString(field.state, "state")) }),
    groupIds: requireArray(field.groupIds, "groupIds").map((value, index) =>
      fromBase64(requireString(value, `groupIds[${index}]`)),
    ),
    verified: requireObject(field.verified, "verified") as Record<string, string>,
    cursors: requireObject(field.cursors, "cursors") as Record<string, number>,
    knownDevices: requireObject(field.knownDevices, "knownDevices") as Record<string, string[]>,
    ...(field.signals === undefined ? {} : { signals: field.signals as StoredSession["signals"] }),
    ...(field.postingKeys === undefined
      ? {}
      : { postingKeys: field.postingKeys as Record<string, string> }),
  };
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`unreadable session: ${name} is not a string`);
  return value;
}

function requireArray(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`unreadable session: ${name} is not an array`);
  return value;
}

function requireObject(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`unreadable session: ${name} is not an object`);
  }
  return value as Record<string, unknown>;
}
