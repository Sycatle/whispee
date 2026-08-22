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
    signalsAt: session.signalsAt,
    postingKeys: session.postingKeys,
    logHead: session.logHead,
    history: session.history === undefined ? undefined : toBase64(session.history),
    discloseConversationName: session.discloseConversationName,
    conversationFlags: session.conversationFlags,
    locale: session.locale,
    searchCoverage: session.searchCoverage,
    contactPolicy: session.contactPolicy,
    blocked: session.blocked,
    recentEmojis: session.recentEmojis,
    skinTone: session.skinTone,
    displayName: session.displayName,
    profiles: session.profiles,
    petnames: session.petnames,
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
    ...(typeof field.signalsAt === "number" ? { signalsAt: field.signalsAt } : {}),
    ...(field.postingKeys === undefined
      ? {}
      : { postingKeys: field.postingKeys as Record<string, string> }),
    // Absent on any session written before the anchor was persisted. Treated as "no anchor",
    // which is what those sessions actually had — the first resolve then re-establishes one.
    ...(field.logHead === undefined
      ? {}
      : { logHead: field.logHead as StoredSession["logHead"] }),
    ...(field.history === undefined
      ? {}
      : { history: fromBase64(requireString(field.history, "history")) }),
    ...(field.discloseConversationName === undefined
      ? {}
      : { discloseConversationName: field.discloseConversationName as boolean }),
    // Everything below is additive and optional, and none of it bumped `VERSION`. That is the
    // whole point: `decodeSession` throws on a version it does not recognise, so raising the
    // number to announce a field nothing is required to read would refuse every session written
    // before today, on both directions of an upgrade. A reader that tolerates absence needs no
    // announcement; a reader that does not would not be fixed by one.
    ...(field.conversationFlags === undefined
      ? {}
      : { conversationFlags: field.conversationFlags as StoredSession["conversationFlags"] }),
    ...(field.locale === undefined ? {} : { locale: requireString(field.locale, "locale") }),
    ...(field.searchCoverage === undefined
      ? {}
      : { searchCoverage: field.searchCoverage as StoredSession["searchCoverage"] }),
    ...(field.contactPolicy === undefined
      ? {}
      : { contactPolicy: field.contactPolicy as StoredSession["contactPolicy"] }),
    ...(field.blocked === undefined
      ? {}
      : {
          blocked: requireArray(field.blocked, "blocked").map((value, index) =>
            requireString(value, `blocked[${index}]`),
          ),
        }),
    ...(field.recentEmojis === undefined
      ? {}
      : {
          recentEmojis: requireArray(field.recentEmojis, "recentEmojis").map((value, index) =>
            requireString(value, `recentEmojis[${index}]`),
          ),
        }),
    // Spread conditionally like every other scalar, and here it carries meaning: absent is
    // "nobody chose a skin tone", `0` is "somebody chose the yellow one". Normalising the first
    // to the second would silently claim a decision was made.
    ...(field.skinTone === undefined
      ? {}
      : { skinTone: field.skinTone as StoredSession["skinTone"] }),
    // Three more additive optionals, and `VERSION` stays at 1 for the reason spelled out just
    // above: raising it to announce fields nothing is required to read would make this decoder
    // refuse every session written before today, in both directions of an upgrade.
    ...(field.displayName === undefined
      ? {}
      : { displayName: requireString(field.displayName, "displayName") }),
    ...(field.profiles === undefined
      ? {}
      : { profiles: requireObject(field.profiles, "profiles") as StoredSession["profiles"] }),
    ...(field.petnames === undefined
      ? {}
      : { petnames: requireObject(field.petnames, "petnames") as Record<string, string> }),
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
