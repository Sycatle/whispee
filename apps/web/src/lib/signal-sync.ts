/**
 * The signalling settings of an account, carried between its own devices.
 *
 * # What this fixes
 *
 * `SignalSettings` lives in the local encrypted session, and `lib/storage.ts` gives the reason:
 * telling the server which accounts refuse to be observed would be teaching it exactly what the
 * refusal is meant to withhold. The reason holds. What did not hold is the consequence —
 * `Session.acknowledge` runs per session, so an account that turned read receipts off on its
 * laptop kept sending them from its phone, and no screen said so.
 *
 * Presence never had the problem: `accounts.presence_optout` is a column on the account, because
 * the server is the one that *executes* that rule. Receipts and the typing indicator have no such
 * executor — the server cannot see either of them, which is the point — so the only place the
 * settings can meet is a channel the devices already share.
 *
 * # The channel
 *
 * Every device of an account is a member of every conversation of that account
 * (`Session.propagateOwnDevices`, and the parity invariant it states). So a control message sent
 * to a group reaches our other devices. It also reaches the peers, which is why it is sealed:
 * `content.ts` states that argument at `TYPE_SIGNALS` and it is the reason this module exists at
 * all rather than a plain struct in the message body.
 *
 * # And then the rest of the preferences
 *
 * The same defect ran through everything else kept locally: a conversation muted on the laptop
 * kept buzzing on the phone, a block held on one device and not the other. `session-types.ts`
 * already said so about the per-conversation flags — "pinning something on a laptop therefore
 * does nothing to a phone, and the settings screen has to say so rather than let it be
 * discovered" — and the screen never said it.
 *
 * They travel in the same message, appended after the nine fixed bytes. What made them wait was
 * not the channel but the arbitration: a single timestamp over a *map* loses edits, so each entry
 * carries its own and removals are stamped rather than merely absent. `stamped.ts` is that rule,
 * and it is where the argument for it lives.
 */
import type { ConversationFlags } from "./session-types.ts";
import type { StampedPatch } from "./stamped.ts";

/** The three switches of the "Receipts and indicators" panel, as they travel. */
export interface SyncedSignals {
  readReceipts: boolean;
  typingIndicator: boolean;
  presence: boolean;
  calls: boolean;
  /** When the device that sent this claims to have changed it. Clamped on receipt. */
  at: number;
}

/**
 * Everything else an account's devices owe each other.
 *
 * # Why these and not the rest
 *
 * The test is whether the preference is a fact about the *account* or about the *machine*.
 * Muting a conversation is about the conversation, so a phone that keeps buzzing after the laptop
 * silenced it is simply wrong. The language the interface is drawn in is about the machine — a
 * work laptop in English and a phone in French is a choice, not a drift — and so is
 * `searchCoverage`, which records how much history *this* disk was willing to index. Those stay
 * where they are.
 *
 * `recentEmojis` and `skinTone` are account facts and are still left out, for a different reason:
 * they change on nearly every message. Syncing them would spend an envelope per conversation on
 * somebody reaching for a thumbs-up.
 *
 * # Why petnames may travel now, having been forbidden
 *
 * `storage.ts` refused to emit them, and was right at the time: "sending one would hand a peer the
 * note taken about them". This channel is sealed under a key only our own devices derive, so the
 * peer carries the note without being able to read it. The objection was about the channel, and
 * the channel changed.
 */
export interface SyncedPreferences {
  /** `discloseConversationName` and `vaultEnabled`, which move together as one decision. */
  scalars: { at: number; disclose: boolean; vault: boolean };
  /** Per conversation, by hex group id. */
  flags: StampedPatch<ConversationFlags>;
  /** Per account, the name we have overruled theirs with. */
  petnames: StampedPatch<string>;
  /** Per account, present when blocked. The value is always `true`; absence is the removal. */
  blocked: StampedPatch<true>;
}

const IV_LEN = 12;

/**
 * `u64 BE milliseconds ‖ u8 bitfield`, and then, optionally, UTF-8 JSON.
 *
 * # Why the preferences are appended rather than given their own message
 *
 * One message means one envelope, and an envelope is padded, stored for thirty days and counted
 * against a conversation's purge window. Two would double that for a pair of records that always
 * change in the same session and are always read by the same code.
 *
 * # Why the first nine bytes did not move
 *
 * They are exactly the layout that shipped, so a device running the older build still reads the
 * signalling settings out of a message from a newer one — it stops at nine bytes and never looks
 * further. The reverse also holds: nine bytes and nothing after is a valid message, and it is
 * what an older device sends. Preferences simply do not travel until both ends are new, which is
 * the honest failure and not a silent one.
 */
const PLAINTEXT_LEN = 8 + 1;

/**
 * How much sealed JSON we are willing to put on the wire.
 *
 * Sixteen kilobytes holds several hundred conversations' flags along with the petnames and blocks
 * of a lifetime; nothing an ordinary account produces comes close. It is a bound rather than an
 * expectation — a decoder without one lets whoever writes the message decide how much memory it
 * costs, and "whoever" includes a future version of ourselves with a bug in it.
 *
 * `Session` reports rather than truncates when a snapshot exceeds this. Half a preference set is
 * worse than none: it would read as a decision to clear whatever fell off the end.
 */
export const MAX_PREFERENCES_BYTES = 16 * 1024;

const BIT_READ_RECEIPTS = 1;
const BIT_TYPING = 2;
const BIT_PRESENCE = 4;
/**
 * **This bit records a refusal, where the three above record a permission.**
 *
 * Not an inconsistency — a necessity. A device built before calls existed announces a byte with
 * this bit clear, and it announces it every time it changes any other setting. Were the bit to
 * mean "calls on", that device would silently turn calls off across the whole account, from a
 * version of the client that has never heard of them.
 *
 * The same reasoning is why `SignalSettings.calls` is optional and absent means enabled, and why
 * the server's own `presence_optout` column is named the way it is.
 */
const BIT_CALLS_OFF = 8;

/**
 * How far ahead of our own clock a device's self-declared time may sit before we replace it.
 *
 * Five minutes, the value and the argument of `PROFILE_CLOCK_SKEW_MS` in `content.ts`. It matters
 * less here — the sender is one of our own devices, not a hostile peer — but a device whose clock
 * is simply wrong would otherwise win last-writer-wins forever, and its owner would have no way
 * to tell why their setting keeps coming back.
 */
const CLOCK_SKEW_MS = 5 * 60 * 1000;

/** Imports the device-sync key. Non-extractable once inside the browser, as the vault key is. */
export function importSyncKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buffer(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

/**
 * Seals the settings for our other devices.
 *
 * A fresh random nonce per message, as the vault does and for the same reason: AES-GCM breaks
 * catastrophically on a nonce reused under one key, and this key never changes.
 */
export async function sealSignals(
  key: CryptoKey,
  signals: SyncedSignals,
  preferences?: SyncedPreferences,
): Promise<Uint8Array> {
  const tail =
    preferences === undefined ? new Uint8Array(0) : new TextEncoder().encode(JSON.stringify(preferences));
  if (tail.length > MAX_PREFERENCES_BYTES) throw new Error("preference snapshot too large");

  const plaintext = new Uint8Array(PLAINTEXT_LEN + tail.length);
  new DataView(plaintext.buffer).setBigUint64(0, BigInt(Math.max(0, Math.trunc(signals.at))), false);
  plaintext[8] =
    (signals.readReceipts ? BIT_READ_RECEIPTS : 0) |
    (signals.typingIndicator ? BIT_TYPING : 0) |
    (signals.presence ? BIT_PRESENCE : 0) |
    (signals.calls ? 0 : BIT_CALLS_OFF);
  plaintext.set(tail, PLAINTEXT_LEN);

  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(iv) }, key, buffer(plaintext)),
  );

  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  return out;
}

/**
 * Opens a sealed settings blob, or returns `null`.
 *
 * `null` rather than a throw, because failure is the ordinary case and not an error: every peer
 * in the room receives this message and cannot open it. Only the sender's own devices hold the
 * key. Distinguishing "not for us" from "corrupt" would need the sender's identity, which the
 * caller has and this does not.
 *
 * The time is clamped here rather than by the caller, so that no path can forget it.
 */
export async function openSignals(
  key: CryptoKey,
  sealed: Uint8Array,
  now: number,
): Promise<{ signals: SyncedSignals; preferences?: SyncedPreferences } | null> {
  if (sealed.length <= IV_LEN) return null;

  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: buffer(sealed.subarray(0, IV_LEN)) },
        key,
        buffer(sealed.subarray(IV_LEN)),
      ),
    );
  } catch {
    return null;
  }

  // Shorter than the fixed head is not a version of this format at all — it authenticated under
  // our own key, so it is our own bug rather than an attack, and reading a truncated header is how
  // a setting gets silently inverted.
  if (plaintext.length < PLAINTEXT_LEN) return null;

  const declared = Number(new DataView(plaintext.buffer, plaintext.byteOffset).getBigUint64(0, false));
  const flags = plaintext[8];
  const clamp = (at: number) => (at > now + CLOCK_SKEW_MS ? now : at);

  const signals: SyncedSignals = {
    readReceipts: (flags & BIT_READ_RECEIPTS) !== 0,
    typingIndicator: (flags & BIT_TYPING) !== 0,
    presence: (flags & BIT_PRESENCE) !== 0,
    // Inverted, and it is the bit's own doc that says why: the flag records a refusal, so a byte
    // from a device that has never heard of calls reads as "on" rather than silencing them.
    calls: (flags & BIT_CALLS_OFF) === 0,
    at: clamp(declared),
  };

  // Nothing after the head is an older device, which sent settings and had no preferences to
  // send. That is a message with no preferences in it, not a message asking to clear them.
  if (plaintext.length === PLAINTEXT_LEN) return { signals };
  if (plaintext.length - PLAINTEXT_LEN > MAX_PREFERENCES_BYTES) return { signals };

  const preferences = readPreferences(plaintext.subarray(PLAINTEXT_LEN), clamp);
  return preferences === null ? { signals } : { signals, preferences };
}

/**
 * Parses the appended preferences, or `null` if they are not what this build expects.
 *
 * # Why every field is checked rather than cast
 *
 * The bytes authenticated under a key only our own devices hold, so this is not defence against a
 * peer. It is defence against ourselves: a later build that changes the shape, a partial write, a
 * field that turned out to be optional. Casting would let any of those through as far as the
 * merge, which writes to disk — and a preference set corrupted there is not recoverable from the
 * network, because every other device would eventually be told the corrupt version is the newer
 * one.
 *
 * Losing the preferences of one message is cheap: they are re-announced at every epoch.
 */
function readPreferences(
  tail: Uint8Array,
  clamp: (at: number) => number,
): SyncedPreferences | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(tail));
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null) return null;
  const body = parsed as Record<string, unknown>;

  const scalars = body.scalars;
  if (typeof scalars !== "object" || scalars === null) return null;
  const { at, disclose, vault } = scalars as Record<string, unknown>;
  if (typeof at !== "number" || typeof disclose !== "boolean" || typeof vault !== "boolean") {
    return null;
  }

  const flags = readPatch<ConversationFlags>(body.flags, clamp, isFlags);
  const petnames = readPatch<string>(body.petnames, clamp, (v): v is string => typeof v === "string");
  const blocked = readPatch<true>(body.blocked, clamp, (v): v is true => v === true);
  if (flags === null || petnames === null || blocked === null) return null;

  return { scalars: { at: clamp(at), disclose, vault }, flags, petnames, blocked };
}

/** One stamped map, with every entry's clock clamped exactly as the scalars' is. */
function readPatch<T>(
  raw: unknown,
  clamp: (at: number) => number,
  isValue: (value: unknown) => value is T,
): StampedPatch<T> | null {
  if (typeof raw !== "object" || raw === null) return null;

  const patch: StampedPatch<T> = {};
  for (const [key, entry] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof entry !== "object" || entry === null) return null;

    const { at, v } = entry as Record<string, unknown>;
    if (typeof at !== "number") return null;
    if (v !== null && !isValue(v)) return null;

    patch[key] = { at: clamp(at), v: v === null ? null : (v as T) };
  }

  return patch;
}

/**
 * A `ConversationFlags`, checked field by field.
 *
 * Every field is optional and absence is meaningful for each of them — `discloseName` and
 * `archiveToVault` have three states, not two — so this rejects wrong *types* and never fills in
 * a default. Unknown keys are tolerated: they are what a later build adds, and dropping the whole
 * record over one would make every upgrade a synchronisation outage.
 */
function isFlags(value: unknown): value is ConversationFlags {
  if (typeof value !== "object" || value === null) return false;
  const flags = value as Record<string, unknown>;

  const optional = (v: unknown, kind: "boolean" | "number") => v === undefined || typeof v === kind;

  return (
    optional(flags.pinned, "boolean") &&
    optional(flags.archived, "boolean") &&
    optional(flags.mutedUntil, "number") &&
    optional(flags.discloseName, "boolean") &&
    optional(flags.archiveToVault, "boolean") &&
    optional(flags.ephemeralMs, "number")
  );
}

/** `Uint8Array` to the `BufferSource` WebCrypto wants. Same helper, same cast, as `vault.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}
