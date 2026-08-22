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
 * # What it does not carry
 *
 * Whether the vault is on, which conversations are muted, who is blocked — none of it, though the
 * format has room. Each of those has its own conflict question to settle, and settling them all
 * at once would settle none of them well.
 */

/** The three switches of the "Receipts and indicators" panel, as they travel. */
export interface SyncedSignals {
  readReceipts: boolean;
  typingIndicator: boolean;
  presence: boolean;
  /** When the device that sent this claims to have changed it. Clamped on receipt. */
  at: number;
}

const IV_LEN = 12;

/** `u64 BE milliseconds ‖ u8 bitfield`. */
const PLAINTEXT_LEN = 8 + 1;

const BIT_READ_RECEIPTS = 1;
const BIT_TYPING = 2;
const BIT_PRESENCE = 4;

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
export async function sealSignals(key: CryptoKey, signals: SyncedSignals): Promise<Uint8Array> {
  const plaintext = new Uint8Array(PLAINTEXT_LEN);
  new DataView(plaintext.buffer).setBigUint64(0, BigInt(Math.max(0, Math.trunc(signals.at))), false);
  plaintext[8] =
    (signals.readReceipts ? BIT_READ_RECEIPTS : 0) |
    (signals.typingIndicator ? BIT_TYPING : 0) |
    (signals.presence ? BIT_PRESENCE : 0);

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
): Promise<SyncedSignals | null> {
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

  // A blob that authenticated under our own key and is still the wrong size is a newer version of
  // this format, written by a device running a later build of ours. Refusing it is right: reading
  // the first nine bytes of something whose layout has changed is how a setting gets silently
  // inverted.
  if (plaintext.length !== PLAINTEXT_LEN) return null;

  const declared = Number(new DataView(plaintext.buffer, plaintext.byteOffset).getBigUint64(0, false));
  const flags = plaintext[8];

  return {
    readReceipts: (flags & BIT_READ_RECEIPTS) !== 0,
    typingIndicator: (flags & BIT_TYPING) !== 0,
    presence: (flags & BIT_PRESENCE) !== 0,
    at: declared > now + CLOCK_SKEW_MS ? now : declared,
  };
}

/** `Uint8Array` to the `BufferSource` WebCrypto wants. Same helper, same cast, as `vault.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}
