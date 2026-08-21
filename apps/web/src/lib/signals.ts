/**
 * Ephemeral channel: the signals that are only worth anything right now.
 *
 * # Why a second channel
 *
 * Everything else goes through the MLS application ratchet, which is designed to lose nothing:
 * each message consumes a generation, and too wide a gap breaks decryption of what follows. That
 * is exactly what messages need — and exactly what a typing indicator does not.
 *
 * The consequence is not theoretical. The `envelopes` table is never purged, and **cannot be**
 * without punching a hole in the ratchet. Routing typing through that path would keep, forever, a
 * record of who started to answer and then thought better of it.
 *
 * Here nothing is stored: the server relays and forgets.
 *
 * # What this channel does not guarantee
 *
 * **No forward secrecy within an epoch.** The key comes from the group's exporter secret: every
 * signal of a given epoch falls together if it leaks. Acceptable for data that expires in three
 * seconds; unacceptable for a message, hence the separation.
 *
 * **No sender authentication.** The key is the group's, so any member can produce a signal
 * that appears to come from another. Harmless with two people — there is only one other. In a
 * group, it means a member can make it look like a third party is typing.
 *
 * What it does guarantee is real: the key changes on every commit, so a removed member loses this
 * channel at the same instant as the rest.
 *
 * # How an indicator goes out
 *
 * Never through a stop signal — it could get lost, and the indicator would stay lit forever. Two
 * paths, both local:
 *
 *  * **a message arriving from the author** (`without`), which is the surest proof they have
 *    finished typing, and which costs nothing since we were not waiting for it;
 *  * **expiry** (`fresh`), as a last resort. It needs a timer on the display side: computing that
 *    an entry is stale is useless if nobody repaints. See `nextExpiry`.
 */

/** What a signal carries. A single case, and the format says so explicitly. */
const TYPE_TYPING = 0;

/**
 * How long a received indicator stays displayed.
 *
 * No "stopped typing" signal is emitted: expiry takes care of it, and a stop signal could get lost
 * — leaving the indicator lit indefinitely.
 *
 * Three seconds, not six: that is the delay after which someone who has genuinely stopped typing
 * stops being announced. Raising it makes the indicator lie for longer, which is the only fault it
 * can have.
 *
 * **Expiry has to be rendered, not just computed.** `fresh()` is only evaluated on render; without
 * a timer forcing that render at the right moment, the value below describes nothing. See
 * `Messages.tsx`.
 */
export const TYPING_TTL_MS = 3000;

/**
 * Minimum interval between two emissions while typing.
 *
 * Any shorter and we pay one network deposit per keystroke for information the recipient already
 * has. Any longer than half the TTL and the indicator flickers — hence exactly half of
 * `TYPING_TTL_MS`.
 *
 * It is also the worst-case lag: the last keystroke before stopping can be swallowed by this
 * threshold, so the last signal emitted may date from a second and a half before the real stop.
 */
export const TYPING_DEBOUNCE_MS = 1500;

export interface Typing {
  handle: string;
  /** Local receipt timestamp, for expiry. */
  at: number;
}

/**
 * Seals a typing indicator under the epoch key.
 *
 * The handle travels **inside** the ciphertext. It is not authenticated — see the module header
 * — but it is not visible to the server either, which is the point that matters: the server sees
 * a deposit towards a group, not who made it.
 */
export async function sealTyping(key: Uint8Array, handle: string): Promise<Uint8Array> {
  const body = new TextEncoder().encode(handle);
  const plaintext = new Uint8Array(1 + body.length);
  plaintext[0] = TYPE_TYPING;
  plaintext.set(body, 1);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey("raw", bytes(key), "AES-GCM", false, [
    "encrypt",
  ]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, material, bytes(plaintext)),
  );

  const out = new Uint8Array(iv.length + sealed.length);
  out.set(iv, 0);
  out.set(sealed, iv.length);
  return out;
}

/**
 * Opens a received signal. Returns `undefined` rather than throwing.
 *
 * An unreadable signal is the **normal** case, not an anomaly: the server relays without filtering
 * by epoch, so a signal sent just before a commit arrives after it, under a key that is no longer
 * the right one. Throwing here would surface an error on every change of group composition.
 */
export async function openTyping(
  key: Uint8Array,
  payload: Uint8Array,
): Promise<string | undefined> {
  if (payload.length < 12 + 16) return undefined;

  try {
    const iv = bytes(payload.subarray(0, 12));
    const material = await crypto.subtle.importKey("raw", bytes(key), "AES-GCM", false, [
      "decrypt",
    ]);
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, material, bytes(payload.subarray(12))),
    );

    if (plaintext.length < 1 || plaintext[0] !== TYPE_TYPING) return undefined;
    return new TextDecoder().decode(plaintext.subarray(1));
  } catch {
    return undefined;
  }
}

/** Keeps only the indicators that have not expired. */
export function fresh(typing: Typing[], now: number): Typing[] {
  return typing.filter((entry) => now - entry.at < TYPING_TTL_MS);
}

/**
 * Delay until the next indicator expires, or `undefined` if there is none.
 *
 * Expiry is lazy: `fresh()` is only evaluated on render, and a render only happens on an outside
 * event. But when someone stops typing, that is precisely when nothing happens any more — so the
 * indicator stayed painted on screen until the next event of any kind, that is, the periodic poll,
 * or thirty seconds. This function is what gives the display something to wake itself up with.
 *
 * Never negative: an already expired entry calls for an immediate render, not a `setTimeout` into
 * the past.
 */
export function nextExpiry(typing: Typing[], now: number): number | undefined {
  if (typing.length === 0) return undefined;

  const oldest = Math.min(...typing.map((entry) => entry.at));
  return Math.max(0, oldest + TYPING_TTL_MS - now);
}

/**
 * Removes a correspondent's indicators.
 *
 * Called when a message from them arrives: sending is the surest proof they have finished typing,
 * and it costs no extra signal. Without it, the author of a message appears to keep typing for the
 * whole TTL after sending it.
 *
 * The risk of a "stopped typing" signal does not apply here: nothing is emitted, so nothing can be
 * lost. At worst we fail to switch it off, and expiry takes over.
 */
export function without(typing: Typing[], handle: string): Typing[] {
  return typing.filter((entry) => entry.handle !== handle);
}

/**
 * A `Uint8Array` can be a view onto a larger buffer; `crypto.subtle` takes the whole buffer.
 * Without this copy, we would encrypt neighbouring bytes.
 */
function bytes(view: Uint8Array): ArrayBuffer {
  return view.slice().buffer as ArrayBuffer;
}
