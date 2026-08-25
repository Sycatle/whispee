/**
 * Ephemeral channel: the signals that are only worth anything right now.
 *
 * # Why a second channel
 *
 * Everything else goes through the MLS application ratchet, which is designed to lose nothing:
 * each message consumes a generation, and too wide a gap breaks decryption of what follows. That
 * is exactly what messages need — and exactly what a typing indicator does not.
 *
 * The consequence is not theoretical. The server does prune `envelopes`, but only past thirty
 * days and only five hundred sequences behind the group's head — a quiet conversation never
 * reaches the second condition at all. Routing typing through that path would keep a record of
 * who started to answer and then thought better of it for a month at best, and forever at worst.
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
 * # Why calls are here too, and where they are not
 *
 * A call needs both kinds of traffic, and the split follows the missing sender authentication
 * above rather than any notion of importance.
 *
 * **The invitation is not in this channel.** "X is calling you" is a claim about who is speaking,
 * and this channel cannot support one: any member could ring a group under somebody else's name.
 * It travels as an ordinary MLS message instead — see `content.ts`, kind `call` — where the
 * protocol authenticates its author. That also gives the missed-call entry and the call log for
 * free, and it wakes a sleeping device by the same path a text message does, without telling the
 * server it was a call.
 *
 * **Everything around the invitation is here**: that a device has started ringing, that one of
 * them has answered, that somebody muted or left. Forging any of those changes nothing that
 * matters — the participants of a call are whoever the media layer reports, not whoever claims to
 * be there — and all of them are worthless a few seconds later, which is this channel's whole
 * definition.
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

/**
 * What a signal carries.
 *
 * The leading byte was already there when typing was the only case, which is what makes adding a
 * second one a non-event: a client that predates calls reads a type it does not know and returns
 * `undefined`, which is the path an out-of-epoch signal already takes. No version negotiation, no
 * flag day.
 */
const TYPE_TYPING = 0;
const TYPE_CALL = 1;

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
  /**
   * Who is typing, as an **account id** — not a handle, whatever the wire format's history
   * suggests.
   *
   * The field was called `handle` and held an account id, which is not a harmless discrepancy:
   * `Session.typingIn` filtered these entries against `this.handle` and therefore never matched a
   * single one, so a guard that reads as "never show ourselves typing" had been doing nothing
   * since the account id replaced the handle in the credential. Nothing broke, because
   * `absorbSignal` drops our own indicator before it is ever recorded — but a backstop that
   * cannot fire is not a backstop, and the name was the whole reason nobody noticed.
   *
   * An account id is also the right unit here: every device of an account emits under it, so two
   * of them typing at once collapse to one name on screen rather than two.
   */
  account: string;
  /** Local receipt timestamp, for expiry. */
  at: number;
}

/**
 * What a call frame says.
 *
 * None of these is load-bearing, and the naming tries to keep that visible: they are reports
 * about a device, not instructions to one. Who is actually in a call is whoever the media layer
 * reports; these only make the interface react before it can know.
 *
 *  * `ringing` — this device has started ringing. It is what turns "calling…" into "ringing…" on
 *    the caller's screen, and nothing else depends on it.
 *  * `accepted` — this device has taken the call. The other devices of the *same account* stop
 *    ringing on it. Losing it leaves a phone ringing until the invitation expires, which is the
 *    right way to fail.
 *  * `declined` — this account has refused. The caller stops waiting instead of ringing out.
 *  * `left` — this device is leaving. A courtesy: the media layer reports the departure anyway,
 *    a second or two later.
 *  * `muted` / `unmuted` — the microphone state. It goes through here rather than through the
 *    media server's own participant metadata, which would hand that server one more thing about
 *    a call it is only supposed to relay.
 *  * `alive` — still in the call. It is what lets a ringing device give up on a caller that
 *    vanished without ever managing to say so.
 */
export type CallEvent =
  | "ringing"
  | "accepted"
  | "declined"
  | "left"
  | "muted"
  | "unmuted"
  | "alive";

/** A call frame, as it travels on this channel. */
export interface CallSignal {
  kind: "call";
  event: CallEvent;
  /** Which call this is about. A device in no call, or in another one, ignores the frame. */
  call: string;
  /** Who emits, for display. Unauthenticated, like everything here. */
  account: string;
  /**
   * Which device emits.
   *
   * Calls need this where typing did not. Every device of an account signals under one account
   * id, which is exactly right for "somebody is typing" and exactly wrong for "one of your own
   * devices has answered" — the frame that has to reach the *others*. Filtering our own frames
   * by account would drop it.
   */
  device: string;
}

/** A typing frame. The account id is the unit — see {@link Typing.account}. */
export interface TypingSignal {
  kind: "typing";
  account: string;
}

/** Everything this channel carries. */
export type Signal = TypingSignal | CallSignal;

/** Order of {@link CallEvent} on the wire. Append only: the index *is* the encoding. */
const CALL_EVENTS: readonly CallEvent[] = [
  "ringing",
  "accepted",
  "declined",
  "left",
  "muted",
  "unmuted",
  "alive",
];

/**
 * Seals a signal under the epoch key.
 *
 * Everything but the type byte travels **inside** the ciphertext. None of it is authenticated —
 * see the module header — but none of it is visible to the server either, which is the point that
 * matters: the server sees a deposit towards a group, not who made it nor what it says.
 */
export async function sealSignal(key: Uint8Array, signal: Signal): Promise<Uint8Array> {
  const plaintext = signal.kind === "typing" ? encodeTyping(signal) : encodeCall(signal);

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
 *
 * A signal of an unknown type takes the same path, deliberately. A newer client adding a case is
 * the same situation as an older epoch, from here: something we cannot read and must not report.
 */
export async function openSignal(
  key: Uint8Array,
  payload: Uint8Array,
): Promise<Signal | undefined> {
  if (payload.length < 12 + 16) return undefined;

  try {
    const iv = bytes(payload.subarray(0, 12));
    const material = await crypto.subtle.importKey("raw", bytes(key), "AES-GCM", false, [
      "decrypt",
    ]);
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, material, bytes(payload.subarray(12))),
    );

    if (plaintext.length < 1) return undefined;
    if (plaintext[0] === TYPE_TYPING) return decodeTyping(plaintext.subarray(1));
    if (plaintext[0] === TYPE_CALL) return decodeCall(plaintext.subarray(1));
    return undefined;
  } catch {
    return undefined;
  }
}

function encodeTyping(signal: TypingSignal): Uint8Array {
  const body = new TextEncoder().encode(signal.account);
  const out = new Uint8Array(1 + body.length);
  out[0] = TYPE_TYPING;
  out.set(body, 1);
  return out;
}

function decodeTyping(body: Uint8Array): TypingSignal {
  return { kind: "typing", account: new TextDecoder().decode(body) };
}

/**
 * `[event][len call][call][len device][device][account]`.
 *
 * Two length-prefixed fields and a trailing one, which is the shape the rest of the codebase
 * already uses. Lengths are single bytes because none of these three can approach 256: a call id
 * and a device id are fixed-width hex, and an account id is a digest.
 */
function encodeCall(signal: CallSignal): Uint8Array {
  const encoder = new TextEncoder();
  const call = encoder.encode(signal.call);
  const device = encoder.encode(signal.device);
  const account = encoder.encode(signal.account);
  const event = CALL_EVENTS.indexOf(signal.event);

  const out = new Uint8Array(4 + call.length + device.length + account.length);
  out[0] = TYPE_CALL;
  out[1] = event;
  out[2] = call.length;
  out.set(call, 3);
  out[3 + call.length] = device.length;
  out.set(device, 4 + call.length);
  out.set(account, 4 + call.length + device.length);
  return out;
}

function decodeCall(body: Uint8Array): CallSignal | undefined {
  if (body.length < 3) return undefined;

  const event = CALL_EVENTS[body[0]];
  // An event this build does not know: a newer client, treated exactly like an older epoch.
  if (event === undefined) return undefined;

  const callLength = body[1];
  const deviceAt = 2 + callLength;
  if (deviceAt >= body.length) return undefined;

  const deviceLength = body[deviceAt];
  const accountAt = deviceAt + 1 + deviceLength;
  if (accountAt > body.length) return undefined;

  const decoder = new TextDecoder();
  return {
    kind: "call",
    event,
    call: decoder.decode(body.subarray(2, deviceAt)),
    device: decoder.decode(body.subarray(deviceAt + 1, accountAt)),
    account: decoder.decode(body.subarray(accountAt)),
  };
}

/**
 * Who is typing, as far as this device is willing to show.
 *
 * # Why `emitting` is a parameter
 *
 * It is the same flag that decides whether we send an indicator, and it is passed in rather than
 * read from a settings module for the reason `receipts.statusOf` gives about its own: the
 * reciprocity is a property of the call, so it belongs in the signature where a reader cannot
 * miss it and a caller cannot forget it.
 *
 * `mine` is an **account id**, and the caller has to pass the right one — see `Typing.account`
 * for what happened the last time it did not.
 *
 * # Why the setting cuts both directions
 *
 * It used to cut only emission, on the argument that there is nothing to hide in going without.
 * There is: an account that stops emitting while still receiving gains a one-way view of who is
 * hesitating before answering it, in every conversation, for free. That is an advantage over the
 * people it is talking to, not privacy from them — and the read receipt next to it has refused
 * exactly that trade since the beginning. Signal makes the same call for the same reason.
 *
 * The reception side cuts it too, in `Session.absorbSignal`, and the duplication is deliberate:
 * the reciprocity must hold even if one of the two places is forgotten. This one is the backstop
 * for anything already recorded when the switch moves.
 */
export function showing(typing: Typing[], mine: string, emitting: boolean): string[] {
  if (!emitting) return [];

  return [...new Set(typing.map((entry) => entry.account))].filter((account) => account !== mine);
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
export function without(typing: Typing[], account: string): Typing[] {
  return typing.filter((entry) => entry.account !== account);
}

/**
 * A `Uint8Array` can be a view onto a larger buffer; `crypto.subtle` takes the whole buffer.
 * Without this copy, we would encrypt neighbouring bytes.
 */
function bytes(view: Uint8Array): ArrayBuffer {
  return view.slice().buffer as ArrayBuffer;
}
