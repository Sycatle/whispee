/**
 * Format of the content carried *inside* an MLS message.
 *
 * The MLS plaintext is just a byte string: it is up to the application to say whether it holds
 * text or an attachment descriptor. A single type byte is enough, and leaves room for other
 * forms later.
 *
 * Everything that goes through here is end-to-end encrypted — including the file name, its type
 * and its key. That is deliberate: they are facts about the content, and the server has no
 * reason to know them.
 */
import type { AttachmentRef } from "./attachments";

const TYPE_TEXT = 0;
const TYPE_ATTACHMENT = 1;
const TYPE_GOSSIP = 2;
const TYPE_POSTING_KEY = 3;
const TYPE_RECEIPT = 4;
const TYPE_REACTION = 5;
const TYPE_REPLY = 6;
/**
 * A wrapper, not a content type: `u8 7 ‖ u64 BE milliseconds ‖ <any encoded content>`.
 *
 * # Why a wrapper rather than a field in each layout
 *
 * Six displayable-or-not layouts already exist, each with its own fixed shape. Adding eight bytes
 * to each would mean six format changes to review instead of one, and six chances to get the
 * offsets wrong. Wrapping composes: whatever gains a type byte tomorrow is stamped without
 * touching this.
 *
 * # What an older client does with it
 *
 * Refuses it, cleanly. `decode` throws on an unknown type, which is the behaviour the header
 * already promises — a message from a later version must not break the conversation, and it does
 * not: that one message fails to display and the rest of the thread carries on.
 *
 * # What the stamp is worth
 *
 * It is **declared by the sender**, and a group member can therefore put anything in it. It is an
 * annotation, not evidence: the order of the thread stays `seq`, which the server assigns and no
 * member controls. See `docs/PROTOCOL.md`.
 */
const TYPE_STAMPED = 7;

/**
 * A self-declared display name: `u8 8 ‖ u64 BE milliseconds ‖ UTF-8 name`, at most 64 bytes of
 * name.
 *
 * # Why the name travels here at all
 *
 * A column on the server would be a cleartext object, one per account, stored and served by the
 * server — and the directory enumeration oracle would start returning human names instead of
 * handles. `ui/Avatar.tsx` already refuses an uploaded picture for exactly that reason, and a
 * name is the same trade for less. The MLS credential is the other tempting place and is worse:
 * the credential **is** the identity link, so every rename would read as an identity change and
 * raise the "the fingerprint changed" banner on a cosmetic edit.
 *
 * # Why it carries its own timestamp instead of using `TYPE_STAMPED`
 *
 * Because it needs to be `isControl` and still be ordered. Control traffic is deliberately never
 * stamped — see `encode` — since it is not displayed, and being control is what buys the three
 * things a profile needs: no bubble in the thread, nothing archived to the vault, and no
 * contribution to the receipt cursor. But last-writer-wins needs *some* order, and `seq` is per
 * conversation while a name is per account: two groups would disagree about which rename came
 * last. Eight bytes inside the body give the ordering without giving up any of the three.
 *
 * # What the timestamp is worth
 *
 * Exactly what the stamp of `TYPE_STAMPED` is worth: nothing, it is **declared by the sender**.
 * A group member can date their rename to the year 2400 and pin their name there forever, since
 * every later update would lose the comparison. So the receiver clamps it — see `decodeBody` —
 * and that clamp is the only reason a self-declared clock is tolerable here.
 */
const TYPE_PROFILE = 8;

/*
 * **9 is reserved for `TYPE_INVITE`**, the friend system that is not built yet. It is written
 * down here rather than left implicit because the failure mode is silent: two branches each
 * taking "the next free number" ship two incompatible meanings for one byte, and the only symptom
 * is a peer decoding an invitation as somebody's name. Numbers are cheap; collisions are not.
 */

/**
 * A change of membership, said in the thread so that everybody sees the same history.
 *
 * # Why a message and not the commit
 *
 * Every member already receives the MLS commit that adds or removes somebody: the information is
 * on the wire either way. Reading it out of the commit would be the more robust design — nothing
 * to send separately, nothing to fail to send — and it is not what this does, because a commit
 * says which *leaf* moved, not which account it belonged to nor who caused it. Recovering "Alice
 * removed Bob" from it means mapping leaves back to handles at the epoch before the change, for
 * a line of prose. The message carries what the sentence needs and nothing else.
 *
 * The cost is stated rather than hidden: this is a claim by its sender, like any message. A
 * client could post "Alice removed Bob" without removing anybody. It changes no state and grants
 * nothing — the roster and the tree are the truth, and both are authenticated — so the worst case
 * is a line of fiction in a conversation where the reader can see the member list disagreeing
 * with it. Making it unforgeable would mean deriving it from the commit, which is the design
 * above, at the price described above.
 *
 * # Not control
 *
 * It is meant to be read, so it is displayed, archived, and counted like anything else in the
 * thread. That is deliberate down to the unread count: somebody added to a group while away has
 * had the room change under them, which is news in the same sense a message is.
 */
const TYPE_MEMBERSHIP = 10;

/**
 * The handle an account currently answers to: `u8 11 ‖ u64 BE milliseconds ‖ UTF-8 handle`.
 *
 * # Why a handle has to travel at all now
 *
 * It did not use to. The handle *was* the account — it was the subject of the MLS credential, so
 * every member of a group already had it, authenticated, without anybody sending anything. Since
 * accounts are named by the fingerprint of their genesis key, the credential carries an id and
 * the handle is a label nobody in the room would otherwise know.
 *
 * # Why not simply ask the server
 *
 * Because that is the one power this whole change took away. The server holds the directory and
 * may lie in it; what stops the lie from mattering is that the id is checkable against the key
 * inside the credential. Reading the *handle* back from the server at render time would hand it
 * a fresh chance to say who somebody is, at the one moment nobody is checking — and it would do
 * so on every screen, forever.
 *
 * So the handle travels the way the display name does: a claim by its owner, through the
 * encrypted channel, believed exactly as much as a display name is. Which is to say: it is what
 * this person says they are called, and `lib/naming.ts` already knows what to do with a claim
 * that collides with somebody else's.
 *
 * # The uniqueness the server enforces is not carried by this
 *
 * A member can claim `@alice` here without holding it. That buys them nothing the display name
 * did not already offer, and `compactNameOf` collapses two members claiming one string back to
 * something unambiguous. The account id is what is authenticated, and it is what every
 * comparison in the protocol uses.
 *
 * # Same shape as `TYPE_PROFILE`, for the same reasons
 *
 * Control — no bubble, nothing archived, no receipt cursor moved — and therefore never stamped,
 * so it carries its own timestamp for last-writer-wins. Clamped on receipt exactly as a profile
 * is: a peer dating their claim to the year 2400 would otherwise pin it forever.
 */
const TYPE_HANDLE = 11;

/**
 * The signalling settings of an account, for its **own** devices: `u8 12 ‖ sealed`.
 *
 * # Why this travels at all
 *
 * `readReceipts` and `typingIndicator` used to be per-device, because they live in the local
 * encrypted session and `lib/storage.ts` gives a good reason for keeping them out of the
 * server's sight. The consequence was not good: `Session.acknowledge` runs per session, so an
 * account that turned receipts off on one device kept sending them from another, and nothing on
 * screen said so. A setting a forgotten laptop silently undoes is not a setting.
 *
 * There is no server-side answer available. The server cannot see receipts — that is the whole
 * point of them being ordinary envelopes under sealed sender — so it cannot enforce anything
 * about them. What it can carry is an opaque message, which is what this is.
 *
 * # Why the body is sealed and `profile` is not
 *
 * A display name is meant for the room. This is not: it is addressed to the other devices of one
 * account, and it travels through the room only because that is where they meet. Peers must not
 * read it — knowing somebody turned their read receipts off is exactly the lever the setting
 * exists to remove, since a peer who can see the switch can ask for it to be flipped back.
 *
 * So the transport is the group and the confidentiality is `Account::device_sync_key`, which
 * every device of an account derives from the seed and nobody else can. A peer sees a control
 * message of a kind it ignores. It learns that *a* preference moved, never which.
 *
 * # What is inside
 *
 * `u64 BE milliseconds ‖ u8 bitfield`, sealed. The timestamp is in the clear text and not beside
 * it: only our own devices order these, and they can all decrypt. The rest of the argument is
 * `TYPE_PROFILE`'s, unchanged — control traffic is never stamped, and last-writer-wins still
 * needs an order that `seq` cannot give, since `seq` is per conversation and this is per account.
 *
 * The clamp `TYPE_PROFILE` describes applies here too, and matters less: the sender is our own
 * device. It costs one comparison and covers the device whose clock is simply wrong.
 *
 * # No length prefix
 *
 * Nothing follows the sealed blob, so the remainder of the buffer is its length. A `u16` in front
 * would be a second statement of the same fact, and two statements of one fact eventually
 * disagree.
 */
const TYPE_SIGNALS = 12;

/**
 * A moment in a call: `u8 13 ‖ u8 event ‖ u32 BE seconds ‖ UTF-8 call id`.
 *
 * # Why a call touches the durable channel at all
 *
 * Almost everything a call needs is worthless a few seconds later, and `signals.ts` carries that
 * traffic — nothing stored, nothing archived. Two moments are different, and both for the same
 * reason: they are claims about **who**.
 *
 * The ephemeral channel is encrypted under a key the whole group shares, so it cannot say who
 * emitted anything: any member could ring a group under somebody else's name. "Alice is calling
 * you" is exactly that kind of claim, so it travels here, where MLS authenticates its author. The
 * conclusion follows it for consistency — a fil that showed the ring but not the outcome would be
 * worse than one showing neither.
 *
 * # What it buys on top
 *
 * The call log, and the missed call, with no extra machinery: they are messages, so they are
 * ordered, archived and re-read like any other. And the wake-up comes for free — an invitation is
 * an envelope, so `push::wake_detached` fires on it exactly as it does on a text, **without the
 * server learning that this one was a call.**
 *
 * # Not control
 *
 * All three are meant to be seen. A call is an event in the conversation in the same sense a
 * message is — which is precisely what "you have a missed call" means.
 */
const TYPE_CALL = 13;

/**
 * A change to how long this conversation keeps what is said in it: `u8 14 ‖ u32 BE seconds`.
 *
 * A notice rather than a silent setting, for the reason membership notices exist: a room whose
 * memory grows from seven days to a year has changed in the way that matters, and the change
 * belongs in the history where everybody sees it rather than in a menu somebody may never open.
 *
 * # Not the authority, and it does not need to be
 *
 * The lifetime itself lives in the MLS group context, authenticated and hashed into every commit
 * — see `crates/crypto-core/src/lifetime.rs`. This is the announcement, and like the membership
 * notice it is a claim by its sender: a client could post one without committing anything. It
 * changes no state, and the reader's own group context is what actually decides when their
 * messages go.
 *
 * # Not control
 *
 * It is meant to be read, so it is displayed, archived and counted like anything else in the
 * thread. Somebody who was away while the room's memory was shortened has had the conversation
 * change under them, which is news in the same sense a message is.
 */
const TYPE_EXPIRY = 14;

/**
 * What happened to a call.
 *
 * `invite` and its conclusion are two envelopes sharing one call id, not one envelope amended:
 * the invitation has to leave before anybody knows how the call will end. The display is what
 * folds the pair back into a single line — see `conversation-view.ts`.
 *
 * `missed` and a `declined` refusal are deliberately the same event here. The difference is
 * visible only to the person who refused, and reporting it to the caller would tell them they
 * were turned down rather than merely unheard — an admission the protocol has no reason to
 * extract from a device.
 */
export type CallEvent = "invite" | "ended" | "missed";

const CALL_EVENTS: CallEvent[] = ["invite", "ended", "missed"];

/** What happened to somebody's membership. The subject is `handle`; the actor is the sender. */
export type MembershipEvent = "joined" | "removed" | "left";

const MEMBERSHIP_EVENTS: MembershipEvent[] = ["joined", "removed", "left"];

export type Content =
  | { kind: "text"; text: string }
  | { kind: "attachment"; ref: AttachmentRef }
  | { kind: "gossip"; head: GossipHead }
  | { kind: "posting-key"; key: Uint8Array }
  | { kind: "receipt"; state: ReceiptState; seq: number }
  | { kind: "reaction"; target: number; emoji: string }
  | { kind: "reply"; target: number; text: string }
  | { kind: "profile"; name: string; at: number }
  | { kind: "call"; event: CallEvent; call: string; seconds: number }
  | { kind: "membership"; event: MembershipEvent; handle: string }
  | { kind: "handle"; handle: string; at: number }
  | { kind: "expiry"; seconds: number }
  | { kind: "signals"; sealed: Uint8Array };

/**
 * What a receipt attests.
 *
 * `delivered` is mechanical: the device picked the envelope up. `read` commits a person — the
 * message was displayed. That difference is why only the second one can be turned off.
 */
export type ReceiptState = "delivered" | "read";

const RECEIPT_DELIVERED = 0;
const RECEIPT_READ = 1;

/**
 * A log head handed to a correspondent, **inside an encrypted message**.
 *
 * # Why this channel and no other
 *
 * An auditable log has one weakness that neither signatures nor proofs cover: the server can
 * keep **two** of them and serve one to each side. Each victim sees a signed, consistent log in
 * which their own view is perfect.
 *
 * Detecting it means comparing two people's views over a channel the server does not control.
 * That channel already exists: the conversation itself. The server carries these bytes without
 * being able to read or alter them — exactly what is needed.
 *
 * The recipient then asks the server to prove that **its** log extends the view it received. If
 * the server served two logs, it cannot.
 */
export interface GossipHead {
  size: number;
  root: Uint8Array;
}

/**
 * A decoded message: its content, and when its sender says it was written.
 *
 * `sentAt` is absent for control traffic, which is never stamped, and for anything written before
 * stamping existed.
 */
export interface Stamped {
  body: Content;
  sentAt?: number;
}

export function encodeText(text: string): Uint8Array {
  const body = new TextEncoder().encode(text);
  const out = new Uint8Array(1 + body.length);
  out[0] = TYPE_TEXT;
  out.set(body, 1);
  return out;
}

/**
 * Encodes a log head. Fixed layout: `u32 size ‖ 32 bytes of root`.
 *
 * No signature, no timestamp: the recipient does not verify this head for its own sake, it uses
 * it as an **anchor** and asks the server to prove that its own log extends it. Carrying the
 * signature would suggest it serves some purpose here.
 */
/**
 * `u8 event ‖ u32 BE seconds ‖ call id`.
 *
 * The duration is fixed-width and always present, zero on an invitation and on a missed call. A
 * variable field would have bought four bytes on the one message of the three that is not
 * displayed with a duration next to it, and cost a length prefix to say so.
 */
export function encodeCall(event: CallEvent, call: string, seconds: number): Uint8Array {
  const id = new TextEncoder().encode(call);
  const out = new Uint8Array(1 + 1 + 4 + id.length);
  out[0] = TYPE_CALL;
  out[1] = CALL_EVENTS.indexOf(event);
  new DataView(out.buffer).setUint32(2, Math.max(0, Math.trunc(seconds)), false);
  out.set(id, 6);
  return out;
}

/** `u8 event ‖ handle`. The handle is the subject; who did it is the sender of the message. */
export function encodeMembership(event: MembershipEvent, handle: string): Uint8Array {
  const name = new TextEncoder().encode(handle);
  const out = new Uint8Array(1 + 1 + name.length);
  out[0] = TYPE_MEMBERSHIP;
  out[1] = MEMBERSHIP_EVENTS.indexOf(event);
  out.set(name, 2);
  return out;
}

/** A change of lifetime, in seconds; `0` announces that it was turned off. */
export function encodeExpiry(seconds: number): Uint8Array {
  const out = new Uint8Array(1 + 4);
  out[0] = TYPE_EXPIRY;
  new DataView(out.buffer).setUint32(1, seconds, false);
  return out;
}

export function encodeGossip(head: GossipHead): Uint8Array {
  const out = new Uint8Array(1 + 4 + 32);
  out[0] = TYPE_GOSSIP;
  new DataView(out.buffer).setUint32(1, head.size, false);
  out.set(head.root.subarray(0, 32), 5);
  return out;
}

/**
 * Encodes any content. A single entry point, so that adding a type forces the case to be handled
 * everywhere — the previous version wrote "if text, else attachment" in two places, which would
 * have sent gossip encoded as an attachment.
 */
/**
 * Is this content **protocol traffic** rather than a message?
 *
 * Gossip and the posting key travel through the same encrypted channel as messages, because that
 * is exactly what we want: a channel the server carries without being able to read it. But they
 * are not messages — displaying them drowns the conversation in empty bubbles, and archiving them
 * fills the vault with things nobody will ever read again.
 *
 * The distinction lives here, in one place, so that a new control type does not have to be
 * remembered on send **and** on receive.
 */
export function isControl(body: Content): boolean {
  return (
    body.kind === "gossip" ||
    body.kind === "posting-key" ||
    body.kind === "receipt" ||
    // A profile is control for all three reasons at once, and each one was checked before it was
    // put here: nobody wants a bubble reading "Charlie" every time someone renames themselves,
    // the vault has no business archiving a name that will be replaced, and the receipt cursor
    // must not advance on it or two clients renaming each other would acknowledge forever. What
    // it gives up in exchange is the stamp, which is why it carries its own.
    body.kind === "profile" ||
    // A handle claim is control for all three of the same reasons, and carries its own timestamp
    // for the same one: `seq` is per conversation, a handle is per account, so two groups would
    // disagree about which claim came last.
    body.kind === "handle" ||
    // Signalling settings are control for all three reasons, and the third is the one that would
    // bite: a settings announcement that moved the receipt cursor would be acknowledged, and the
    // acknowledgement would be a message, and two devices would trade them forever. They carry
    // their own timestamp for the reason the two above do — `seq` is per conversation, an
    // account's settings are not.
    body.kind === "signals"
  );
}

/**
 * Encodes any content, stamped when a time is given.
 *
 * Control traffic is never stamped even if a time is passed: it is not displayed, so the eight
 * bytes would buy nothing, and a receipt that looked like a dated message would be one more thing
 * for `isControl` to have to un-say.
 */
export function encode(body: Content, sentAt?: number): Uint8Array {
  const inner = encodeBody(body);
  if (sentAt === undefined || isControl(body)) return inner;

  const out = new Uint8Array(1 + 8 + inner.length);
  out[0] = TYPE_STAMPED;
  new DataView(out.buffer).setBigUint64(1, BigInt(Math.trunc(sentAt)), false);
  out.set(inner, 9);
  return out;
}

function encodeBody(body: Content): Uint8Array {
  switch (body.kind) {
    case "text":
      return encodeText(body.text);
    case "attachment":
      return encodeAttachment(body.ref);
    case "gossip":
      return encodeGossip(body.head);
    case "posting-key":
      return encodePostingKey(body.key);
    case "receipt":
      return encodeReceipt(body.state, body.seq);
    case "reaction":
      return encodeTargeted(TYPE_REACTION, body.target, body.emoji);
    case "reply":
      return encodeTargeted(TYPE_REPLY, body.target, body.text);
    case "profile":
      return encodeProfile(body.name, body.at);
    case "call":
      return encodeCall(body.event, body.call, body.seconds);
    case "membership":
      return encodeMembership(body.event, body.handle);
    case "expiry":
      return encodeExpiry(body.seconds);
    case "handle":
      return encodeHandle(body.handle, body.at);
    case "signals":
      return encodeSignals(body.sealed);
  }
}

/**
 * Encodes a receipt. Fixed layout: `u8 state ‖ u64 BE seq`.
 *
 * # Cumulative, and that is the whole sizing argument
 *
 * A receipt carries "up to this number", not "this message". A reading session therefore costs
 * one envelope instead of one per bubble — otherwise opening a conversation two hundred messages
 * behind would produce two hundred of them, in a table the server only prunes past thirty days
 * and five hundred sequences — which is to say, not soon enough to matter here.
 */
export function encodeReceipt(state: ReceiptState, seq: number): Uint8Array {
  const out = new Uint8Array(1 + 1 + 8);
  out[0] = TYPE_RECEIPT;
  out[1] = state === "read" ? RECEIPT_READ : RECEIPT_DELIVERED;
  new DataView(out.buffer).setBigUint64(2, BigInt(seq), false);
  return out;
}

/**
 * Encodes the two forms that point at an earlier message: `u64 BE target ‖ UTF-8`.
 *
 * Reaction and reply share their layout and differ only by their type byte. Writing them twice
 * would invite one of them to get a fix the other never did.
 */
function encodeTargeted(type: number, target: number, text: string): Uint8Array {
  const body = new TextEncoder().encode(text);
  const out = new Uint8Array(1 + 8 + body.length);
  out[0] = type;
  new DataView(out.buffer).setBigUint64(1, BigInt(target), false);
  out.set(body, 9);
  return out;
}

/**
 * Hands the group's posting key to the other members.
 *
 * # Why it travels inside the encrypted content
 *
 * This key allows posting to the group without identifying yourself to the server. Routing it
 * through the server would mean asking it to distribute the means of not talking to it — it could
 * hand it to whoever it likes, or withhold it. So it goes through MLS, like any other group
 * secret.
 *
 * The server holds it anyway: it has to verify the MACs. What it cannot do is decide who else
 * gets it.
 */
export function encodePostingKey(key: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + 32);
  out[0] = TYPE_POSTING_KEY;
  out.set(key.subarray(0, 32), 1);
  return out;
}

/**
 * Encodes a display name and the moment its owner claims to have set it.
 *
 * The size is checked here and not only on the way in, because this is the last place that sees
 * the bytes: a name that got past the input field by some other route — a queued send from an
 * older build, a caller that forgot `validate` — would otherwise go out over the wire in a shape
 * every recipient is required to reject. Failing on our own side is the one failure the sender
 * can actually see.
 */
export function encodeProfile(name: string, at: number): Uint8Array {
  const body = new TextEncoder().encode(name);
  if (body.length > PROFILE_NAME_MAX_BYTES) throw new Error("display name too long");

  const out = new Uint8Array(1 + 8 + body.length);
  out[0] = TYPE_PROFILE;
  new DataView(out.buffer).setBigUint64(1, BigInt(Math.max(0, Math.trunc(at))), false);
  out.set(body, 9);
  return out;
}

/**
 * The wire ceiling on a name, in bytes.
 *
 * Duplicated from `display-name.ts` rather than imported: this module is the format, and a format
 * that reads its own limits out of a validation module would change shape the day somebody
 * relaxes the user-facing rule. `display-name.ts` refuses a name over this; here it is a hard
 * bound on bytes anybody may put on the wire, including a peer we did not write.
 */
const PROFILE_NAME_MAX_BYTES = 64;

/**
 * How far ahead of our own clock a peer's self-declared time may sit before we stop believing it.
 *
 * Five minutes, which is ordinary clock skew between two consumer devices. Past that the sender
 * is either badly wrong or pinning: a name dated ten years out would win last-writer-wins against
 * every update its owner ever makes afterwards, and the name would be frozen with no way to say
 * so. So the value is replaced by the moment of receipt, which is the one clock we trust.
 */
const PROFILE_CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * Encodes a handle claim and the moment its owner says they took it.
 *
 * The ceiling is the handle format's own — `^[a-z0-9_]{3,32}$` — checked here because this is the
 * last place that sees the bytes. A claim longer than that is one every recipient is required to
 * refuse, so failing on our own side is the one failure the sender can actually see.
 */
export function encodeHandle(handle: string, at: number): Uint8Array {
  const body = new TextEncoder().encode(handle);
  if (body.length > HANDLE_MAX_BYTES) throw new Error("handle too long");

  const out = new Uint8Array(1 + 8 + body.length);
  out[0] = TYPE_HANDLE;
  new DataView(out.buffer).setBigUint64(1, BigInt(Math.max(0, Math.trunc(at))), false);
  out.set(body, 9);
  return out;
}

/**
 * The wire ceiling on a handle, in bytes.
 *
 * Duplicated from `handle.ts` rather than imported, for the reason `PROFILE_NAME_MAX_BYTES` gives
 * next to it: this module is the format, and a format that read its limits out of a validation
 * module would change shape the day somebody relaxed the user-facing rule. Here it is a hard
 * bound on bytes anybody may put on the wire, a peer we did not write included.
 */
const HANDLE_MAX_BYTES = 32;

/**
 * Wraps an already sealed settings blob. The sealing happens in `session.ts`, which holds the
 * key; this module decodes bytes and has no business holding one.
 */
export function encodeSignals(sealed: Uint8Array): Uint8Array {
  if (sealed.length < SEALED_SIGNALS_MIN_BYTES) throw new Error("settings blob too short");
  if (sealed.length > SEALED_SIGNALS_MAX_BYTES) throw new Error("settings blob too long");

  const out = new Uint8Array(1 + sealed.length);
  out[0] = TYPE_SIGNALS;
  out.set(sealed, 1);
  return out;
}

/**
 * A twelve-byte AES-GCM nonce and a sixteen-byte tag, so nothing shorter can be a sealed blob at
 * all. Checked on both sides: on send because a caller that passed the plaintext by mistake would
 * otherwise publish it, and on receive so that a truncated message fails here rather than three
 * layers down in WebCrypto with an error that names nothing.
 */
const SEALED_SIGNALS_MIN_BYTES = 12 + 16;

/**
 * And a ceiling, because a decoder without one lets a hostile member decide how much memory this
 * costs. The payload is nine bytes today; a hundred and twenty-eight leaves room for the fields
 * that will follow — `conversationFlags`, `blocked`, and the rest of what does not sync yet —
 * without leaving room for an attack.
 */
const SEALED_SIGNALS_MAX_BYTES = 12 + 16 + 128;

export function encodeAttachment(ref: AttachmentRef): Uint8Array {
  const body = new TextEncoder().encode(JSON.stringify(ref));
  const out = new Uint8Array(1 + body.length);
  out[0] = TYPE_ATTACHMENT;
  out.set(body, 1);
  return out;
}

/**
 * These bytes were authenticated by MLS: they really do come from a group member. That does not
 * make them well-formed — a member can send anything at all, by mistake or on purpose. So
 * decoding has to fail cleanly.
 *
 * Forward compatibility: a message from a later version, carrying an unknown type, must not break
 * the conversation.
 */
export function decode(bytes: Uint8Array): Stamped {
  if (bytes.length < 1) throw new Error("empty content");

  if (bytes[0] === TYPE_STAMPED) {
    if (bytes.length < 1 + 8) throw new Error("truncated timestamp");
    const sentAt = Number(new DataView(bytes.buffer, bytes.byteOffset + 1).getBigUint64(0, false));

    // One level, never two. A wrapper around a wrapper is not something a correct sender
    // produces, and unwrapping recursively would let a hostile member nest a few thousand of
    // them and spend our stack on it.
    const inner = decodeBody(bytes.subarray(9));
    return { body: inner, sentAt };
  }

  return { body: decodeBody(bytes) };
}

function decodeBody(bytes: Uint8Array): Content {
  if (bytes.length < 1) throw new Error("empty content");

  const body = bytes.subarray(1);

  switch (bytes[0]) {
    case TYPE_TEXT:
      return { kind: "text", text: new TextDecoder().decode(body) };

    case TYPE_GOSSIP: {
      if (body.length !== 4 + 32) throw new Error("badly sized log head");
      return {
        kind: "gossip",
        head: {
          size: new DataView(body.buffer, body.byteOffset).getUint32(0, false),
          root: body.slice(4, 36),
        },
      };
    }

    case TYPE_POSTING_KEY: {
      if (body.length !== 32) throw new Error("badly sized posting key");
      return { kind: "posting-key", key: body.slice(0, 32) };
    }

    case TYPE_RECEIPT: {
      if (body.length !== 1 + 8) throw new Error("badly sized receipt");
      const view = new DataView(body.buffer, body.byteOffset);
      return {
        kind: "receipt",
        state: body[0] === RECEIPT_READ ? "read" : "delivered",
        // `Number` rather than `bigint`: sequence numbers stay well below 2^53, and a bigint
        // would contaminate all the cursor arithmetic downstream.
        seq: Number(view.getBigUint64(1, false)),
      };
    }

    case TYPE_REACTION:
    case TYPE_REPLY: {
      if (body.length < 8) throw new Error("missing message reference");
      const target = Number(new DataView(body.buffer, body.byteOffset).getBigUint64(0, false));
      const text = new TextDecoder().decode(body.subarray(8));
      return bytes[0] === TYPE_REACTION
        ? { kind: "reaction", target, emoji: text }
        : { kind: "reply", target, text };
    }

    case TYPE_CALL: {
      if (body.length < 5) throw new Error("truncated call event");

      const event = CALL_EVENTS[body[0]];
      // Same reasoning as the membership event below: an unknown verb draws a blank line.
      if (event === undefined) throw new Error("unknown call event");

      return {
        kind: "call",
        event,
        seconds: new DataView(body.buffer, body.byteOffset).getUint32(1, false),
        call: new TextDecoder().decode(body.subarray(5)),
      };
    }

    case TYPE_EXPIRY: {
      // Four bytes and nothing else. A length nobody checks is how a garbled body becomes a
      // lifetime somebody did not choose — and the sentence drawn from it would name a delay no
      // member of the room ever agreed to.
      if (body.length !== 4) throw new Error("badly sized expiry notice");

      return {
        kind: "expiry",
        seconds: new DataView(body.buffer, body.byteOffset).getUint32(0, false),
      };
    }

    case TYPE_MEMBERSHIP: {
      if (body.length < 1) throw new Error("truncated membership event");

      const event = MEMBERSHIP_EVENTS[body[0]];
      // An event byte we do not know is a newer client saying something this one cannot render.
      // Refusing it is right: the alternative is drawing a line with a blank verb in it.
      if (event === undefined) throw new Error("unknown membership event");

      return {
        kind: "membership",
        event,
        handle: new TextDecoder().decode(body.subarray(1)),
      };
    }

    case TYPE_HANDLE: {
      if (body.length < 8) throw new Error("truncated handle timestamp");
      const handle = body.subarray(8);
      if (handle.length > HANDLE_MAX_BYTES) throw new Error("badly sized handle");

      const declared = Number(new DataView(body.buffer, body.byteOffset).getBigUint64(0, false));
      const now = Date.now();
      // Clamped, never rejected — the argument is the one on `TYPE_PROFILE`, and it applies
      // unchanged: a date far in the future is a pin, and taking the receipt time defeats it
      // without needing to tell a pin from a skewed clock.
      const at = declared > now + PROFILE_CLOCK_SKEW_MS ? now : declared;

      // Not validated against the handle format here. `content.ts` decodes bytes and does not
      // know what a screen is; the receiving end in `session.ts` is what decides whether a claim
      // is well-formed enough to show.
      return { kind: "handle", handle: new TextDecoder().decode(handle), at };
    }

    case TYPE_SIGNALS: {
      if (body.length < SEALED_SIGNALS_MIN_BYTES) throw new Error("truncated settings blob");
      if (body.length > SEALED_SIGNALS_MAX_BYTES) throw new Error("oversized settings blob");

      // Not opened here: this module has no key, and it is the receiving end in `session.ts`
      // that knows whether the author is one of our own devices — which is the only case where
      // opening it can succeed, and the only case where it means anything.
      return { kind: "signals", sealed: body.slice() };
    }

    case TYPE_PROFILE: {
      if (body.length < 8) throw new Error("truncated profile timestamp");
      const name = body.subarray(8);
      if (name.length > PROFILE_NAME_MAX_BYTES) throw new Error("badly sized display name");

      const declared = Number(new DataView(body.buffer, body.byteOffset).getBigUint64(0, false));
      const now = Date.now();

      // Clamped, not rejected. A skewed clock is common and refusing the message would drop a
      // legitimate rename; a date far in the future is the pinning move described on
      // `TYPE_PROFILE`, and taking the receipt time defeats it without needing to tell the two
      // cases apart. The name is **not** sanitised here: `content.ts` decodes bytes and does not
      // know what a screen is, and `display-name.ts` states that its `sanitize` runs at both
      // ends. The caller in `session.ts` is the receiving end.
      const at = declared > now + PROFILE_CLOCK_SKEW_MS ? now : declared;

      return { kind: "profile", name: new TextDecoder().decode(name), at };
    }

    case TYPE_ATTACHMENT: {
      const ref = JSON.parse(new TextDecoder().decode(body)) as AttachmentRef;
      for (const field of ["id", "key", "iv", "name", "mime"] as const) {
        if (typeof ref[field] !== "string") {
          throw new Error(`invalid attachment descriptor: ${field} missing`);
        }
      }
      if (typeof ref.size !== "number") {
        throw new Error("invalid attachment descriptor: size missing");
      }
      return { kind: "attachment", ref };
    }

    default:
      throw new Error(`unknown content type: ${bytes[0]}`);
  }
}
