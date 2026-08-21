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

export type Content =
  | { kind: "text"; text: string }
  | { kind: "attachment"; ref: AttachmentRef }
  | { kind: "gossip"; head: GossipHead }
  | { kind: "posting-key"; key: Uint8Array }
  | { kind: "receipt"; state: ReceiptState; seq: number }
  | { kind: "reaction"; target: number; emoji: string }
  | { kind: "reply"; target: number; text: string };

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
  return body.kind === "gossip" || body.kind === "posting-key" || body.kind === "receipt";
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
  }
}

/**
 * Encodes a receipt. Fixed layout: `u8 state ‖ u64 BE seq`.
 *
 * # Cumulative, and that is the whole sizing argument
 *
 * A receipt carries "up to this number", not "this message". A reading session therefore costs
 * one envelope instead of one per bubble — otherwise opening a conversation two hundred messages
 * behind would produce two hundred of them, in a table that is never purged.
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
