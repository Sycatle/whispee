/**
 * The recent thread, kept on this device.
 *
 * # What this changes, and what it gives up
 *
 * Until now no decrypted body ever touched the disk. `persist` said so in as many words, and the
 * reasoning was sound as far as it went: MLS destroys its message keys as it goes, so a transport
 * captured after the fact yields nothing, and writing the plaintext down is what takes that back.
 *
 * What it cost was not small. Every conversation opened **empty** and refilled itself from the
 * server vault over the network, two hundred entries at a time. Offline there was nothing to
 * read at all, on a messenger — and the vault, which is what made the thread reappear, is itself
 * a copy of the history on the server under a key that never rotates. So the plaintext was
 * already being written down; it was being written down *there*, where the server learns how much
 * each account archives and when.
 *
 * A local cache is the same data in the better place. It is sealed by the device cipher — the
 * same one that seals the MLS state, so under the master key whenever a lock is set — and it
 * never leaves. What it does not survive is what it should not survive: erasing the identity.
 *
 * # Why a window and not an archive
 *
 * Only the most recent messages per conversation are kept. `Session.persist` re-serialises
 * everything it holds on every write, so an unbounded log here would make each send cost the
 * whole history — quadratic, and felt first by whoever talks the most. The vault stays the
 * archive; this is the part you see before the network answers, and `hydrate` still fetches the
 * rest behind it.
 *
 * # What an attacker gets that they did not before
 *
 * Someone holding the **unlocked** device: nothing new — they have the running session and its
 * decrypted thread on screen. That is already out of scope (`docs/THREAT-MODEL.md` §2.5).
 * Someone holding the **locked** device: still nothing, as long as a lock is set, because this
 * blob is sealed under the master key like everything else. With no lock, it is sealed by the
 * non-extractable device key, which stops a script and not someone with the browser profile —
 * the same guarantee the MLS state has always had, applied now to something more legible.
 */
import * as content from "./content.ts";
import type { Message, Pending } from "./session";

/**
 * Messages kept per conversation.
 *
 * Two hundred, matching the vault's page size: it is one round trip's worth, so the boundary
 * between "already here" and "being fetched" falls where the network was going to draw it anyway.
 * Enough to open a conversation and scroll back through a day of it; short enough that
 * re-serialising the lot on every send stays a fixed cost rather than a growing one.
 */
export const RECENT_PER_CONVERSATION = 200;

/** On-disk shape. Bodies are re-encoded, so the timestamp rides along with them. */
interface StoredMessage {
  seq: number;
  sender: string | null;
  mine: boolean;
  body: number[];
}

interface StoredHistory {
  v: 1;
  conversations: Record<string, StoredMessage[]>;
  /**
   * What was written and not yet accepted.
   *
   * Stored beside the thread rather than in it, exactly as it is held in memory: these have no
   * `seq`, and the whole point of keeping them apart is that nothing downstream can mistake one
   * for a message the server has numbered.
   */
  outbox?: Record<string, Pending[]>;
  /**
   * How far the user had actually read, per conversation.
   *
   * Persisted, while the receipts beside it are not, and the difference is the point: a receipt
   * is a claim made **to someone else** and means "as of then", so replaying it across sessions
   * would assert a reading nobody has confirmed since. This is a fact about this screen, for this
   * person. Now that the thread survives a reload, forgetting it would mark a conversation you
   * read yesterday as entirely unread today.
   */
  read?: Record<string, number>;
}

/** What a conversation contributes to the cache. */
export interface Cached {
  messages: Message[];
  outbox: Pending[];
  readCursor: number;
}

/**
 * Serialises the tail of each conversation.
 *
 * Sorted and trimmed here rather than at the call site: a caller that forgot would write an
 * unbounded log, and the symptom — sends getting slower the longer you have used the
 * application — is one nobody attributes to this.
 */
export function encodeHistory(conversations: Map<string, Cached>): Uint8Array {
  const out: Record<string, StoredMessage[]> = {};
  const queued: Record<string, Pending[]> = {};
  const read: Record<string, number> = {};

  for (const [key, { messages, outbox, readCursor }] of conversations) {
    if (readCursor > 0) read[key] = readCursor;
    const recent = messages
      .slice()
      .sort((a, b) => a.seq - b.seq)
      .slice(-RECENT_PER_CONVERSATION);

    if (recent.length > 0) {
      out[key] = recent.map((message) => ({
        seq: message.seq,
        sender: message.sender,
        mine: message.mine,
        body: [...content.encode(message.content, message.sentAt)],
      }));
    }

    // The outbox is **not** capped. It is not a cache: nothing else holds these, and dropping the
    // oldest would silently lose a message the user wrote. It is also bounded by the only thing
    // that fills it — a person typing while the network is down.
    if (outbox.length > 0) queued[key] = outbox;
  }

  const payload: StoredHistory = { v: 1, conversations: out, outbox: queued, read };
  return new TextEncoder().encode(JSON.stringify(payload));
}

/**
 * Reads back what `encodeHistory` wrote.
 *
 * A cache is not state: an entry that no longer parses is dropped rather than thrown over,
 * because the conversation it belongs to is still on the server and `hydrate` will fetch it. The
 * opposite choice — refusing to start on a corrupt cache — would turn a cosmetic loss into a
 * device that cannot open, for data whose whole purpose is to be redundant.
 */
export function decodeHistory(bytes: Uint8Array): Map<string, Cached> {
  const restored = new Map<string, Cached>();

  let payload: StoredHistory;
  try {
    payload = JSON.parse(new TextDecoder().decode(bytes)) as StoredHistory;
  } catch {
    return restored;
  }

  if (payload?.v !== 1 || typeof payload.conversations !== "object") return restored;

  const at = (key: string): Cached => {
    const existing = restored.get(key);
    if (existing) return existing;
    const fresh: Cached = { messages: [], outbox: [], readCursor: 0 };
    restored.set(key, fresh);
    return fresh;
  };

  for (const [key, stored] of Object.entries(payload.conversations)) {
    if (!Array.isArray(stored)) continue;

    for (const entry of stored) {
      try {
        const { body, sentAt } = content.decode(new Uint8Array(entry.body));
        at(key).messages.push({
          seq: entry.seq,
          sender: entry.sender,
          mine: entry.mine,
          content: body,
          ...(sentAt === undefined ? {} : { sentAt }),
        });
      } catch {
        // One unreadable entry, not one unreadable conversation.
      }
    }
  }

  for (const [key, stored] of Object.entries(payload.outbox ?? {})) {
    if (!Array.isArray(stored)) continue;

    for (const entry of stored) {
      if (typeof entry?.localId !== "string" || typeof entry.text !== "string") continue;

      at(key).outbox.push({
        localId: entry.localId,
        text: entry.text,
        sentAt: typeof entry.sentAt === "number" ? entry.sentAt : 0,
        // Anything that was in flight when the tab closed comes back as failed. We never saw the
        // answer, so it may or may not have arrived; saying it did not go and letting the user
        // decide beats retrying silently and posting it twice.
        state: "failed",
      });
    }
  }

  for (const [key, cursor] of Object.entries(payload.read ?? {})) {
    if (typeof cursor === "number" && restored.has(key)) at(key).readCursor = cursor;
  }

  for (const [key, cached] of restored) {
    if (cached.messages.length === 0 && cached.outbox.length === 0) restored.delete(key);
  }

  return restored;
}
