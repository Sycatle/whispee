/**
 * History vault. **On by default.**
 *
 * # What keeping it gives up
 *
 * MLS destroys its keys as messages go by: whoever gets hold of the transport after the fact can
 * make nothing of it — including the user themselves on a new device. That is forward secrecy,
 * and it is real protection, not an inconvenient side effect.
 *
 * The vault gives it up **for history**: entries are encrypted under a key derived from the
 * recovery phrase, so stable over time. If that phrase ever leaks, everything saved leaks with it,
 * retroactively.
 *
 * That is the price of a history that survives losing every device, and it has been paid: a
 * messenger whose conversation starts empty on every reload is not one, and putting the choice
 * behind a settings screen amounted to refusing it for almost everyone without almost anyone
 * having decided it.
 *
 * So the trade-off is taken in `Session.attach`, stated on the recovery phrase screen — the one
 * moment that phrase, which is also the vault key, is in front of someone — and restated in the
 * present tense in settings, where it stays revocable. A trade-off that became the default is the
 * one you stop stating unless you are careful.
 *
 * # What the server learns anyway
 *
 * How many messages each account archives, and when. It already knew who talks to whom; this adds
 * a volume and a timeline. Avoiding it would take padding and decoy deposits.
 */
import * as content from "./content.ts";
import type { Message } from "./session";

/**
 * What the vault expects from the transport, and nothing more.
 *
 * Declared here rather than imported from `api.ts` so that the batching and pagination below are
 * testable without a network: that is exactly the kind of logic that fails silently if nobody
 * checks it.
 */
export interface VaultApi {
  storeVault(
    groupId: Uint8Array,
    entries: { seq: number; payload: Uint8Array }[],
  ): Promise<{ stored: number }>;
  fetchVault(groupId: Uint8Array, after: number): Promise<{ seq: number; payload: Uint8Array }[]>;
}

/**
 * Batch size, on deposit as on retrieval.
 *
 * **Must stay equal to `MAX_VAULT_ENTRIES` on the server** (`crates/server/src/routes.rs`), which
 * bounds both: a larger deposit is refused with a 400, a longer retrieval is truncated — with no
 * error, which is the worse of the two. While the vault was optional both cases stayed rare; they
 * become the nominal case of a first start.
 */
const PAGE = 200;

/** See the note on `buffer` in `keys.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

const IV_LEN = 12;

/** Imports the vault key derived from the phrase. Non-extractable once inside the browser. */
export function importVaultKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buffer(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

/**
 * Archived form of a message.
 *
 * The sender is kept: without it, a restored history would no longer say who said what, which
 * makes it more or less useless. It is one more piece of data under the vault's stable key — but
 * one the server already knows through group membership.
 */
interface Archived {
  sender: string | null;
  mine: boolean;
  body: number[];
}

export async function encryptEntry(key: CryptoKey, message: Message): Promise<Uint8Array> {
  // Re-encoded **with its stamp**, so the archive keeps the time it was written rather than the
  // time it was restored. `Archived` gains no field for it: the stamp already travels inside the
  // encoded body, and a second copy would be one more thing that can disagree with the first.
  const body = content.encode(message.content, message.sentAt);

  const archived: Archived = { sender: message.sender, mine: message.mine, body: [...body] };
  const plaintext = new TextEncoder().encode(JSON.stringify(archived));

  // Random nonce per entry. AES-GCM breaks catastrophically if a nonce is reused under the same
  // key — and this key never changes.
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(iv) }, key, buffer(plaintext)),
  );

  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  return out;
}

export async function decryptEntry(
  key: CryptoKey,
  seq: number,
  blob: Uint8Array,
): Promise<Message> {
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(blob.slice(0, IV_LEN)) },
      key,
      buffer(blob.slice(IV_LEN)),
    ),
  );

  const archived = JSON.parse(new TextDecoder().decode(plaintext)) as Archived;
  const { body, sentAt } = content.decode(new Uint8Array(archived.body));
  return {
    seq,
    sender: archived.sender,
    mine: archived.mine,
    content: body,
    ...(sentAt === undefined ? {} : { sentAt }),
  };
}

/**
 * Deposits messages into the vault. Idempotent on the server side.
 *
 * Split into batches: a device catching up can have far more than `PAGE` messages to archive at
 * once, and the server refuses the whole batch beyond that. Serially, not in parallel — archiving
 * is background work, nothing justifies opening ten concurrent requests for it.
 */
export async function store(
  api: VaultApi,
  key: CryptoKey,
  groupId: Uint8Array,
  messages: Message[],
): Promise<void> {
  for (let start = 0; start < messages.length; start += PAGE) {
    const batch = messages.slice(start, start + PAGE);

    const entries = await Promise.all(
      batch.map(async (message) => ({
        seq: message.seq,
        payload: await encryptEntry(key, message),
      })),
    );

    await api.storeVault(groupId, entries);
  }
}

/** What a restore reports, including what it could not read. */
export interface Restored {
  messages: Message[];
  /**
   * Entries we could not decrypt.
   *
   * Reported rather than silently counted: if **every** entry of a conversation is unreadable, it
   * is not an old format, it is an account rotation — the vault key derives from the recovery
   * phrase, and rotating it makes the archived past permanently inaccessible. An empty thread with
   * no explanation would be the worst of both behaviours.
   */
  unreadable: number;
}

/**
 * Restores a conversation's history.
 *
 * An unreadable entry is skipped rather than fatal: it may come from an earlier version of the
 * format, and losing all the history because one message in a thousand does not decode would be a
 * disproportionate reaction.
 */
export async function restore(
  api: VaultApi,
  key: CryptoKey,
  groupId: Uint8Array,
): Promise<Restored> {
  const messages: Message[] = [];
  let unreadable = 0;
  let after = 0;

  // The server serves at most `PAGE` rows per call, sorted by ascending `seq`. A single request
  // therefore truncated history **without an error** beyond two hundred messages: the thread just
  // looked shorter, and nothing said so.
  for (;;) {
    const rows = await api.fetchVault(groupId, after);
    if (rows.length === 0) break;

    for (const row of rows) {
      try {
        messages.push(await decryptEntry(key, row.seq, row.payload));
      } catch (error) {
        unreadable += 1;
        console.warn(`vault entry ${row.seq} unreadable`, error);
      }
    }

    if (rows.length < PAGE) break;
    after = rows[rows.length - 1].seq;
  }

  return { messages, unreadable };
}

/**
 * Merges a restored history into an already populated thread, without duplicates.
 *
 * Pulled out of `Session` to be testable: the merge is a business rule — `seq` identifies a
 * message — not a display detail, and `session.ts` is not testable as it stands (WASM,
 * IndexedDB).
 */
export function merge(existing: Message[], archives: Message[]): Message[] {
  const known = new Set(existing.map((message) => message.seq));
  return archives.filter((message) => !known.has(message.seq));
}
