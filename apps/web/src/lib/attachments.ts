/**
 * Encrypted attachments.
 *
 * The file is encrypted on the client with a **random key of its own**, then deposited on the
 * server. The key never leaves the client by that path: it travels inside the MLS message, so
 * end-to-end encrypted like the text.
 *
 * Consequence: the server holds the whole file and can do nothing with it. It knows neither its
 * content, nor its name, nor its type.
 *
 * # Why one key per file
 *
 * Reusing a key across files would mean a single leaked descriptor opens all the others. One key
 * per file bounds the damage of a leak to that file, and also allows sharing one specific
 * attachment without giving access to the rest.
 *
 * # Size is padded, and what that costs
 *
 * The plaintext used to reach the server at its exact length, to within the sixteen bytes of the
 * GCM tag — often enough to recognise a known document from its size alone. It now goes through
 * the same ISO/IEC 7816-4 buckets as messages (`padding.ts`): padding is applied to the
 * **plaintext**, before encryption, because AES-GCM is a stream cipher and it is the plaintext
 * length that decides the ciphertext length.
 *
 * The bill is not small and should not be presented as if it were. Buckets double, so a 6 MiB
 * video is uploaded, stored and downloaded as 8 MiB, and a 9 MiB one as 16 MiB — up to 100 % more
 * bytes over the wire, paid by every recipient as well as the sender, and on a mobile data plan.
 * That is the price of the server no longer being able to match a size against a catalogue, and
 * it is a price, not a rounding error.
 *
 * What it still does not hide: that a file was sent, to whom, and when; the number of
 * attachments; and the order of magnitude of each one. A recipient's download of a given blob is
 * also visible to the server.
 */
import type { Api } from "./api";
import { pad, unpad } from "./padding.ts";

/** Descriptor carried inside the MLS message. This is what holds the secret. */
export interface AttachmentRef {
  id: string;
  /** AES-256-GCM key, in base64. Must never reach the server other than encrypted. */
  key: string;
  iv: string;
  /** Original name. This is content: it must not be handed to the server. */
  name: string;
  /** Type declared by the sender. Treat as a hint, never as proof. */
  mime: string;
  /** Plaintext size, for display before download. */
  size: number;
  /**
   * Is the blob padded?
   *
   * Set by every sender since padding landed; absent on descriptors written before it. Without
   * this flag an old attachment still sitting in the vault would be unpadded on read and either
   * throw or come back truncated.
   *
   * It solves one direction only: a client from before padding, handed a padded blob, hands the
   * user a file with a tail of zeroes on it. Nothing in the descriptor can fix that end, and it
   * is a real breakage for anyone running an old build.
   */
  padded?: boolean;
}

/**
 * The server refuses a request body above this (`MAX_ATTACHMENT_BYTES`, `crates/server/src/lib.rs`).
 * It bounds the **ciphertext**, which is what travels.
 */
const SERVER_CEILING = 25 * 1024 * 1024;

/** AES-GCM appends its authentication tag to the ciphertext. */
const GCM_TAG = 16;

/**
 * Largest padded plaintext whose ciphertext still fits under the server's ceiling.
 *
 * # Why a capped bucket rather than a lower limit
 *
 * The doubling stops at 16 MiB; the next bucket, 32 MiB, is above what the server accepts. Two
 * ways out. Refusing anything past 16 MiB keeps the buckets pure but takes a third of the
 * advertised limit away from the user for a privacy gain they never asked about — and the file
 * they wanted to send is simply rejected. Capping the top bucket instead keeps the limit where it
 * was and pads everything between 16 MiB and the ceiling into one final bucket.
 *
 * The cap loses no privacy relative to the ideal scheme: with a 32 MiB bucket unreachable, "over
 * 16 MiB" is the last class either way. It costs bandwidth, and a lot of it — a 17 MiB file is
 * uploaded as nearly 25 MiB, 47 % of it padding. Sending large files is where this scheme is at
 * its most expensive and least elegant, and nothing here fixes that.
 *
 * What the cap fails to hide: this ceiling is the client's, not a law of the protocol. A server
 * with a different limit, or a client built from another version of this file, produces different
 * top buckets — so the top bucket identifies the client as much as it hides the file.
 */
const TOP_BUCKET = SERVER_CEILING - GCM_TAG;

/**
 * Largest file that can be sent.
 *
 * One byte below the top bucket, because the marker byte is always added — a file of exactly
 * `TOP_BUCKET` bytes would have to pad past the ceiling.
 */
export const MAX_ATTACHMENT_BYTES = TOP_BUCKET - 1;

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** See the note on `buffer` in `keys.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

/**
 * Encrypts then uploads a file. Returns the descriptor to attach to the message.
 *
 * The key is marked extractable — it has to be exported to be sent to the recipient. This is the
 * justified exception to the principle followed everywhere else: a file key *must* travel, unlike
 * the identity and wrapping keys.
 */
export async function encryptAndUpload(
  api: Api,
  groupId: Uint8Array,
  file: File,
): Promise<AttachmentRef> {
  if (file.size > MAX_ATTACHMENT_BYTES) {
    // The limit is a hair under 25 MiB rather than exactly 25: padding rounds the plaintext up and
    // the tag adds sixteen bytes, and the whole thing has to stay under what the server accepts.
    throw new Error(
      `File too large (${Math.round(file.size / 1024 / 1024)} MB, maximum just under ${
        SERVER_CEILING / 1024 / 1024
      } MB).`,
    );
  }

  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // Padded before encryption, and it has to be that way round: padding the ciphertext would leave
  // the true length readable at the point where the recipient has to strip it, and would tell the
  // server nothing less. The copy costs a second buffer the size of the padded file — up to 25 MiB
  // of extra memory during the upload, on top of the file itself and its ciphertext.
  const plaintext = pad(new Uint8Array(await file.arrayBuffer()), TOP_BUCKET);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer(plaintext)),
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));

  const { id } = await api.uploadAttachment(groupId, ciphertext);

  return {
    id,
    key: toBase64(raw),
    iv: toBase64(iv),
    name: file.name,
    mime: file.type || "application/octet-stream",
    size: file.size,
    padded: true,
  };
}

/**
 * Fetches and decrypts an attachment.
 *
 * The AEAD carries integrity: if the server substitutes or alters the blob, decryption fails
 * instead of returning forged bytes. No separate digest is needed — the GCM tag does that work.
 *
 * The `Blob` is built with the type **declared by the sender**, which is only a hint. The caller
 * must never render it inline on this origin: an SVG or an HTML file displayed that way would run
 * script with the user's keys within reach.
 */
export async function downloadAndDecrypt(
  api: Api,
  groupId: Uint8Array,
  ref: AttachmentRef,
): Promise<Blob> {
  const ciphertext = await api.downloadAttachment(groupId, ref.id);

  const key = await crypto.subtle.importKey(
    "raw",
    buffer(fromBase64(ref.key)),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const decrypted = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(fromBase64(ref.iv)) },
      key,
      buffer(ciphertext),
    ),
  );

  // `unpad` throws on a malformed tail rather than guessing. That is the right behaviour here too:
  // these bytes carry a valid GCM tag, so they are the ones the sender encrypted — a padding that
  // does not parse means the two clients disagree about the format, and returning a plausible
  // prefix of the file would hide that behind a corrupt download.
  const plaintext = ref.padded ? unpad(decrypted) : decrypted;

  return new Blob([buffer(plaintext)], { type: ref.mime });
}
