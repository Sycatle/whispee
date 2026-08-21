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
 * # What leaks anyway
 *
 * The file's **size**, to within sixteen bytes. That is often enough to identify a known document.
 * Only padding would mask it, at the cost of bandwidth.
 */
import type { Api } from "./api";

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
}

/** Must stay under the server's ceiling (`MAX_ATTACHMENT_BYTES`). */
export const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

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
    throw new Error(
      `File too large (${Math.round(file.size / 1024 / 1024)} MB, maximum ${
        MAX_ATTACHMENT_BYTES / 1024 / 1024
      } MB).`,
    );
  }

  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new Uint8Array(await file.arrayBuffer());

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

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buffer(fromBase64(ref.iv)) },
    key,
    buffer(ciphertext),
  );

  return new Blob([plaintext], { type: ref.mime });
}
