/**
 * Keys held by the browser.
 *
 * Two distinct keys, with two distinct roles:
 *
 * * **auth** (Ed25519) — signs HTTP requests to the delivery service;
 * * **wrap** (AES-GCM) — encrypts MLS state before it touches IndexedDB.
 *
 * Both are created **non-extractable**: `crypto.subtle` will refuse to ever export their
 * material, including to our own code.
 *
 * # What "non-extractable" protects, and what it does not
 *
 * It prevents key material from being exfiltrated. It does **not** prevent a hostile script
 * running on this origin from using the key — signing, decrypting — while the page is open.
 * The distinction matters: a stolen key is permanent, abuse ends with the session.
 *
 * And above all: the server delivers this JavaScript. A compromised server can deliver a
 * version that uses these keys against the user. That is the structural limit of the web, and
 * no browser API fixes it.
 */

const AUTH_ALGORITHM = "Ed25519";

/**
 * TypeScript 5.7+ distinguishes `Uint8Array<ArrayBuffer>` from `Uint8Array<SharedArrayBuffer>`,
 * and WebCrypto only accepts the former. None of our arrays come from a `SharedArrayBuffer` —
 * not the WASM ones, not `getRandomValues`, not network decoding — but `subarray` and `slice`
 * lose that type information.
 *
 * A single named cast beats propagating the generic through every signature: if the assumption
 * ever becomes false, there is only one place to revisit.
 */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export interface DeviceKeys {
  auth: CryptoKeyPair;
  wrap: CryptoKey;
}

/**
 * Ed25519 in WebCrypto is available on Chrome 137+, Firefox 129+ and Safari 17+. If it is
 * missing we prefer to fail visibly rather than fall back to a JavaScript implementation where
 * the private key would sit exposed in the script's memory.
 */
export async function supportsEd25519(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey(AUTH_ALGORITHM, false, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
}

export async function generateDeviceKeys(): Promise<DeviceKeys> {
  const auth = (await crypto.subtle.generateKey(AUTH_ALGORITHM, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const wrap = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);

  return { auth, wrap };
}

/**
 * The public authentication key — the only half that leaves the device.
 *
 * As bytes, because the attestation covers it as-is: signing it in base64 form would make
 * verification depend on the encoding, and two valid encodings of the same bytes (padding,
 * URL-safe variant) would then produce two different signed messages.
 */
export async function exportAuthPublicKeyBytes(keys: DeviceKeys): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", keys.auth.publicKey));
}

/** The same key, in base64, for JSON bodies. */
export async function exportAuthPublicKey(keys: DeviceKeys): Promise<string> {
  return toBase64(await exportAuthPublicKeyBytes(keys));
}

export async function sign(keys: DeviceKeys, payload: Uint8Array): Promise<string> {
  const signature = await crypto.subtle.sign(
    AUTH_ALGORITHM,
    keys.auth.privateKey,
    buffer(payload),
  );
  return toBase64(new Uint8Array(signature));
}

/**
 * Encrypts MLS state before persistence, under the given key.
 *
 * The key is a parameter rather than a field of `DeviceKeys`: depending on whether the local
 * lock is active, it will be the master key derived from the password (which only exists in
 * memory) or the non-extractable key stored in IndexedDB.
 *
 * A random 96-bit nonce per encryption. AES-GCM breaks catastrophically if a nonce is reused
 * under the same key; 96 random bits make a collision negligible at the rate a client saves its
 * state.
 */
export async function wrapState(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer(plaintext));

  const out = new Uint8Array(iv.length + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), iv.length);
  return out;
}

export async function unwrapState(key: CryptoKey, blob: Uint8Array): Promise<Uint8Array> {
  if (blob.length <= 12) throw new Error("truncated encrypted state");

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buffer(blob.subarray(0, 12)) },
    key,
    buffer(blob.subarray(12)),
  );
  return new Uint8Array(plaintext);
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Inverse of `toHex`, for the group ids that come back from the real-time stream.
 *
 * An odd-length or non-hexadecimal input would produce silently wrong bytes — hence the explicit
 * rejection rather than a `NaN` propagating all the way into a request.
 */
export function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error("odd-length hex string");

  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex string");
    bytes[i] = byte;
  }
  return bytes;
}
