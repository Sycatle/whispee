/**
 * Pairing a new device.
 *
 * # Which way the QR points, and why it is not arbitrary
 *
 * The **new** device displays, the **old** one scans. A QR code can be photographed by
 * construction: putting a secret in it would amount to publishing it. This one carries only an
 * ephemeral public key and a deposit address, both worthless to whoever intercepts them.
 *
 * The old device then seals the packet under the shared X25519 secret and deposits it on the
 * server, which only ever sees a blob: it holds neither of the two private halves.
 *
 * # What is not protected
 *
 * The channel's security is **physical**: it rests on the user only scanning the screen they are
 * holding. An attacker who shows them their own QR code gets paired, and no cryptography can
 * prevent it. That is WhatsApp's model, and Signal's.
 */
import { Api } from "./api";
import { fromBase64, toBase64 } from "./keys";

/** What the QR code encodes. None of these fields is secret. */
export interface PairingCode {
  id: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Encodes the offer into a compact string.
 *
 * The QR code is not always practical — a screen that cannot be shown, no camera on a desktop
 * computer. The same string can then be copied by hand, with exactly the same properties: it
 * contains nothing secret.
 */
export function encodePairingCode(code: PairingCode): string {
  const joined = new Uint8Array(code.id.length + code.publicKey.length);
  joined.set(code.id, 0);
  joined.set(code.publicKey, code.id.length);
  return toBase64(joined).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodePairingCode(text: string): PairingCode {
  const normalized = text.trim().replace(/-/g, "+").replace(/_/g, "/");
  const bytes = fromBase64(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));

  // 16 bytes of id + 32 of X25519 key. An unexpected length signals a truncated entry, not an
  // attack — but failing here beats sealing into the void.
  if (bytes.length !== 48) {
    throw new Error("Invalid or incomplete pairing code.");
  }

  return { id: bytes.slice(0, 16), publicKey: bytes.slice(16) };
}

export function depositPairing(api: Api, id: Uint8Array, payload: Uint8Array): Promise<unknown> {
  return api.depositPairing(id, payload);
}

/**
 * Waits for the original device to deposit the packet.
 *
 * The server does not notify: we poll. The window is short — the packet contains enough to take
 * control of the account, and the server expires it after five minutes.
 */
export async function awaitPairing(
  id: Uint8Array,
  signal: { cancelled: boolean },
): Promise<Uint8Array | null> {
  const deadline = Date.now() + 5 * 60 * 1000;

  while (!signal.cancelled && Date.now() < deadline) {
    const payload = await Api.claimPairing(id);
    if (payload) return payload;
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
  return null;
}
