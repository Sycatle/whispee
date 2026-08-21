/**
 * Application envelope carried inside the server's opaque blobs.
 *
 * The server does not speak MLS: it routes bytes. But a conversation stream mixes two things that
 * are handled differently — ordinary MLS messages, and the Welcome that lets a newcomer join. A
 * type byte tells them apart.
 *
 * The Welcome therefore travels in the clear from the server's point of view, and that is of no
 * consequence: its secrets are encrypted to the init key of the invitee's KeyPackage, and the
 * ratchet tree is public by construction.
 */

const TYPE_MLS = 0;
const TYPE_WELCOME = 1;

export type Parsed =
  | { kind: "mls"; payload: Uint8Array }
  | { kind: "welcome"; welcome: Uint8Array; ratchetTree: Uint8Array };

export function encodeMls(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + payload.length);
  out[0] = TYPE_MLS;
  out.set(payload, 1);
  return out;
}

export function encodeWelcome(welcome: Uint8Array, ratchetTree: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + 4 + welcome.length + ratchetTree.length);
  out[0] = TYPE_WELCOME;
  new DataView(out.buffer).setUint32(1, welcome.length, false);
  out.set(welcome, 5);
  out.set(ratchetTree, 5 + welcome.length);
  return out;
}

/**
 * These bytes come from the network: any inconsistent length must produce an error, and never an
 * out-of-bounds read or a silently truncated array.
 */
export function decode(blob: Uint8Array): Parsed {
  if (blob.length < 1) throw new Error("empty envelope");

  switch (blob[0]) {
    case TYPE_MLS:
      return { kind: "mls", payload: blob.subarray(1) };

    case TYPE_WELCOME: {
      if (blob.length < 5) throw new Error("truncated welcome envelope");
      const welcomeLength = new DataView(blob.buffer, blob.byteOffset).getUint32(1, false);
      if (5 + welcomeLength > blob.length) throw new Error("inconsistent welcome length");
      return {
        kind: "welcome",
        welcome: blob.subarray(5, 5 + welcomeLength),
        ratchetTree: blob.subarray(5 + welcomeLength),
      };
    }

    default:
      throw new Error(`unknown envelope type: ${blob[0]}`);
  }
}
