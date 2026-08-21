/**
 * Resolving an account into devices, and checking what the server says.
 *
 * # Why this module exists
 *
 * As soon as an account gathers several devices, someone has to say which ones. That someone is
 * the server: it keeps the list, and it serves it. A list it composes freely would be enough for
 * it to invite itself into any conversation — the message would stay end-to-end encrypted, one of
 * the ends would simply be the server.
 *
 * So every served device carries an attestation signed by the account. This module re-verifies it,
 * systematically, before any device enters a group.
 *
 * # What the attestation does not prevent
 *
 * The server can still **omit** a legitimate device from the list. The victim then notices that
 * one of their devices stops receiving new conversations: that is censorship, noisy and useless to
 * anyone who wants to read quietly. Detecting it would take an auditable key transparency log, out
 * of scope here.
 *
 * The asymmetry is the win: the server can subtract, never add.
 *
 * # Do not rely on the server's verification
 *
 * The server already verifies attestations on write, but the server is exactly who we suspect: its
 * verification is only an early filter, never a guarantee. All the protection rests on this file
 * doing the work again.
 */
import type { Api } from "./api";
import type { AttestedDevice, Crypto } from "./wasm";

export interface ResolvedAccount {
  /**
   * What identifies the account: the fingerprint of its genesis key.
   *
   * Was the handle, and the rename is not cosmetic — the attestations below are signed over this
   * string, so a value that could move would make every one of them expire on a rename.
   */
  handle: string;
  /** The account's public key. This is what gets compared out of band, via its fingerprint. */
  identityKey: Uint8Array;
  /** Fingerprint to display. Stable when the account gains or loses a device. */
  fingerprint: string;
  /** Active devices whose attestation was verified right here. */
  devices: AttestedDevice[];
  /**
   * Devices whose revocation was verified right here.
   *
   * Served by the server rather than hidden, so that omission stays distinguishable from
   * revocation. Their MLS keys feed the group policy: that is what lets a non-admin member evict
   * them without waiting for an admin to come back.
   */
  revoked: AttestedDevice[];
  /**
   * MLS signature keys of the revoked devices, ready for `Client.process`.
   *
   * An empty context is not neutral: it makes the removal of a stolen device fail, of all things.
   * That is the most likely implementation trap, hence this ready-made field rather than a filter
   * every caller has to redo.
   */
  revokedKeys: Uint8Array[];
  /**
   * Devices served by the server but rejected.
   *
   * Non-empty means the server served something it should not have been able to produce. This is
   * not a benign error to absorb in silence: it is the exact signal we were after, and the
   * interface has to show it.
   */
  rejected: AttestedDevice[];
}

/**
 * Queries the server and keeps only what verifies.
 *
 * The caller gets a list whose every element has been proven to belong to the account. The others
 * are returned separately rather than thrown away: making them disappear would amount to hiding a
 * substitution attempt.
 */
export async function resolveAccount(
  api: Api,
  crypto: Crypto,
  account: string,
): Promise<ResolvedAccount> {
  const { identityKey, devices } = await api.listAccountDevices(account);

  const verified: AttestedDevice[] = [];
  const revoked: AttestedDevice[] = [];
  const rejected: AttestedDevice[] = [];

  for (const device of devices) {
    const attested = crypto.verifyAttestation(
      identityKey,
      account,
      device.id,
      device.authKey,
      device.mlsKey,
      device.attestation,
    );

    if (!attested) {
      rejected.push(device);
      continue;
    }

    if (device.revokedAt === undefined || device.revocation === undefined) {
      verified.push(device);
      continue;
    }

    // A revocation announced without a valid certificate is not a revocation: it is the server
    // trying to push aside a legitimate device. We refuse it and keep the device active —
    // treating it as revoked would mean carrying out the censorship we are trying to detect.
    const certified = crypto.verifyRevocation(
      identityKey,
      account,
      device.id,
      BigInt(device.revokedAt),
      device.revocation,
    );

    if (certified) {
      revoked.push(device);
    } else {
      rejected.push(device);
    }
  }

  return {
    handle: account,
    identityKey,
    fingerprint: crypto.accountFingerprint(identityKey),
    devices: verified,
    revoked,
    revokedKeys: revoked.map((device) => device.mlsKey),
    rejected,
  };
}
