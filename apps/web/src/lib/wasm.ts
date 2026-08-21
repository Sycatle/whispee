/**
 * Loading the WebAssembly module.
 *
 * The binary weighs ~1.4 MB (≈515 KB gzipped): it must be served compressed and cached for a
 * long time. It is loaded once per tab, on demand.
 */
import type {
  AccountKey,
  Client,
  Pairing,
  accountFingerprint,
  deriveUnlockKey,
  sealPairing,
  accountId,
  verifyAttestation,
  verifyRevocation,
  verifyRotation,
  logLeaf,
  verifyInclusion,
  verifyConsistency,
  verifyTreeHead,
  postMac,
  signalMac,
  gatewayChallenge,
} from "./generated/crypto_wasm";

/**
 * What the WASM module exposes and the application needs.
 *
 * `Client` and `AccountKey` are deliberately distinct: an account outlives its devices, and a
 * device exists for the length of a pairing without holding the account key. Merging them would
 * suggest that one implies the other.
 */
export interface Crypto {
  Client: typeof Client;
  AccountKey: typeof AccountKey;
  Pairing: typeof Pairing;
  sealPairing: typeof sealPairing;
  deriveUnlockKey: typeof deriveUnlockKey;
  verifyAttestation: typeof verifyAttestation;
  verifyRevocation: typeof verifyRevocation;
  verifyRotation: typeof verifyRotation;
  accountId: typeof accountId;
  logLeaf: typeof logLeaf;
  verifyInclusion: typeof verifyInclusion;
  verifyConsistency: typeof verifyConsistency;
  verifyTreeHead: typeof verifyTreeHead;
  postMac: typeof postMac;
  signalMac: typeof signalMac;
  gatewayChallenge: typeof gatewayChallenge;
  accountFingerprint: typeof accountFingerprint;
}

let loading: Promise<Crypto> | null = null;

/**
 * Deliberate dynamic import: the wasm-bindgen glue must not enter the initial bundle. It touches
 * `WebAssembly` and `fetch` on evaluation, which has no business in a server-side render, and it
 * is only useful once the application is interactive.
 */
export function loadCrypto(): Promise<Crypto> {
  loading ??= import("./generated/crypto_wasm").then(async (module) => {
    await module.default({ module_or_path: "/crypto_wasm_bg.wasm" });
    return {
      Client: module.Client,
      AccountKey: module.AccountKey,
      Pairing: module.Pairing,
      sealPairing: module.sealPairing,
      deriveUnlockKey: module.deriveUnlockKey,
      verifyAttestation: module.verifyAttestation,
      verifyRevocation: module.verifyRevocation,
      verifyRotation: module.verifyRotation,
      accountId: module.accountId,
      logLeaf: module.logLeaf,
      verifyInclusion: module.verifyInclusion,
      verifyConsistency: module.verifyConsistency,
      verifyTreeHead: module.verifyTreeHead,
      postMac: module.postMac,
      signalMac: module.signalMac,
      gatewayChallenge: module.gatewayChallenge,
      accountFingerprint: module.accountFingerprint,
    };
  });
  return loading;
}

export type { AccountKey, Client, Pairing };

/** Return value of `sealPairing`. */
export interface Sealed {
  payload: Uint8Array;
  /** Short code to compare by eye on both screens. */
  confirmation: string;
}

/** Return value of `Pairing.open`. */
export interface Opened {
  plaintext: Uint8Array;
  confirmation: string;
}

/** Return value of `AccountKey.generate`. */
export interface CreatedAccount {
  /**
   * To be shown **once**, then forgotten. The application does not keep it and cannot show it
   * again: a phrase that can be shown on demand is a phrase anyone holding the unlocked device
   * can show too.
   */
  phrase: string;
  identityKey: Uint8Array;
}

/** A device as the server declares it. Nothing is settled before verification. */
export interface AttestedDevice {
  id: string;
  authKey: Uint8Array;
  mlsKey: Uint8Array;
  attestation: Uint8Array;
  /**
   * Revocation instant in Unix seconds, absent if the device is active.
   *
   * Revoked devices **are served**, with their certificate, and that is deliberate: hiding them
   * would make revocation indistinguishable from an omission by the server.
   */
  revokedAt?: number;
  /** Certificate signed by the account. Present exactly when `revokedAt` is. */
  revocation?: Uint8Array;
  /**
   * Last activity, in Unix seconds. **Served to the account owner only.**
   *
   * Absent for other people's devices: per-device detail would say how many devices someone owns
   * and which one they use at what hour. For yourself, it is what makes a genuinely active ghost
   * device visible.
   */
  lastSeen?: number;
}

/** Return value of `Client.invite`. */
export interface Invitation {
  /** For the members already present, so they advance an epoch. */
  commit: Uint8Array;
  /** For the invitee alone. */
  welcome: Uint8Array;
}

/** Return value of `Client.process`. */
export type Incoming =
  | { kind: "application"; sender: string | null; plaintext: Uint8Array }
  /** The group's composition or its keys changed: refresh the fingerprints. */
  | { kind: "groupChanged" }
  | { kind: "proposal" };

export interface Peer {
  name: string;
  fingerprint: string;
}
