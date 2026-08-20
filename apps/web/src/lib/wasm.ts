/**
 * Chargement du module WebAssembly.
 *
 * Le binaire fait ~1,4 Mo (≈515 Ko gzip) : il doit être servi compressé et mis en cache
 * longuement. Il est chargé une seule fois par onglet, à la demande.
 */
import type {
  AccountKey,
  Client,
  Pairing,
  accountFingerprint,
  deriveUnlockKey,
  sealPairing,
  verifyAttestation,
  verifyRevocation,
  logLeaf,
  verifyInclusion,
  verifyConsistency,
  verifyTreeHead,
  postMac,
  signalMac,
} from "./generated/crypto_wasm";

/**
 * Ce que le module WASM expose et dont l'application a besoin.
 *
 * `Client` et `AccountKey` sont volontairement distincts : un compte survit à ses appareils,
 * et un appareil existe le temps d'un appairage sans détenir la clé du compte. Les fusionner
 * laisserait croire que l'un implique l'autre.
 */
export interface Crypto {
  Client: typeof Client;
  AccountKey: typeof AccountKey;
  Pairing: typeof Pairing;
  sealPairing: typeof sealPairing;
  deriveUnlockKey: typeof deriveUnlockKey;
  verifyAttestation: typeof verifyAttestation;
  verifyRevocation: typeof verifyRevocation;
  logLeaf: typeof logLeaf;
  verifyInclusion: typeof verifyInclusion;
  verifyConsistency: typeof verifyConsistency;
  verifyTreeHead: typeof verifyTreeHead;
  postMac: typeof postMac;
  signalMac: typeof signalMac;
  accountFingerprint: typeof accountFingerprint;
}

let loading: Promise<Crypto> | null = null;

/**
 * Import dynamique volontaire : le glue wasm-bindgen ne doit pas entrer dans le bundle
 * initial. Il touche `WebAssembly` et `fetch` à l'évaluation, ce qui n'a rien à faire
 * dans un rendu côté serveur, et il n'est utile qu'une fois l'application interactive.
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
      logLeaf: module.logLeaf,
      verifyInclusion: module.verifyInclusion,
      verifyConsistency: module.verifyConsistency,
      verifyTreeHead: module.verifyTreeHead,
      postMac: module.postMac,
      signalMac: module.signalMac,
      accountFingerprint: module.accountFingerprint,
    };
  });
  return loading;
}

export type { AccountKey, Client, Pairing };

/** Retour de `sealPairing`. */
export interface Sealed {
  payload: Uint8Array;
  /** Code court à comparer de visu sur les deux écrans. */
  confirmation: string;
}

/** Retour de `Pairing.open`. */
export interface Opened {
  plaintext: Uint8Array;
  confirmation: string;
}

/** Retour de `AccountKey.generate`. */
export interface CreatedAccount {
  /**
   * À afficher **une seule fois**, puis à oublier. L'application ne la conserve pas et ne
   * peut pas la réafficher : une phrase remontrable à la demande est une phrase que quiconque
   * tient l'appareil déverrouillé peut remontrer aussi.
   */
  phrase: string;
  identityKey: Uint8Array;
}

/** Un appareil tel que le serveur le déclare. Rien n'est acquis avant vérification. */
export interface AttestedDevice {
  id: string;
  authKey: Uint8Array;
  mlsKey: Uint8Array;
  attestation: Uint8Array;
  /**
   * Instant de révocation en secondes Unix, absent si l'appareil est actif.
   *
   * Les appareils révoqués **sont servis** avec leur certificat, et c'est délibéré : les taire
   * rendrait la révocation indiscernable d'une omission par le serveur.
   */
  revokedAt?: number;
  /** Certificat signé par le compte. Présent exactement quand `revokedAt` l'est. */
  revocation?: Uint8Array;
}

/** Retour de `Client.invite`. */
export interface Invitation {
  /** Aux membres déjà présents, pour qu'ils avancent d'epoch. */
  commit: Uint8Array;
  /** Au seul invité. */
  welcome: Uint8Array;
}

/** Retour de `Client.process`. */
export type Incoming =
  | { kind: "application"; sender: string | null; plaintext: Uint8Array }
  /** La composition du groupe ou ses clés ont changé : rafraîchir les empreintes. */
  | { kind: "groupChanged" }
  | { kind: "proposal" };

export interface Peer {
  name: string;
  fingerprint: string;
}
