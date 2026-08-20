/**
 * Ce qu'un appareil sait faire avec ses secrets, sans jamais les montrer.
 *
 * # Une capacité, pas un porteur de clé
 *
 * `DeviceKeys` — deux `CryptoKey` passées de fonction en fonction — imposait que le secret
 * circule, fût-ce sous une forme que WebCrypto refuse d'exporter. Cette interface impose
 * l'inverse : l'appelant demande une signature ou un déchiffrement, et ne voit jamais de
 * matériel de clé.
 *
 * La distinction n'est pas cosmétique. C'est elle qui permettra à la clé de vivre ailleurs que
 * dans la webview — dans le processus Rust, puis dans le trousseau du système — sans que le
 * reste du code sache que quoi que ce soit a changé.
 *
 * # Le problème que cela prépare
 *
 * L'état MLS est aujourd'hui persisté dans IndexedDB. Sur mobile, ce stockage **n'est pas
 * garanti** : iOS évince les données de WKWebView après sept jours d'inactivité, Android purge
 * sous pression mémoire. Et sa perte est **définitive** — le ratchet MLS détruit ses clés au fur
 * et à mesure, donc l'historique devient illisible et les conversations sont à recréer.
 *
 * Déplacer l'état ne suffirait pas : la clé d'authentification de l'appareil est au moins aussi
 * mortelle à perdre, et pire, elle est non extractable et le serveur **refuse d'en changer**
 * (voir la clause sur `auth_key` dans `register_device`). Un état sauvé dont la clé
 * d'authentification a disparu ne sert à rien : l'appareil ne peut plus émettre une requête.
 *
 * D'où une interface qui couvre les deux — signer et sceller — plutôt qu'un simple port de
 * stockage.
 *
 * # Ce que « non extractable » protège, et ce que ça ne protège pas
 *
 * Cela empêche l'exfiltration du matériel de clé. Cela n'empêche **pas** un script hostile de
 * s'en servir tant que la page est ouverte. La distinction compte : un vol de clé est permanent,
 * un usage abusif cesse avec la session. Une clé détenue par le processus Rust et exposée par
 * IPC offrira exactement la même propriété, garantie cette fois par une frontière de processus
 * plutôt que par une politique de moteur JavaScript.
 */
import { invoke } from "@tauri-apps/api/core";

import {
  type DeviceKeys,
  fromBase64,
  sign as signAvecWebCrypto,
  toBase64,
  unwrapState,
  wrapState,
} from "./keys";

export interface DeviceCipher {
  /** La clé publique d'authentification, en octets — la seule moitié qui quitte l'appareil. */
  authPublicKey(): Promise<Uint8Array>;

  /** Signe un message de requête. Rend la signature en base64, prête pour l'en-tête. */
  sign(payload: Uint8Array): Promise<string>;

  /** Chiffre pour la persistance locale. */
  seal(plaintext: Uint8Array): Promise<Uint8Array>;

  /** Déchiffre ce que `seal` a produit. */
  open(blob: Uint8Array): Promise<Uint8Array>;
}

/**
 * L'implémentation historique, adossée aux `CryptoKey` non extractables d'IndexedDB.
 *
 * Reste le seul chemin sur le web, où il n'y a rien de mieux : le navigateur est le seul à
 * pouvoir garder un secret hors de portée du script qu'il exécute.
 */
export class WebCryptoCipher implements DeviceCipher {
  constructor(
    private readonly keys: DeviceKeys,
    /**
     * Clé de chiffrement au repos.
     *
     * Séparée de `keys` parce qu'elle **change** : sans verrou local c'est `keys.wrap`, la clé
     * non extractable rangée à côté ; avec verrou c'est une clé maîtresse qui n'existe qu'en
     * mémoire après saisie du mot de passe. Voir `lock.ts`.
     */
    private readonly atRest: CryptoKey,
  ) {}

  async authPublicKey(): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.exportKey("raw", this.keys.auth.publicKey));
  }

  sign(payload: Uint8Array): Promise<string> {
    return signAvecWebCrypto(this.keys, payload);
  }

  seal(plaintext: Uint8Array): Promise<Uint8Array> {
    return wrapState(this.atRest, plaintext);
  }

  open(blob: Uint8Array): Promise<Uint8Array> {
    return unwrapState(this.atRest, blob);
  }

  /**
   * Le même appareil, mais chiffrant au repos sous une autre clé.
   *
   * C'est ce que fait la pose ou le retrait du verrou : l'identité de l'appareil ne change pas —
   * la clé d'authentification est la même, le serveur ne voit rien — seule bascule la clé qui
   * protège l'état sur le disque.
   */
  withKeyAtRest(atRest: CryptoKey): WebCryptoCipher {
    return new WebCryptoCipher(this.keys, atRest);
  }

  /**
   * Les clés brutes, pour le seul code qui doit encore les voir : la persistance, qui range les
   * `CryptoKey` non extractables dans IndexedDB.
   *
   * **À supprimer** quand le stockage natif prendra le relais. Chaque appelant restant est une
   * raison de plus pour laquelle la clé ne peut pas encore quitter la webview.
   */
  get rawKeys(): DeviceKeys {
    return this.keys;
  }
}

/**
 * Les mêmes capacités, rendues par le processus natif.
 *
 * # Ce que cela change, et ce que cela ne change pas
 *
 * Les clés vivent côté Rust, dans le répertoire privé de l'application — qui n'est purgé qu'à la
 * désinstallation, là où le stockage d'une webview mobile est évincé sans préavis. C'est la
 * durabilité qu'on vient chercher.
 *
 * Ce n'est **pas** un renforcement contre un script hostile. Il pouvait déjà utiliser les
 * `CryptoKey` non extractables sans les extraire ; il peut toujours appeler ces commandes. Ce
 * qui change est la garantie qui empêche l'extraction : une frontière de processus au lieu d'une
 * politique de moteur JavaScript.
 *
 * # Pourquoi rien ne l'utilise encore
 *
 * Basculer une installation existante vers ces clés-ci la casserait : les clés natives sont
 * neuves, donc l'état chiffré sous l'ancienne clé devient illisible et le serveur ne reconnaît
 * plus la signature de l'appareil. La bascule est indissociable de la migration, et la migration
 * bute sur un point dur — la clé d'authentification actuelle est non extractable et
 * `register_device` refuse d'en changer, donc les appareils déjà enregistrés ne peuvent pas la
 * déplacer.
 *
 * Le brancher avant d'avoir tranché cela ne ferait pas gagner de temps : cela ferait perdre des
 * comptes.
 */
export class NativeCipher implements DeviceCipher {
  async authPublicKey(): Promise<Uint8Array> {
    return fromBase64(await invoke<string>("device_public_key"));
  }

  /** Rend déjà du base64 : la commande native signe et encode, il n'y a rien à reconvertir. */
  sign(payload: Uint8Array): Promise<string> {
    return invoke<string>("device_sign", { payload: toBase64(payload) });
  }

  async seal(plaintext: Uint8Array): Promise<Uint8Array> {
    return fromBase64(await invoke<string>("state_seal", { plaintext: toBase64(plaintext) }));
  }

  async open(blob: Uint8Array): Promise<Uint8Array> {
    return fromBase64(await invoke<string>("state_open", { blob: toBase64(blob) }));
  }
}

/** Réexporté pour que les appelants n'aient pas à importer `keys.ts` juste pour encoder. */
export { toBase64 };
