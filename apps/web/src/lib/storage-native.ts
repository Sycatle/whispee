/**
 * La session rangée par le processus natif, plutôt que par la webview.
 *
 * # Ce que cela achète
 *
 * De la durabilité, et rien d'autre. Le stockage d'une webview mobile **n'est pas garanti** : iOS
 * évince les données de WKWebView après sept jours d'inactivité, Android purge sous pression
 * mémoire. Et la perte est définitive — le ratchet MLS détruit ses clés au fur et à mesure, donc
 * l'historique devient illisible et les conversations sont à recréer. Le répertoire privé de
 * l'application, lui, n'est purgé qu'à la désinstallation.
 *
 * # Le chiffrement reste ici, pas côté Rust
 *
 * `session_save` écrit les octets qu'on lui donne, sans les regarder. C'est délibéré : le
 * chiffrement passe par `DeviceCipher`, la même abstraction que sur le web, donc le format sur
 * disque ne dépend pas de la plateforme et le jour où un verrou local change la clé au repos, il
 * n'y a qu'un endroit à toucher.
 *
 * # Pourquoi le pont est injecté
 *
 * `invoke` n'existe que dans une webview Tauri. Le passer en paramètre rend cette classe
 * testable sans application — et le test qui compte ici est celui d'un aller-retour complet, y
 * compris le scellement, puisque c'est l'enchaînement codec → chiffrement → fichier qui peut
 * perdre un compte, pas chacun de ses maillons.
 */
import { invoke } from "@tauri-apps/api/core";

import { fromBase64, toBase64 } from "./keys.ts";
import { decoderSession, encoderSession } from "./session-codec.ts";
import type { SessionStore, StoredSession } from "./storage.ts";
import type { DeviceCipher } from "./cipher.ts";

/**
 * Les trois commandes natives dont le store a besoin.
 *
 * Volontairement plus étroit que l'ensemble des commandes : ce qui manipule les clés passe par
 * `DeviceCipher`, ce qui manipule le fichier passe par ici, et aucun des deux ne peut faire le
 * travail de l'autre.
 */
export interface PontSession {
  /** Le blob scellé, en base64, ou `null` au premier lancement. */
  charger(): Promise<string | null>;
  enregistrer(contenu: string): Promise<void>;
  effacer(): Promise<void>;
}

/**
 * Le pont réel, adossé à l'IPC de Tauri.
 *
 * `invoke` est importé statiquement : `cipher.ts` le fait déjà, donc le différer ici ne
 * retirerait rien du paquet — cela donnerait seulement l'illusion que le module se charge sans
 * Tauri. L'appel, lui, n'a lieu que si quelqu'un construit ce pont.
 */
export function pontTauri(): PontSession {
  return {
    charger: () => invoke<string | null>("session_load"),
    enregistrer: (contenu) => invoke<void>("session_save", { contenu }),
    effacer: () => invoke<void>("session_clear"),
  };
}

/**
 * Le store natif.
 *
 * # Le même port que le store du navigateur
 *
 * `StoredSession` ne porte aucune clé : celles du navigateur sont rangées par `IndexedDbStore`,
 * celles-ci vivent dans le processus natif. C'est ce qui permet aux deux stores de remplir la
 * même interface, et à la session d'ignorer laquelle des deux la sert.
 *
 * # Une installation existante ne bascule pas dessus telle quelle
 *
 * Ses clés sont enfermées dans IndexedDB, non extractables, et le serveur **refuse d'en changer**
 * (clause sur `auth_key` dans `register_device`). Un store natif adossé à des clés natives neuves
 * ne saurait ni relire son ancien état ni prouver son identité : il faut enregistrer un appareil
 * neuf et révoquer l'ancien. Voir `migration.ts`.
 */
export class NativeStore implements SessionStore {
  // Champs déclarés plutôt que propriétés de paramètre : le lanceur de tests de Node se
  // contente de retirer les types, et une propriété de paramètre demanderait une transformation.
  private readonly cipher: DeviceCipher;
  private readonly pont: PontSession;

  constructor(cipher: DeviceCipher, pont: PontSession) {
    this.cipher = cipher;
    this.pont = pont;
  }

  async load(): Promise<StoredSession | undefined> {
    const scelle = await this.pont.charger();
    // `null` est un premier lancement, pas une panne. Les confondre créerait un compte neuf
    // par-dessus un état encore présent, ce qui est irréversible.
    if (scelle === null) return undefined;

    return decoderSession(await this.cipher.open(fromBase64(scelle)));
  }

  async save(session: StoredSession): Promise<void> {
    const scelle = await this.cipher.seal(encoderSession(session));
    await this.pont.enregistrer(toBase64(scelle));
  }

  /**
   * Efface la session, **et pas les secrets**.
   *
   * La commande native s'en tient là volontairement : oublier une session laisse un appareil
   * enregistré qui repart de zéro, effacer les secrets laisse une identité que le serveur
   * connaît encore mais que plus personne ne peut prouver. Le second effacement existe, et c'est
   * un autre appel.
   */
  async clear(): Promise<void> {
    await this.pont.effacer();
  }
}
