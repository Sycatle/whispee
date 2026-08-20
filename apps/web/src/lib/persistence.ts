/**
 * Où la session est rangée, et sous quelle clé.
 *
 * # Pourquoi les deux ensemble
 *
 * Un store et un chiffreur ne se choisissent pas séparément : la clé qui ouvre l'état doit être
 * celle sous laquelle il a été scellé, et l'ordre compte — il faut les clés pour construire le
 * chiffreur, et le chiffreur pour ouvrir ce que le store rend. Les livrer par paire évite le
 * seul assemblage faux possible, celui qui rendrait un état illisible sans rien dire d'autre
 * qu'une erreur de déchiffrement.
 *
 * # Deux ancrages, pas deux sessions
 *
 * Sur le web, les clés vivent dans IndexedDB à côté de l'état ; sous Tauri, dans le processus
 * natif, et l'état dans un fichier. `Session` ne sait pas lequel la sert, et c'est le but : la
 * différence est entièrement contenue ici.
 */
import { NativeCipher, WebCryptoCipher, type DeviceCipher } from "./cipher";
import { generateDeviceKeys, type DeviceKeys } from "./keys";
import { isTauri } from "./platform";
import { IndexedDbStore, readStoredKeys, type SessionStore } from "./storage";
import { NativeStore, pontTauri } from "./storage-native";

export interface Ancrage {
  store: SessionStore;
  /**
   * Le chiffreur **socle** : celui qui porte l'identité de l'appareil.
   *
   * Distinct de la clé au repos, que le verrou local remplace. Poser un verrou ne change pas
   * l'identité — le serveur ne voit rien — donc c'est bien le socle qu'on garde ici.
   */
  cipher: DeviceCipher;
}

/** L'ancrage natif. Sans état à charger : les clés sont déjà dans le processus. */
export function ancrageNatif(): Ancrage {
  const cipher = new NativeCipher();
  return { store: new NativeStore(cipher, pontTauri()), cipher };
}

/**
 * L'ancrage du navigateur, s'il existe déjà.
 *
 * `undefined` quand la base ne contient pas de clés : c'est une installation neuve, et créer
 * des clés ici les écrirait avant qu'un compte n'existe.
 */
export async function ancrageWebExistant(): Promise<Ancrage | undefined> {
  const keys = await readStoredKeys();
  return keys === undefined ? undefined : ancrageWeb(keys);
}

export function ancrageWeb(keys: DeviceKeys): Ancrage {
  return { store: new IndexedDbStore(keys), cipher: new WebCryptoCipher(keys) };
}

/** Des clés de navigateur toutes neuves, pour un appareil qui n'existe pas encore. */
export async function ancrageWebNeuf(): Promise<Ancrage> {
  return ancrageWeb(await generateDeviceKeys());
}

/**
 * L'ancrage d'un appareil neuf sur cette plateforme.
 *
 * Sous Tauri, natif : c'est là tout l'intérêt, puisque le stockage d'une webview mobile est
 * évincé sans préavis et qu'une perte d'état MLS est définitive. Ailleurs, IndexedDB, faute de
 * mieux — le navigateur reste le seul à pouvoir garder un secret hors de portée du script qu'il
 * exécute.
 */
export function ancrageNeuf(): Promise<Ancrage> {
  return isTauri() ? Promise.resolve(ancrageNatif()) : ancrageWebNeuf();
}

/**
 * L'ancrage de la session déjà installée, s'il y en a une.
 *
 * Sous Tauri, le natif est interrogé en premier : une session native présente signifie que la
 * migration est faite, et l'ancienne session web qui subsisterait ne serait qu'un reste à
 * effacer. L'ordre inverse ferait redémarrer l'application sur l'ancien appareil, révoqué.
 */
export async function ancrageCourant(): Promise<Ancrage | undefined> {
  if (isTauri()) {
    const natif = ancrageNatif();
    if (await natif.store.load()) return natif;
  }

  return ancrageWebExistant();
}

/**
 * Efface tout ce qui est rangé, des deux côtés.
 *
 * Sert au cas où le mot de passe du verrou est perdu : il n'y a alors aucune session à ouvrir,
 * donc aucun moyen de savoir laquelle des deux existe. Effacer les deux est la seule réponse
 * complète — en oublier une laisserait l'application redémarrer sur l'identité que
 * l'utilisateur croit détruite.
 */
export async function effacerTout(): Promise<void> {
  if (isTauri()) await ancrageNatif().store.clear();

  const web = await ancrageWebExistant();
  await web?.store.clear();
}
