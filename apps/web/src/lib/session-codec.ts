/**
 * Traduction de la session en octets, pour les stockages qui ne savent ranger que des octets.
 *
 * # Pourquoi ce module existe séparément
 *
 * IndexedDB accepte une `StoredSession` telle quelle : le clonage structuré sait transporter un
 * `Uint8Array`, et même une `CryptoKey` non extractable. Un fichier ne sait rien de tout cela. Le
 * store natif a donc besoin d'une traduction, et cette traduction est le seul endroit où les
 * invariants de forme de la session sont écrits noir sur blanc — ce qui vaut d'être testable sans
 * base de données ni processus Rust.
 *
 * # Ce que le codec ne transporte pas
 *
 * Les clés. `StoredSession` n'en porte aucune : sur le web elles vivent dans la même base, mais
 * c'est le store qui les y range, pas la session. Un fichier ne pourrait pas les recevoir — des
 * `CryptoKey` non extractables ne se sérialisent pas, par construction — et il n'a pas à le
 * faire : sous Tauri elles vivent dans le processus natif, derrière `NativeCipher`.
 *
 * # Le champ qui justifie les tests
 *
 * `vaultEnabled` a **trois** états et non deux : absent vaut « actif » — le coffre est le défaut
 * — tandis que `false` est un refus explicite de l'utilisateur. Un codec qui normaliserait
 * l'absence en `false` couperait la sauvegarde d'un compte neuf ; un codec qui normaliserait
 * `false` en absent la rallumerait dans le dos de quelqu'un qui l'avait coupée. La seconde erreur
 * est la pire, et aucune des deux ne se voit à l'œil nu. Même raisonnement pour
 * `signals.presence`.
 */
import { fromBase64, toBase64 } from "./keys.ts";
import type { StoredSession } from "./storage";

/**
 * Version du format sur disque.
 *
 * Présente dès la première version : l'ajouter après coup obligerait à deviner l'âge d'un fichier
 * qui ne le dit pas.
 */
const VERSION = 1;

/**
 * Encode en JSON UTF-8.
 *
 * Les octets deviennent du base64 plutôt qu'un tableau de nombres — un `Uint8Array` passé à
 * `JSON.stringify` devient un objet indexé par chaînes, qui se relit en objet et non en tableau
 * d'octets. La panne serait silencieuse : `state` redeviendrait un objet vide plutôt que d'échouer.
 */
export function encoderSession(session: StoredSession): Uint8Array {
  const brut = {
    v: VERSION,
    deviceId: session.deviceId,
    handle: session.handle,
    accountSeed: toBase64(session.accountSeed),
    lock: session.lock,
    vaultEnabled: session.vaultEnabled,
    state: session.state === undefined ? undefined : toBase64(session.state),
    groupIds: session.groupIds.map(toBase64),
    verified: session.verified,
    cursors: session.cursors,
    knownDevices: session.knownDevices,
    signals: session.signals,
    postingKeys: session.postingKeys,
  };

  return new TextEncoder().encode(JSON.stringify(brut));
}

/**
 * Relit ce qu'`encoderSession` a produit, ou lève.
 *
 * Lever plutôt que rendre une session partielle : un état MLS amputé de son curseur rejouerait
 * des clés déjà consommées, et la conversation resterait vide après un simple rechargement. Une
 * erreur visible au démarrage vaut mieux qu'une session qui semble marcher.
 */
export function decoderSession(octets: Uint8Array): StoredSession {
  const brut: unknown = JSON.parse(new TextDecoder().decode(octets));

  if (typeof brut !== "object" || brut === null) {
    throw new Error("session illisible : la racine n'est pas un objet");
  }

  const champ = brut as Record<string, unknown>;

  if (champ.v !== VERSION) {
    throw new Error(`session en version ${String(champ.v)}, attendue ${VERSION}`);
  }

  return {
    deviceId: exigerChaine(champ.deviceId, "deviceId"),
    handle: exigerChaine(champ.handle, "handle"),
    accountSeed: fromBase64(exigerChaine(champ.accountSeed, "accountSeed")),
    // Les optionnels sont répandus conditionnellement plutôt qu'affectés à `undefined` : une
    // propriété présente et valant `undefined` n'est pas la même chose qu'une propriété absente
    // pour `Object.keys`, pour une comparaison structurelle, ou pour un futur `in`. Puisque toute
    // la subtilité de `vaultEnabled` tient à la distinction absent / `false`, autant que la forme
    // relue soit exactement celle qui a été écrite.
    ...(champ.lock === undefined ? {} : { lock: champ.lock as StoredSession["lock"] }),
    ...(champ.vaultEnabled === undefined ? {} : { vaultEnabled: champ.vaultEnabled as boolean }),
    ...(champ.state === undefined
      ? {}
      : { state: fromBase64(exigerChaine(champ.state, "state")) }),
    groupIds: exigerTableau(champ.groupIds, "groupIds").map((valeur, index) =>
      fromBase64(exigerChaine(valeur, `groupIds[${index}]`)),
    ),
    verified: exigerObjet(champ.verified, "verified") as Record<string, string>,
    cursors: exigerObjet(champ.cursors, "cursors") as Record<string, number>,
    knownDevices: exigerObjet(champ.knownDevices, "knownDevices") as Record<string, string[]>,
    ...(champ.signals === undefined ? {} : { signals: champ.signals as StoredSession["signals"] }),
    ...(champ.postingKeys === undefined
      ? {}
      : { postingKeys: champ.postingKeys as Record<string, string> }),
  };
}

function exigerChaine(valeur: unknown, nom: string): string {
  if (typeof valeur !== "string") throw new Error(`session illisible : ${nom} n'est pas une chaîne`);
  return valeur;
}

function exigerTableau(valeur: unknown, nom: string): unknown[] {
  if (!Array.isArray(valeur)) throw new Error(`session illisible : ${nom} n'est pas un tableau`);
  return valeur;
}

function exigerObjet(valeur: unknown, nom: string): Record<string, unknown> {
  if (typeof valeur !== "object" || valeur === null || Array.isArray(valeur)) {
    throw new Error(`session illisible : ${nom} n'est pas un objet`);
  }
  return valeur as Record<string, unknown>;
}
