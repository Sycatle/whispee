/**
 * Déverrouillage par empreinte ou visage.
 *
 * # Ce que cela échange, et qui doit le savoir
 *
 * Un mot de passe n'est stocké nulle part : il n'existe que dans la tête de son propriétaire, et
 * c'est ce qui rend l'état illisible pour qui emporte le disque. Activer la biométrie **écrit la
 * clé maîtresse sur l'appareil**, scellée par les secrets du processus natif — lesquels sont, eux,
 * en clair dans le répertoire privé de l'application.
 *
 * La protection devient donc celle du système : le répertoire privé, plus l'invite du système
 * devant la clé. C'est solide contre qui prend le téléphone en main ; sans valeur contre qui en
 * extrait le stockage — un `root`, une sauvegarde non chiffrée, une image disque.
 *
 * C'est **strictement plus faible** que le mot de passe seul. Ce n'est pas une raison de s'en
 * priver : un verrou qu'on retire parce qu'il est pénible protège moins qu'un verrou tiède qu'on
 * garde. Mais c'est une raison de le dire avant, et non dans une note de bas de page.
 *
 * # Où l'invite est déclenchée
 *
 * Dans le processus natif, sur le chemin de la clé — pas ici. Une invite posée en JavaScript
 * avant l'appel serait une politesse qu'un script hostile saute ; celle-ci, il ne peut que la
 * subir. Ce module ne fait donc qu'appeler des commandes, et n'a aucune logique de sécurité :
 * c'est voulu, et c'est ce qu'il faut vérifier en le lisant.
 */
import { invoke } from "@tauri-apps/api/core";

import { fromBase64, toBase64 } from "./keys";
import { isTauri } from "./platform";

/**
 * L'appareil peut-il proposer ce déverrouillage ?
 *
 * Deux conditions, tenues côté natif : la plateforme expose l'invite, et l'utilisateur a enrôlé
 * une empreinte ou un visage. Un téléphone dont personne n'a configuré la biométrie répond non —
 * proposer le réglage y donnerait un bouton qui échoue à l'usage.
 */
export async function biometrieDisponible(): Promise<boolean> {
  if (!isTauri()) return false;

  return invoke<boolean>("biometrie_disponible");
}

/** Le déverrouillage biométrique est-il activé ? Ne déclenche aucune invite. */
export async function biometrieActive(): Promise<boolean> {
  if (!isTauri()) return false;

  return invoke<boolean>("master_present");
}

/** Range la clé maîtresse pour que l'invite puisse la rendre. */
export async function activerBiometrie(master: Uint8Array): Promise<void> {
  await invoke("master_seal", { master: toBase64(master) });
}

/**
 * Demande la clé maîtresse, derrière l'invite du système.
 *
 * `null` si aucune clé n'est rangée. Une invite refusée **lève** : l'échec doit se distinguer de
 * l'absence, sans quoi un refus renverrait l'utilisateur vers la saisie du mot de passe comme si
 * la biométrie n'avait jamais été activée.
 */
export async function ouvrirParBiometrie(): Promise<Uint8Array | null> {
  const master = await invoke<string | null>("master_open");
  return master === null ? null : fromBase64(master);
}

/**
 * Retire le déverrouillage biométrique. Le verrou reste posé ; le mot de passe l'ouvre encore.
 *
 * Sans effet hors Tauri, plutôt qu'en erreur : le retrait est appelé par le retrait du verrou,
 * qui existe sur toutes les plateformes, et faire échouer là où il n'y a rien à retirer
 * transformerait une opération réussie en incident.
 */
export async function retirerBiometrie(): Promise<void> {
  if (!isTauri()) return;

  await invoke("master_clear");
}
