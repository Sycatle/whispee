/**
 * Présence : de « vu à telle heure » à « en ligne ».
 *
 * # Pourquoi la décision est ici et non côté serveur
 *
 * Le serveur renvoie un horodatage brut, jamais un booléen. Un booléen figerait la politique
 * dans le protocole et interdirait d'afficher « vu à 14:02 » à partir de la même donnée — alors
 * que c'est exactement la même donnée, lue avec un seuil différent.
 *
 * # Pourquoi l'heure du serveur voyage avec la réponse
 *
 * Parce qu'on compare deux horloges. `MAX_CLOCK_SKEW` existe côté serveur précisément parce
 * qu'elles divergent : comparer un horodatage serveur à l'heure locale ferait clignoter le point
 * chez tout utilisateur mal réglé, sans qu'il puisse comprendre pourquoi.
 */

/**
 * Au-delà, un compte est considéré hors ligne.
 *
 * L'arithmétique, parce que c'est typiquement la valeur qu'on « optimise » plus tard à soixante
 * secondes en s'étonnant que le point clignote :
 *
 *  * le serveur ne réécrit qu'une fois par minute (`PRESENCE_REFRESH`) ;
 *  * le client ne relève la présence qu'à chaque tour de relève, soit trente secondes ;
 *  * il faut une marge pour un battement manqué ou une reconnexion de flux, dont le délai de
 *    reprise monte jusqu'à trente secondes.
 *
 * Soit deux minutes et demie. Descendre en dessous ne rend pas la présence plus juste, seulement
 * plus nerveuse.
 */
export const ONLINE_WINDOW_MS = 150_000;

/** Dernière activité connue d'un compte, en millisecondes. */
export type LastSeen = number | undefined;

/**
 * En ligne ?
 *
 * Un horodatage dans le futur compte comme « en ligne » : il vient d'un décalage d'horloge, et
 * la seule autre réponse possible — « vu dans trois minutes » — serait absurde.
 */
export function isOnline(lastSeen: LastSeen, serverNow: number): boolean {
  if (lastSeen === undefined) return false;
  return serverNow - lastSeen < ONLINE_WINDOW_MS;
}

/**
 * Ce qui s'affiche à côté d'un nom.
 *
 * Une chaîne vide quand on ne sait pas — et non « hors ligne ». Un compte dont on n'a jamais eu
 * de nouvelles n'est pas un compte absent : c'est un compte sur lequel le serveur n'a rien à
 * dire, parce qu'il n'a jamais été vu ou parce que son propriétaire a refusé de le diffuser.
 * Trancher à sa place serait le premier mensonge de l'écran.
 */
export function describePresence(lastSeen: LastSeen, serverNow: number): string {
  if (lastSeen === undefined) return "";
  if (isOnline(lastSeen, serverNow)) return "en ligne";

  const date = new Date(lastSeen);
  const heures = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");

  const memeJour = new Date().toDateString() === date.toDateString();
  return memeJour ? `vu à ${heures}:${minutes}` : `vu le ${date.toLocaleDateString()}`;
}
