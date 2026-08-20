/**
 * Canal éphémère : les signaux qui n'ont de valeur que maintenant.
 *
 * # Pourquoi un second canal
 *
 * Tout le reste passe par le ratchet applicatif MLS, qui est conçu pour ne rien perdre :
 * chaque message consomme une génération, et un trou trop large casse le déchiffrement de la
 * suite. C'est exactement ce qu'il faut pour des messages — et exactement ce qu'il ne faut pas
 * pour un indicateur de frappe.
 *
 * La conséquence n'est pas théorique. La table `envelopes` n'est jamais purgée, et **ne peut
 * pas l'être** sans trouer le ratchet. Faire transiter la frappe par ce chemin conserverait
 * indéfiniment la trace de qui a commencé à répondre puis s'est ravisé.
 *
 * Ici, rien n'est stocké : le serveur relaie et oublie.
 *
 * # Ce que ce canal ne garantit pas
 *
 * **Pas de forward secrecy à l'intérieur d'une epoch.** La clé vient du secret d'export du
 * groupe : tous les signaux d'une même epoch tombent ensemble si elle fuit. Acceptable pour une
 * donnée qui expire en trois secondes ; inacceptable pour un message, d'où la séparation.
 *
 * **Pas d'authentification de l'émetteur.** La clé est celle du groupe, donc tout membre peut
 * produire un signal qui paraît venir d'un autre. Sans conséquence à deux — il n'y a qu'un
 * autre. Dans un groupe, cela signifie qu'un membre peut faire croire qu'un tiers écrit.
 *
 * Ce qu'il garantit en revanche est réel : la clé change à chaque commit, donc un membre
 * retiré perd ce canal au même instant que le reste.
 *
 * # Comment un indicateur s'éteint
 *
 * Jamais par un signal de fin — il pourrait se perdre, et l'indicateur resterait allumé pour
 * toujours. Deux chemins, tous deux locaux :
 *
 *  * **l'arrivée d'un message de l'auteur** (`without`), qui est la preuve la plus sûre qu'il a
 *    fini d'écrire, et qui ne coûte rien puisqu'on ne l'attend pas ;
 *  * **l'expiration** (`fresh`), en dernier recours. Elle demande un minuteur côté affichage :
 *    calculer qu'une entrée est périmée ne sert à rien si personne ne redessine. Voir
 *    `nextExpiry`.
 */

/** Ce qu'un signal transporte. Un seul cas, et le format le dit explicitement. */
const TYPE_TYPING = 0;

/**
 * Durée pendant laquelle un indicateur reçu reste affiché.
 *
 * Aucun signal « a cessé d'écrire » n'est émis : l'expiration s'en charge, et un signal de fin
 * pourrait se perdre — laissant l'indicateur allumé indéfiniment.
 *
 * Trois secondes, et non six : c'est le délai au bout duquel quelqu'un qui a réellement cessé
 * d'écrire cesse d'être annoncé. Le porter plus haut rend l'indicateur menteur plus longtemps,
 * ce qui est le seul défaut qu'il puisse avoir.
 *
 * **L'expiration doit être rendue, pas seulement calculée.** `fresh()` ne s'évalue qu'au rendu ;
 * sans minuteur qui force ce rendu au moment voulu, la valeur ci-dessous ne décrit rien. Voir
 * `Messages.tsx`.
 */
export const TYPING_TTL_MS = 3000;

/**
 * Intervalle minimal entre deux émissions pendant qu'on tape.
 *
 * Plus court, on paie un dépôt réseau par frappe de touche pour une information que le
 * destinataire a déjà. Plus long que la moitié du TTL, l'indicateur clignote — d'où la moitié
 * exacte de `TYPING_TTL_MS`.
 *
 * C'est aussi le pire cas d'inertie : la dernière frappe avant l'arrêt peut être avalée par ce
 * seuil, donc le dernier signal émis peut dater d'une seconde et demie avant l'arrêt réel.
 */
export const TYPING_DEBOUNCE_MS = 1500;

export interface Typing {
  handle: string;
  /** Horodatage local de réception, pour l'expiration. */
  at: number;
}

/**
 * Scelle un indicateur de frappe sous la clé d'epoch.
 *
 * Le handle voyage **à l'intérieur** du chiffré. Il n'est pas authentifié — voir l'en-tête du
 * module — mais il n'est pas non plus visible du serveur, ce qui est le point qui compte : le
 * serveur constate un dépôt vers un groupe, pas qui l'a fait.
 */
export async function sealTyping(key: Uint8Array, handle: string): Promise<Uint8Array> {
  const body = new TextEncoder().encode(handle);
  const plaintext = new Uint8Array(1 + body.length);
  plaintext[0] = TYPE_TYPING;
  plaintext.set(body, 1);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey("raw", bytes(key), "AES-GCM", false, ["encrypt"]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, material, bytes(plaintext)),
  );

  const out = new Uint8Array(iv.length + sealed.length);
  out.set(iv, 0);
  out.set(sealed, iv.length);
  return out;
}

/**
 * Ouvre un signal reçu. Retourne `undefined` plutôt que de lever.
 *
 * Un signal illisible est le cas **normal**, pas une anomalie : le serveur relaie sans filtrer
 * par epoch, donc un signal émis juste avant un commit arrive après, sous une clé qui n'est
 * plus la bonne. Lever ici ferait remonter une erreur à chaque changement de composition du
 * groupe.
 */
export async function openTyping(
  key: Uint8Array,
  payload: Uint8Array,
): Promise<string | undefined> {
  if (payload.length < 12 + 16) return undefined;

  try {
    const iv = bytes(payload.subarray(0, 12));
    const material = await crypto.subtle.importKey("raw", bytes(key), "AES-GCM", false, ["decrypt"]);
    const clair = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, material, bytes(payload.subarray(12))),
    );

    if (clair.length < 1 || clair[0] !== TYPE_TYPING) return undefined;
    return new TextDecoder().decode(clair.subarray(1));
  } catch {
    return undefined;
  }
}

/** Ne garde que les indicateurs non expirés. */
export function fresh(typing: Typing[], now: number): Typing[] {
  return typing.filter((entry) => now - entry.at < TYPING_TTL_MS);
}

/**
 * Délai avant que le prochain indicateur n'expire, ou `undefined` s'il n'y en a aucun.
 *
 * L'expiration est paresseuse : `fresh()` ne s'évalue qu'au rendu, et un rendu n'a lieu que sur
 * un événement extérieur. Or quand quelqu'un cesse d'écrire, il ne se produit justement plus
 * rien — l'indicateur restait donc peint à l'écran jusqu'au prochain événement quelconque, soit
 * la relève périodique, soit trente secondes. C'est cette fonction qui donne à l'affichage de
 * quoi se réveiller tout seul.
 *
 * Jamais négatif : une entrée déjà expirée demande un rendu immédiat, pas un `setTimeout` au
 * passé.
 */
export function nextExpiry(typing: Typing[], now: number): number | undefined {
  if (typing.length === 0) return undefined;

  const plusAncien = Math.min(...typing.map((entry) => entry.at));
  return Math.max(0, plusAncien + TYPING_TTL_MS - now);
}

/**
 * Retire les indicateurs d'un correspondant.
 *
 * Appelé quand un message de sa part arrive : l'envoi est la preuve la plus sûre qu'il a fini
 * d'écrire, et elle ne coûte aucun signal supplémentaire. Sans cela, l'auteur d'un message
 * paraît continuer d'écrire pendant tout le TTL après l'avoir envoyé.
 *
 * Le risque du signal « a cessé d'écrire » ne s'applique pas ici : rien n'est émis, donc rien ne
 * peut se perdre. Au pire on n'éteint pas, et l'expiration reprend la main.
 */
export function without(typing: Typing[], handle: string): Typing[] {
  return typing.filter((entry) => entry.handle !== handle);
}

/**
 * `Uint8Array` peut être une vue sur un buffer plus grand ; `crypto.subtle` prend le buffer
 * entier. Sans cette copie, on chiffrerait des octets voisins.
 */
function bytes(view: Uint8Array): ArrayBuffer {
  return view.slice().buffer as ArrayBuffer;
}
