/**
 * Accusés de livraison et de lecture.
 *
 * # Cumulatifs, jamais unitaires
 *
 * Un accusé dit « jusqu'à ce numéro », pas « ce message-ci ». Ouvrir une conversation en
 * retard de deux cents messages coûte donc une enveloppe et non deux cents — dans une table
 * qui n'est jamais purgée, la différence n'est pas une optimisation, c'est la viabilité.
 *
 * # La boucle qu'il faut couper
 *
 * Un accusé est lui-même une enveloppe. Sans garde, chacun accuse réception de l'accusé de
 * l'autre et la conversation ne s'arrête plus. La coupure est dans `content.isControl()`, en
 * un seul endroit, appliqué à l'émission comme à la réception.
 *
 * # Deux appareils, un seul compte
 *
 * Chaque appareil d'un compte reçoit chaque message et voudrait accuser réception. Comme tous
 * les membres reçoivent aussi tous les accusés, l'état de son propre compte est connu
 * localement : il suffit de n'émettre que si l'on dépasse ce que le compte a déjà accusé. La
 * déduplication ne demande aucune coordination.
 *
 * # Réciprocité
 *
 * Désactiver ses accusés de lecture désactive aussi leur affichage. Sans cette symétrie, on
 * pourrait voir sans être vu, ce qui est précisément ce que le réglage prétend empêcher.
 * Le `delivered` n'est pas concerné : il constate qu'un appareil a relevé sa boîte, pas
 * qu'une personne a lu.
 */

/** Ce qu'un compte a accusé, dans une conversation. */
export interface AccountReceipts {
  delivered: number;
  read: number;
}

export type ReceiptBook = Map<string, AccountReceipts>;

/**
 * Enregistre un accusé reçu. Un curseur ne recule jamais.
 *
 * Le serveur ordonne les enveloppes mais ne garantit pas l'ordre dans lequel un client les
 * traite après une reconnexion. Prendre le maximum plutôt que la dernière valeur évite qu'un
 * accusé ancien, rejoué ou relu, fasse régresser l'affichage.
 */
export function record(
  book: ReceiptBook,
  handle: string,
  state: "delivered" | "read",
  seq: number,
): void {
  const courant = book.get(handle) ?? { delivered: 0, read: 0 };

  if (state === "read") {
    // Lire implique avoir reçu. Sans cette ligne, un client qui n'émet que `read` (accusés de
    // livraison arrivés hors d'ordre) afficherait « lu » sans jamais afficher « reçu ».
    courant.read = Math.max(courant.read, seq);
    courant.delivered = Math.max(courant.delivered, seq);
  } else {
    courant.delivered = Math.max(courant.delivered, seq);
  }

  book.set(handle, courant);
}

/**
 * Faut-il émettre un accusé, et pour quel numéro ?
 *
 * Retourne `undefined` quand il n'y a rien à annoncer — c'est le cas courant, et c'est ce qui
 * empêche chaque tour de relève de produire une enveloppe.
 */
export function pending(
  book: ReceiptBook,
  handle: string,
  state: "delivered" | "read",
  cursor: number,
): number | undefined {
  const connu = book.get(handle) ?? { delivered: 0, read: 0 };
  const acquis = state === "read" ? connu.read : connu.delivered;
  return cursor > acquis ? cursor : undefined;
}

/**
 * État à afficher sur un message qu'on a envoyé soi-même.
 *
 * `readReceipts` est le réglage local : quand il est désactivé, on n'émet pas et on n'affiche
 * pas. Le paramètre est passé plutôt que lu d'un module de réglages pour que la réciprocité
 * soit visible dans la signature — un défaut de couplage rendrait l'asymétrie possible.
 */
export function statusOf(
  book: ReceiptBook,
  peers: string[],
  seq: number,
  readReceipts: boolean,
): "sent" | "delivered" | "read" {
  if (peers.length === 0) return "sent";

  const etats = peers.map((handle) => book.get(handle) ?? { delivered: 0, read: 0 });

  if (readReceipts && etats.every((etat) => etat.read >= seq)) return "read";
  if (etats.every((etat) => etat.delivered >= seq)) return "delivered";
  return "sent";
}
