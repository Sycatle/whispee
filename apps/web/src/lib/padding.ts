/**
 * Rembourrage des messages, pour que leur taille cesse de renseigner le serveur.
 *
 * # Ce que la taille révèle
 *
 * Le contenu est chiffré, mais sa **longueur** ne l'est pas : elle traverse MLS presque
 * inchangée, et le serveur la lit sur chaque enveloppe. Cela suffit à distinguer « oui » de
 * « je te rappelle dans dix minutes », à repérer un mot de passe collé, à reconnaître un
 * message type. Sur une conversation suivie dans la durée, la suite des longueurs est une
 * signature.
 *
 * # Le compromis, qui est réel
 *
 * Rembourrer coûte de la bande passante : c'est un octet transmis pour rien à chaque octet
 * ajouté. Des paliers trop fins ne cachent rien, trop larges gaspillent. Les paliers retenus
 * commencent à 256 octets — au-dessus de l'écrasante majorité des messages écrits, qui
 * deviennent donc **tous de la même taille** — puis doublent.
 *
 * Le doublement borne le gaspillage à moins de 100 % et donne une échelle logarithmique : le
 * serveur n'apprend plus que l'ordre de grandeur, jamais la taille.
 *
 * # Ce que cela ne cache pas
 *
 * Qui écrit, à qui, et quand. Le rythme d'une conversation reste entièrement lisible, et il
 * en dit souvent plus que les longueurs. Le masquer demanderait du trafic factice — un coût
 * permanent, y compris quand personne ne parle.
 *
 * Les pièces jointes ne passent pas par ici : elles transitent par un autre chemin et leur
 * taille est de toute façon dominée par le fichier.
 */

/** Premier palier. Choisi au-dessus de la quasi-totalité des messages écrits. */
const FIRST_BUCKET = 256;

/**
 * Marqueur de fin de contenu, puis des zéros — ISO/IEC 7816-4.
 *
 * Un simple remplissage par des zéros serait ambigu : un contenu se terminant légitimement par
 * un zéro deviendrait indistinguable de son rembourrage. Le marqueur lève l'ambiguïté sans
 * coûter plus d'un octet.
 */
const MARKER = 0x80;

/** Palier atteignant au moins `length`. */
function bucket(length: number): number {
  let size = FIRST_BUCKET;
  while (size < length) size *= 2;
  return size;
}

/**
 * Rembourre jusqu'au palier supérieur.
 *
 * Le marqueur est **toujours** ajouté, même quand la longueur tombe pile sur un palier : sans
 * cela, le retrait ne saurait pas si le dernier octet appartient au contenu.
 */
export function pad(body: Uint8Array): Uint8Array {
  const size = bucket(body.length + 1);
  const out = new Uint8Array(size);
  out.set(body);
  out[body.length] = MARKER;
  return out;
}

/**
 * Retire le rembourrage.
 *
 * Lève sur un rembourrage mal formé plutôt que de deviner : ces octets ont été authentifiés
 * par MLS, donc ils viennent bien d'un membre — mais un membre peut envoyer n'importe quoi,
 * par erreur comme volontairement, et une lecture approximative ici deviendrait une différence
 * d'interprétation entre clients.
 */
export function unpad(padded: Uint8Array): Uint8Array {
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0x00) end -= 1;

  if (end < 0 || padded[end] !== MARKER) {
    throw new Error("rembourrage mal formé");
  }

  return padded.subarray(0, end);
}
