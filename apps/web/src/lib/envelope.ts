/**
 * Enveloppe applicative transportée dans les blobs opaques du serveur.
 *
 * Le serveur ne parle pas MLS : il route des octets. Mais un flux de conversation mêle deux
 * choses qui se traitent différemment — les messages MLS ordinaires, et le Welcome qui
 * permet à un nouvel arrivant de rejoindre. Un octet de type les distingue.
 *
 * Le Welcome circule ainsi en clair du point de vue du serveur, et c'est sans conséquence :
 * ses secrets sont chiffrés pour la clé d'initialisation du KeyPackage de l'invité, et
 * l'arbre de ratchet est public par construction.
 */

const TYPE_MLS = 0;
const TYPE_WELCOME = 1;

export type Parsed =
  | { kind: "mls"; payload: Uint8Array }
  | { kind: "welcome"; welcome: Uint8Array; ratchetTree: Uint8Array };

export function encodeMls(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + payload.length);
  out[0] = TYPE_MLS;
  out.set(payload, 1);
  return out;
}

export function encodeWelcome(welcome: Uint8Array, ratchetTree: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + 4 + welcome.length + ratchetTree.length);
  out[0] = TYPE_WELCOME;
  new DataView(out.buffer).setUint32(1, welcome.length, false);
  out.set(welcome, 5);
  out.set(ratchetTree, 5 + welcome.length);
  return out;
}

/**
 * Ces octets viennent du réseau : toute longueur incohérente doit produire une erreur, et
 * jamais une lecture hors limites ou un tableau silencieusement tronqué.
 */
export function decode(blob: Uint8Array): Parsed {
  if (blob.length < 1) throw new Error("enveloppe vide");

  switch (blob[0]) {
    case TYPE_MLS:
      return { kind: "mls", payload: blob.subarray(1) };

    case TYPE_WELCOME: {
      if (blob.length < 5) throw new Error("enveloppe welcome tronquée");
      const welcomeLength = new DataView(blob.buffer, blob.byteOffset).getUint32(1, false);
      if (5 + welcomeLength > blob.length) throw new Error("longueur de welcome incohérente");
      return {
        kind: "welcome",
        welcome: blob.subarray(5, 5 + welcomeLength),
        ratchetTree: blob.subarray(5 + welcomeLength),
      };
    }

    default:
      throw new Error(`type d'enveloppe inconnu : ${blob[0]}`);
  }
}
