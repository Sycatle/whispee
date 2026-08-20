/**
 * Format du contenu transporté *à l'intérieur* d'un message MLS.
 *
 * Le plaintext MLS n'est qu'une suite d'octets : c'est à l'application de dire s'il s'agit
 * de texte ou du descripteur d'une pièce jointe. Un octet de type suffit, et laisse la place
 * à d'autres formes plus tard.
 *
 * Tout ce qui passe par ici est chiffré de bout en bout — y compris le nom du fichier, son
 * type et sa clé. C'est délibéré : ce sont des informations sur le contenu, et le serveur
 * n'a aucune raison de les connaître.
 */
import type { AttachmentRef } from "./attachments";

const TYPE_TEXT = 0;
const TYPE_ATTACHMENT = 1;
const TYPE_GOSSIP = 2;
const TYPE_POSTING_KEY = 3;
const TYPE_RECEIPT = 4;
const TYPE_REACTION = 5;
const TYPE_REPLY = 6;

export type Content =
  | { kind: "text"; text: string }
  | { kind: "attachment"; ref: AttachmentRef }
  | { kind: "gossip"; head: GossipHead }
  | { kind: "posting-key"; key: Uint8Array }
  | { kind: "receipt"; state: ReceiptState; seq: number }
  | { kind: "reaction"; target: number; emoji: string }
  | { kind: "reply"; target: number; text: string };

/**
 * Ce qu'un accusé constate.
 *
 * `delivered` est mécanique : l'appareil a relevé l'enveloppe. `read` engage une personne —
 * le message a été affiché. C'est cette différence qui justifie que seul le second soit
 * désactivable.
 */
export type ReceiptState = "delivered" | "read";

const RECEIPT_DELIVERED = 0;
const RECEIPT_READ = 1;

/**
 * Tête de journal transmise à un correspondant, **dans un message chiffré**.
 *
 * # Pourquoi ce canal et pas un autre
 *
 * Un journal auditable a une faiblesse que ni la signature ni les preuves ne couvrent : le
 * serveur peut en tenir **deux** et en servir un à chacun. Chaque victime voit un journal
 * signé, cohérent, où sa propre vue est parfaite.
 *
 * La détecter demande de comparer les vues de deux personnes par un canal que le serveur ne
 * contrôle pas. Ce canal existe déjà : la conversation elle-même. Le serveur transporte ces
 * octets sans pouvoir les lire ni les modifier — c'est exactement ce qu'il faut.
 *
 * Le destinataire demande alors au serveur de prouver que **son** journal prolonge la vue
 * reçue. Si le serveur a servi deux journaux, il ne le peut pas.
 */
export interface GossipHead {
  size: number;
  root: Uint8Array;
}

export function encodeText(text: string): Uint8Array {
  const body = new TextEncoder().encode(text);
  const out = new Uint8Array(1 + body.length);
  out[0] = TYPE_TEXT;
  out.set(body, 1);
  return out;
}

/**
 * Encode une tête de journal. Format fixe : `u32 taille ‖ 32 octets de racine`.
 *
 * Ni signature ni horodatage : le destinataire ne vérifie pas cette tête pour elle-même, il
 * s'en sert comme **ancre** et demande au serveur de prouver que son propre journal la
 * prolonge. Transporter la signature laisserait croire qu'elle sert à quelque chose ici.
 */
export function encodeGossip(head: GossipHead): Uint8Array {
  const out = new Uint8Array(1 + 4 + 32);
  out[0] = TYPE_GOSSIP;
  new DataView(out.buffer).setUint32(1, head.size, false);
  out.set(head.root.subarray(0, 32), 5);
  return out;
}

/**
 * Encode n'importe quel contenu. Un point d'entrée unique, pour que l'ajout d'un type oblige
 * à traiter le cas partout — la version précédente écrivait « si texte, sinon pièce jointe »
 * en deux endroits, ce qui aurait envoyé du gossip encodé comme une pièce jointe.
 */
/**
 * Ce contenu est-il du **trafic de protocole** plutôt qu'un message ?
 *
 * Le gossip et la clé de dépôt circulent dans le même canal chiffré que les messages, parce
 * que c'est précisément ce qu'on veut : un canal que le serveur transporte sans pouvoir le
 * lire. Mais ce ne sont pas des messages — les afficher noie la conversation sous des bulles
 * vides, et les archiver remplit le coffre de choses que personne ne relira jamais.
 *
 * La distinction est ici, dans un seul endroit, pour qu'un nouveau type de contrôle n'oblige
 * pas à se souvenir de le filtrer à l'envoi **et** à la réception.
 */
export function isControl(body: Content): boolean {
  return body.kind === "gossip" || body.kind === "posting-key" || body.kind === "receipt";
}

export function encode(body: Content): Uint8Array {
  switch (body.kind) {
    case "text":
      return encodeText(body.text);
    case "attachment":
      return encodeAttachment(body.ref);
    case "gossip":
      return encodeGossip(body.head);
    case "posting-key":
      return encodePostingKey(body.key);
    case "receipt":
      return encodeReceipt(body.state, body.seq);
    case "reaction":
      return encodeTargeted(TYPE_REACTION, body.target, body.emoji);
    case "reply":
      return encodeTargeted(TYPE_REPLY, body.target, body.text);
  }
}

/**
 * Encode un accusé. Format fixe : `u8 état ‖ u64 BE seq`.
 *
 * # Cumulatif, et c'est tout le dimensionnement
 *
 * L'accusé porte « jusqu'à ce numéro », pas « ce message-ci ». Une session de lecture coûte
 * donc une enveloppe et non une par bulle — sans quoi ouvrir une conversation en retard de
 * deux cents messages en produirait deux cents, dans une table qui n'est jamais purgée.
 */
export function encodeReceipt(state: ReceiptState, seq: number): Uint8Array {
  const out = new Uint8Array(1 + 1 + 8);
  out[0] = TYPE_RECEIPT;
  out[1] = state === "read" ? RECEIPT_READ : RECEIPT_DELIVERED;
  new DataView(out.buffer).setBigUint64(2, BigInt(seq), false);
  return out;
}

/**
 * Encode les deux formes qui désignent un message antérieur : `u64 BE cible ‖ UTF-8`.
 *
 * Réaction et réponse partagent leur structure et ne diffèrent que par leur octet de type.
 * Les écrire deux fois inviterait à ce que l'une gagne une correction que l'autre n'aurait
 * pas.
 */
function encodeTargeted(type: number, target: number, text: string): Uint8Array {
  const body = new TextEncoder().encode(text);
  const out = new Uint8Array(1 + 8 + body.length);
  out[0] = type;
  new DataView(out.buffer).setBigUint64(1, BigInt(target), false);
  out.set(body, 9);
  return out;
}

/**
 * Transmet la clé de dépôt du groupe aux autres membres.
 *
 * # Pourquoi elle passe par le contenu chiffré
 *
 * Cette clé permet de déposer dans le groupe sans s'identifier auprès du serveur. La faire
 * transiter par le serveur reviendrait à lui demander de distribuer le moyen de ne pas lui
 * parler — il pourrait la donner à qui il veut, ou la retenir. Elle passe donc par MLS, comme
 * n'importe quel autre secret du groupe.
 *
 * Le serveur la détient malgré tout : il doit vérifier les MAC. Ce qu'il ne peut pas, c'est
 * décider qui d'autre l'obtient.
 */
export function encodePostingKey(key: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + 32);
  out[0] = TYPE_POSTING_KEY;
  out.set(key.subarray(0, 32), 1);
  return out;
}

export function encodeAttachment(ref: AttachmentRef): Uint8Array {
  const body = new TextEncoder().encode(JSON.stringify(ref));
  const out = new Uint8Array(1 + body.length);
  out[0] = TYPE_ATTACHMENT;
  out.set(body, 1);
  return out;
}

/**
 * Ces octets ont été authentifiés par MLS : ils viennent bien d'un membre du groupe. Cela
 * ne les rend pas pour autant bien formés — un membre peut envoyer n'importe quoi, par
 * erreur ou volontairement. La lecture doit donc échouer proprement.
 *
 * Compatibilité ascendante : un message d'une version ultérieure, portant un type inconnu,
 * ne doit pas casser la conversation.
 */
export function decode(bytes: Uint8Array): Content {
  if (bytes.length < 1) throw new Error("contenu vide");

  const body = bytes.subarray(1);

  switch (bytes[0]) {
    case TYPE_TEXT:
      return { kind: "text", text: new TextDecoder().decode(body) };

    case TYPE_GOSSIP: {
      if (body.length !== 4 + 32) throw new Error("tête de journal mal dimensionnée");
      return {
        kind: "gossip",
        head: {
          size: new DataView(body.buffer, body.byteOffset).getUint32(0, false),
          root: body.slice(4, 36),
        },
      };
    }

    case TYPE_POSTING_KEY: {
      if (body.length !== 32) throw new Error("clé de dépôt mal dimensionnée");
      return { kind: "posting-key", key: body.slice(0, 32) };
    }

    case TYPE_RECEIPT: {
      if (body.length !== 1 + 8) throw new Error("accusé mal dimensionné");
      const vue = new DataView(body.buffer, body.byteOffset);
      return {
        kind: "receipt",
        state: body[0] === RECEIPT_READ ? "read" : "delivered",
        // `Number` plutôt que `bigint` : les numéros de séquence restent très en deçà de
        // 2^53, et un bigint contaminerait toute l'arithmétique de curseur en aval.
        seq: Number(vue.getBigUint64(1, false)),
      };
    }

    case TYPE_REACTION:
    case TYPE_REPLY: {
      if (body.length < 8) throw new Error("référence de message manquante");
      const target = Number(new DataView(body.buffer, body.byteOffset).getBigUint64(0, false));
      const texte = new TextDecoder().decode(body.subarray(8));
      return bytes[0] === TYPE_REACTION
        ? { kind: "reaction", target, emoji: texte }
        : { kind: "reply", target, text: texte };
    }

    case TYPE_ATTACHMENT: {
      const ref = JSON.parse(new TextDecoder().decode(body)) as AttachmentRef;
      for (const champ of ["id", "key", "iv", "name", "mime"] as const) {
        if (typeof ref[champ] !== "string") {
          throw new Error(`descripteur de pièce jointe invalide : ${champ} manquant`);
        }
      }
      if (typeof ref.size !== "number") {
        throw new Error("descripteur de pièce jointe invalide : size manquant");
      }
      return { kind: "attachment", ref };
    }

    default:
      throw new Error(`type de contenu inconnu : ${bytes[0]}`);
  }
}
