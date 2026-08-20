/**
 * Pièces jointes chiffrées.
 *
 * Le fichier est chiffré côté client avec une **clé aléatoire propre à ce fichier**, puis
 * déposé sur le serveur. La clé ne quitte jamais le client par ce chemin : elle voyage à
 * l'intérieur du message MLS, donc chiffrée de bout en bout comme le texte.
 *
 * Conséquence : le serveur détient l'intégralité du fichier et ne peut rien en faire. Il
 * n'en connaît ni le contenu, ni le nom, ni le type.
 *
 * # Pourquoi une clé par fichier
 *
 * Réutiliser une clé entre fichiers ferait qu'un seul descripteur divulgué ouvrirait tous
 * les autres. Une clé par fichier borne les dégâts d'une fuite à ce fichier, et permet en
 * outre de partager une pièce jointe précise sans donner accès au reste.
 *
 * # Ce qui fuit malgré tout
 *
 * La **taille** du fichier, à seize octets près. Elle suffit souvent à identifier un
 * document connu. Seul du padding la masquerait, au prix de la bande passante.
 */
import type { Api } from "./api";

/** Descripteur transporté dans le message MLS. C'est lui qui porte le secret. */
export interface AttachmentRef {
  id: string;
  /** Clé AES-256-GCM, en base64. Ne doit jamais atteindre le serveur autrement que chiffrée. */
  key: string;
  iv: string;
  /** Nom d'origine. C'est du contenu : il ne doit pas être confié au serveur. */
  name: string;
  /** Type déclaré par l'expéditeur. À traiter comme une suggestion, jamais comme une preuve. */
  mime: string;
  /** Taille en clair, pour l'affichage avant téléchargement. */
  size: number;
}

/** Doit rester sous le plafond du serveur (`MAX_ATTACHMENT_BYTES`). */
export const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Voir la note sur `buffer` dans `keys.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

/**
 * Chiffre puis dépose un fichier. Retourne le descripteur à joindre au message.
 *
 * La clé est marquée extractable — il faut bien l'exporter pour la transmettre au
 * destinataire. C'est l'exception justifiée au principe suivi partout ailleurs : une clé de
 * fichier *doit* voyager, contrairement aux clés d'identité et d'enveloppe.
 */
export async function encryptAndUpload(
  api: Api,
  groupId: Uint8Array,
  file: File,
): Promise<AttachmentRef> {
  if (file.size > MAX_ATTACHMENT_BYTES) {
    throw new Error(
      `Fichier trop volumineux (${Math.round(file.size / 1024 / 1024)} Mo, maximum ${
        MAX_ATTACHMENT_BYTES / 1024 / 1024
      } Mo).`,
    );
  }

  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new Uint8Array(await file.arrayBuffer());

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer(plaintext)),
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));

  const { id } = await api.uploadAttachment(groupId, ciphertext);

  return {
    id,
    key: toBase64(raw),
    iv: toBase64(iv),
    name: file.name,
    mime: file.type || "application/octet-stream",
    size: file.size,
  };
}

/**
 * Récupère et déchiffre une pièce jointe.
 *
 * L'AEAD porte l'intégrité : si le serveur substitue ou altère le blob, le déchiffrement
 * échoue au lieu de rendre des octets falsifiés. Aucune empreinte séparée n'est donc
 * nécessaire — le tag GCM fait ce travail.
 *
 * Le `Blob` est construit avec le type **déclaré par l'expéditeur**, qui n'est qu'une
 * indication. L'appelant ne doit jamais le rendre inline sur cette origine : un SVG ou un
 * HTML ainsi affiché exécuterait du script avec les clés de l'utilisateur à portée.
 */
export async function downloadAndDecrypt(
  api: Api,
  groupId: Uint8Array,
  ref: AttachmentRef,
): Promise<Blob> {
  const ciphertext = await api.downloadAttachment(groupId, ref.id);

  const key = await crypto.subtle.importKey(
    "raw",
    buffer(fromBase64(ref.key)),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buffer(fromBase64(ref.iv)) },
    key,
    buffer(ciphertext),
  );

  return new Blob([plaintext], { type: ref.mime });
}
