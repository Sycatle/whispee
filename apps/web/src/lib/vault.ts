/**
 * Coffre d'historique. **Optionnel, et désactivé par défaut.**
 *
 * # Ce qu'on abandonne en l'activant
 *
 * MLS détruit ses clés au fil des messages : quiconque met la main sur le transport après coup
 * ne peut rien en tirer — y compris l'utilisateur lui-même sur un appareil neuf. C'est la
 * forward secrecy, et c'est une protection réelle, pas un effet de bord gênant.
 *
 * Le coffre y renonce **pour l'historique** : les entrées sont chiffrées sous une clé dérivée
 * de la phrase de récupération, donc stable dans le temps. Si cette phrase fuit un jour, tout
 * le passé sauvegardé fuit avec elle, rétroactivement.
 *
 * C'est le prix d'un historique qui survit à la perte de tous les appareils. Il se paie une
 * fois, en connaissance de cause — d'où l'activation explicite, et l'écran qui l'énonce au
 * lieu de l'enfouir dans un menu.
 *
 * # Ce que le serveur apprend malgré tout
 *
 * Combien de messages chaque compte archive, et quand. Il savait déjà qui parle à qui ; ceci
 * ajoute un volume et une chronologie. L'éviter demanderait du padding et des dépôts factices.
 */
import type { Api } from "./api";
import * as content from "./content";
import type { Message } from "./session";

/** Voir la note sur `buffer` dans `keys.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

const IV_LEN = 12;

/** Importe la clé de coffre dérivée de la phrase. Non-extractable une fois dans le navigateur. */
export function importVaultKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buffer(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

/**
 * Forme archivée d'un message.
 *
 * L'expéditeur est conservé : sans lui, un historique restauré ne dirait plus qui a dit quoi,
 * ce qui le rend à peu près inutile. C'est une donnée de plus sous la clé stable du coffre —
 * mais elle est déjà connue du serveur via l'appartenance au groupe.
 */
interface Archived {
  sender: string | null;
  mine: boolean;
  body: number[];
}

export async function encryptEntry(key: CryptoKey, message: Message): Promise<Uint8Array> {
  const body = content.encode(message.content);

  const archived: Archived = { sender: message.sender, mine: message.mine, body: [...body] };
  const plaintext = new TextEncoder().encode(JSON.stringify(archived));

  // Nonce aléatoire par entrée. AES-GCM casse catastrophiquement si un nonce est réutilisé
  // sous la même clé — et cette clé, elle, ne change jamais.
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(iv) }, key, buffer(plaintext)),
  );

  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  return out;
}

export async function decryptEntry(
  key: CryptoKey,
  seq: number,
  blob: Uint8Array,
): Promise<Message> {
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(blob.slice(0, IV_LEN)) },
      key,
      buffer(blob.slice(IV_LEN)),
    ),
  );

  const archived = JSON.parse(new TextDecoder().decode(plaintext)) as Archived;
  return {
    seq,
    sender: archived.sender,
    mine: archived.mine,
    content: content.decode(new Uint8Array(archived.body)),
  };
}

/** Dépose des messages dans le coffre. Idempotent côté serveur. */
export async function store(
  api: Api,
  key: CryptoKey,
  groupId: Uint8Array,
  messages: Message[],
): Promise<void> {
  if (messages.length === 0) return;

  const entries = await Promise.all(
    messages.map(async (message) => ({
      seq: message.seq,
      payload: await encryptEntry(key, message),
    })),
  );

  await api.storeVault(groupId, entries);
}

/**
 * Restaure l'historique d'une conversation.
 *
 * Une entrée illisible est ignorée plutôt que fatale : elle peut venir d'une version antérieure
 * du format, et perdre tout l'historique parce qu'un message sur mille ne se relit pas serait
 * une réaction disproportionnée.
 */
export async function restore(
  api: Api,
  key: CryptoKey,
  groupId: Uint8Array,
): Promise<Message[]> {
  const rows = await api.fetchVault(groupId, 0);
  const messages: Message[] = [];

  for (const row of rows) {
    try {
      messages.push(await decryptEntry(key, row.seq, row.payload));
    } catch (error) {
      console.warn(`entrée de coffre ${row.seq} illisible`, error);
    }
  }
  return messages;
}
