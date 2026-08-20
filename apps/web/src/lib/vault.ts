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
import * as content from "./content.ts";
import type { Message } from "./session";

/**
 * Ce que le coffre attend du transport, et rien de plus.
 *
 * Déclaré ici plutôt qu'importé depuis `api.ts` pour que le découpage et la pagination
 * ci-dessous soient testables sans réseau : c'est exactement le genre de logique qui échoue en
 * silence si personne ne la vérifie.
 */
export interface VaultApi {
  storeVault(
    groupId: Uint8Array,
    entries: { seq: number; payload: Uint8Array }[],
  ): Promise<{ stored: number }>;
  fetchVault(groupId: Uint8Array, after: number): Promise<{ seq: number; payload: Uint8Array }[]>;
}

/**
 * Taille d'un lot, en dépôt comme en relève.
 *
 * **Doit rester égale à `MAX_VAULT_ENTRIES` côté serveur** (`crates/server/src/routes.rs`), qui
 * borne les deux : un dépôt plus gros est refusé par un 400, une relève plus longue est tronquée
 * — sans erreur, ce qui est le pire des deux. Tant que le coffre était optionnel, les deux cas
 * restaient rares ; ils deviennent le cas nominal du premier démarrage.
 */
const PAGE = 200;

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

/**
 * Dépose des messages dans le coffre. Idempotent côté serveur.
 *
 * Découpé en lots : un appareil qui rattrape un retard peut avoir bien plus de `PAGE` messages
 * à archiver d'un coup, et le serveur refuse le lot entier au-delà. En série et non en
 * parallèle — l'archivage est du travail de fond, rien ne justifie d'ouvrir dix requêtes
 * concurrentes pour lui.
 */
export async function store(
  api: VaultApi,
  key: CryptoKey,
  groupId: Uint8Array,
  messages: Message[],
): Promise<void> {
  for (let debut = 0; debut < messages.length; debut += PAGE) {
    const lot = messages.slice(debut, debut + PAGE);

    const entries = await Promise.all(
      lot.map(async (message) => ({
        seq: message.seq,
        payload: await encryptEntry(key, message),
      })),
    );

    await api.storeVault(groupId, entries);
  }
}

/** Ce qu'une restauration rapporte, y compris ce qu'elle n'a pas su lire. */
export interface Restored {
  messages: Message[];
  /**
   * Entrées qu'on n'a pas su déchiffrer.
   *
   * Remonté plutôt que compté en silence : si **toutes** les entrées d'une conversation sont
   * illisibles, ce n'est pas un vieux format, c'est une rotation de compte — la clé du coffre
   * dérive de la phrase de récupération, et la tourner rend le passé archivé définitivement
   * inaccessible. Un fil vide sans explication serait le pire des deux comportements.
   */
  illisibles: number;
}

/**
 * Restaure l'historique d'une conversation.
 *
 * Une entrée illisible est ignorée plutôt que fatale : elle peut venir d'une version antérieure
 * du format, et perdre tout l'historique parce qu'un message sur mille ne se relit pas serait
 * une réaction disproportionnée.
 */
export async function restore(
  api: VaultApi,
  key: CryptoKey,
  groupId: Uint8Array,
): Promise<Restored> {
  const messages: Message[] = [];
  let illisibles = 0;
  let after = 0;

  // Le serveur sert au plus `PAGE` lignes par appel, triées par `seq` croissant. Une seule
  // requête tronquait donc l'historique **sans erreur** au-delà de deux cents messages : le fil
  // paraissait simplement plus court, et rien ne le signalait.
  for (;;) {
    const rows = await api.fetchVault(groupId, after);
    if (rows.length === 0) break;

    for (const row of rows) {
      try {
        messages.push(await decryptEntry(key, row.seq, row.payload));
      } catch (error) {
        illisibles += 1;
        console.warn(`entrée de coffre ${row.seq} illisible`, error);
      }
    }

    if (rows.length < PAGE) break;
    after = rows[rows.length - 1].seq;
  }

  return { messages, illisibles };
}

/**
 * Fusionne un historique restauré dans un fil déjà peuplé, sans doublon.
 *
 * Extrait de `Session` pour être testable : la fusion est une règle métier — le `seq` identifie
 * un message —, pas un détail d'affichage, et `session.ts` n'est pas testable en l'état (WASM,
 * IndexedDB).
 */
export function merge(existants: Message[], archives: Message[]): Message[] {
  const connus = new Set(existants.map((message) => message.seq));
  return archives.filter((message) => !connus.has(message.seq));
}
