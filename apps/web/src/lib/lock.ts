/**
 * Verrou local : chiffrement au repos de l'état, sous un mot de passe.
 *
 * # L'indirection, et pourquoi elle n'est pas un raffinement
 *
 * ```
 * mot de passe --Argon2id--> clé de déverrouillage --chiffre--> clé maîtresse --chiffre--> état
 * ```
 *
 * La clé maîtresse est aléatoire et ne dépend pas du mot de passe. Changer celui-ci ne
 * re-chiffre donc que 32 octets, jamais l'état complet — qui pèse plusieurs kilooctets et
 * grandit avec le nombre de conversations. Sans cette indirection, un changement de mot de
 * passe imposerait de déchiffrer puis re-chiffrer tout l'état : une opération longue, faite
 * au pire moment (l'utilisateur soupçonne une compromission), et qui laisse l'état en clair
 * en mémoire pendant toute sa durée.
 *
 * # Ce qui change par rapport à la clé non-extractable
 *
 * Jusqu'ici l'état était chiffré par une `CryptoKey` non-extractable rangée dans IndexedDB.
 * Cela protège contre l'exfiltration par script — la clé ne peut pas être lue — mais **pas
 * contre quiconque obtient la session du navigateur** : il lui suffit d'appeler l'API de
 * déchiffrement. Avec le verrou, la clé maîtresse n'existe qu'en mémoire, après saisie.
 */
import { fromBase64, toBase64 } from "./keys";
import { loadCrypto } from "./wasm";

/** Voir la note sur `buffer` dans `keys.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

const SALT_LEN = 16;
const IV_LEN = 12;

/** Ce qui est stocké en clair à côté de l'état. Rien ici n'est secret. */
export interface LockEnvelope {
  /** Sel Argon2id. Public : son rôle est d'interdire les tables précalculées. */
  salt: string;
  /** Clé maîtresse chiffrée sous la clé de déverrouillage : `iv ‖ ciphertext`. */
  wrapped: string;
}

/** Crée un verrou neuf : clé maîtresse aléatoire, scellée sous le mot de passe. */
export async function createLock(password: string): Promise<[LockEnvelope, CryptoKey]> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const master = crypto.getRandomValues(new Uint8Array(32));

  const envelope = { salt: toBase64(salt), wrapped: await seal(password, salt, master) };
  return [envelope, await importMaster(master)];
}

/**
 * Ouvre le verrou. Rejette si le mot de passe est faux.
 *
 * L'échec vient de l'AEAD : sans la bonne clé, le déchiffrement de la clé maîtresse ne
 * produit pas des octets faux, il échoue. Il n'y a donc rien à comparer et pas de risque de
 * comparaison non constante — c'est la propriété qui permet de se passer d'un « hash du mot
 * de passe » stocké à côté, lequel serait une cible d'attaque hors ligne supplémentaire.
 */
export async function openLock(envelope: LockEnvelope, password: string): Promise<CryptoKey> {
  const salt = fromBase64(envelope.salt);
  const blob = fromBase64(envelope.wrapped);

  const unlock = await unlockKey(password, salt);
  const master = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(blob.slice(0, IV_LEN)) },
      unlock,
      buffer(blob.slice(IV_LEN)),
    ),
  );

  return importMaster(master);
}

/**
 * Change le mot de passe sans toucher à l'état chiffré.
 *
 * Exige l'ancien : sans lui on ne peut pas retrouver la clé maîtresse, et la remplacer par une
 * neuve rendrait tout l'état illisible. Quelqu'un qui trouve un appareil déverrouillé ne peut
 * donc pas en changer le mot de passe pour s'en approprier le contenu.
 */
export async function changePassword(
  envelope: LockEnvelope,
  ancien: string,
  nouveau: string,
): Promise<LockEnvelope> {
  const master = await openLock(envelope, ancien);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", master));

  // Sel neuf : réutiliser l'ancien laisserait un attaquant qui a capturé les deux versions
  // attaquer les deux mots de passe avec le même travail de dérivation.
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  return { salt: toBase64(salt), wrapped: await seal(nouveau, salt, raw) };
}

async function seal(password: string, salt: Uint8Array, master: Uint8Array): Promise<string> {
  const unlock = await unlockKey(password, salt);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(iv) }, unlock, buffer(master)),
  );

  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  return toBase64(out);
}

/**
 * Dérive la clé de déverrouillage. **Bloque environ une seconde.**
 *
 * Argon2id vient du module WebAssembly : WebCrypto n'offre que PBKDF2, qui ne coûte que du
 * calcul et se parallélise sur GPU pour presque rien. Le coût mémoire d'Argon2id est ce qui
 * rend une attaque hors ligne réellement chère.
 */
async function unlockKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const crypt = await loadCrypto();
  const derived = crypt.deriveUnlockKey(password, salt);

  // Non-extractable : une fois importée, cette clé ne peut plus quitter le navigateur.
  return crypto.subtle.importKey("raw", buffer(derived), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * La clé maîtresse est importée **extractable**, parce qu'un changement de mot de passe doit
 * pouvoir la re-sceller. C'est le seul secret du système dans ce cas, et il ne quitte jamais
 * la mémoire : il n'est ni persisté en clair, ni transmis.
 */
function importMaster(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buffer(raw), "AES-GCM", true, ["encrypt", "decrypt"]);
}
