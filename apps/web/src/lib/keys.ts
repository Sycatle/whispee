/**
 * Clés détenues par le navigateur.
 *
 * Deux clés distinctes, avec deux rôles distincts :
 *
 * * **auth** (Ed25519) — signe les requêtes HTTP vers le delivery service ;
 * * **wrap** (AES-GCM) — chiffre l'état MLS avant qu'il touche IndexedDB.
 *
 * Les deux sont créées **non extractables** : `crypto.subtle` refusera de jamais en
 * exporter le matériel, y compris à notre propre code.
 *
 * # Ce que « non extractable » protège, et ce que ça ne protège pas
 *
 * Cela empêche l'exfiltration du matériel de clé. Cela n'empêche **pas** un script hostile
 * s'exécutant sur cette origine d'utiliser la clé — signer, déchiffrer — tant que la page
 * est ouverte. La distinction compte : un vol de clé est permanent, un usage abusif cesse
 * avec la session.
 *
 * Et surtout : le serveur livre ce JavaScript. Un serveur compromis peut livrer une version
 * qui utilise ces clés contre l'utilisateur. C'est la limite structurelle du web, qu'aucune
 * API navigateur ne corrige.
 */

const AUTH_ALGORITHM = "Ed25519";

/**
 * TypeScript 5.7+ distingue `Uint8Array<ArrayBuffer>` de `Uint8Array<SharedArrayBuffer>`,
 * et WebCrypto n'accepte que le premier. Aucun de nos tableaux ne provient d'un
 * `SharedArrayBuffer` — ni le WASM, ni `getRandomValues`, ni le décodage réseau — mais
 * `subarray` et `slice` perdent cette information de type.
 *
 * Un cast unique et nommé vaut mieux que de propager le générique dans toutes les
 * signatures : si l'hypothèse devient fausse un jour, il n'y a qu'un endroit à revoir.
 */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export interface DeviceKeys {
  auth: CryptoKeyPair;
  wrap: CryptoKey;
}

/**
 * Ed25519 dans WebCrypto est disponible sur Chrome 137+, Firefox 129+ et Safari 17+.
 * En cas d'absence, on préfère échouer visiblement plutôt que retomber sur une
 * implémentation JavaScript où la clé privée resterait exposée en mémoire du script.
 */
export async function supportsEd25519(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey(AUTH_ALGORITHM, false, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
}

export async function generateDeviceKeys(): Promise<DeviceKeys> {
  const auth = (await crypto.subtle.generateKey(AUTH_ALGORITHM, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const wrap = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);

  return { auth, wrap };
}

/**
 * La clé publique d'authentification — la seule moitié qui quitte l'appareil.
 *
 * En octets, parce que l'attestation la couvre telle quelle : la signer sous sa forme base64
 * ferait dépendre la vérification de l'encodage, et deux encodages valides du même octet
 * (padding, variante URL-safe) produiraient alors deux messages signés différents.
 */
export async function exportAuthPublicKeyBytes(keys: DeviceKeys): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", keys.auth.publicKey));
}

/** Même clé, en base64, pour les corps JSON. */
export async function exportAuthPublicKey(keys: DeviceKeys): Promise<string> {
  return toBase64(await exportAuthPublicKeyBytes(keys));
}

export async function sign(keys: DeviceKeys, payload: Uint8Array): Promise<string> {
  const signature = await crypto.subtle.sign(
    AUTH_ALGORITHM,
    keys.auth.privateKey,
    buffer(payload),
  );
  return toBase64(new Uint8Array(signature));
}

/**
 * Chiffre l'état MLS avant persistance, sous la clé fournie.
 *
 * La clé est un paramètre et non un champ de `DeviceKeys` : selon que le verrou local est
 * actif ou non, ce sera la clé maîtresse dérivée du mot de passe (qui n'existe qu'en mémoire)
 * ou la clé non-extractable rangée dans IndexedDB.
 *
 * Un nonce aléatoire de 96 bits par chiffrement. AES-GCM casse catastrophiquement si un
 * nonce est réutilisé sous la même clé ; 96 bits aléatoires rendent la collision
 * négligeable au rythme où un client sauvegarde son état.
 */
export async function wrapState(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer(plaintext));

  const out = new Uint8Array(iv.length + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), iv.length);
  return out;
}

export async function unwrapState(key: CryptoKey, blob: Uint8Array): Promise<Uint8Array> {
  if (blob.length <= 12) throw new Error("état chiffré tronqué");

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buffer(blob.subarray(0, 12)) },
    key,
    buffer(blob.subarray(12)),
  );
  return new Uint8Array(plaintext);
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Réciproque de `toHex`, pour les identifiants de groupe qui reviennent du flux temps réel.
 *
 * Une entrée de longueur impaire ou non hexadécimale produirait des octets silencieusement
 * faux — d'où le rejet explicite plutôt qu'un `NaN` qui se propagerait jusqu'à une requête.
 */
export function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error("chaîne hexadécimale de longueur impaire");

  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    const octet = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(octet)) throw new Error("chaîne hexadécimale invalide");
    bytes[i] = octet;
  }
  return bytes;
}
