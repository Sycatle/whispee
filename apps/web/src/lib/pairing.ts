/**
 * Appairage d'un nouvel appareil.
 *
 * # Le sens du QR, et pourquoi il n'est pas arbitraire
 *
 * Le **nouvel** appareil affiche, l'**ancien** scanne. Un QR est photographiable par
 * construction : y mettre un secret reviendrait à le publier. Celui-ci ne porte qu'une clé
 * publique éphémère et une adresse de dépôt, tous deux sans valeur pour qui les intercepte.
 *
 * L'ancien appareil scelle ensuite le paquet sous le secret X25519 partagé et le dépose sur le
 * serveur, qui n'en voit qu'un blob : il ne détient aucune des deux moitiés privées.
 *
 * # Ce qui n'est pas protégé
 *
 * La sécurité du canal est **physique** : elle tient à ce que l'utilisateur ne scanne que
 * l'écran qu'il a en main. Un attaquant qui lui présente son propre QR est appairé, et aucune
 * cryptographie ne peut l'en empêcher. C'est le modèle de WhatsApp et de Signal.
 */
import { Api } from "./api";
import { fromBase64, toBase64 } from "./keys";

/** Ce que le QR encode. Aucun de ces champs n'est secret. */
export interface PairingCode {
  id: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Encode l'offre en une chaîne compacte.
 *
 * Le QR n'est pas toujours praticable — écran non partagé, absence de caméra sur un
 * ordinateur de bureau. La même chaîne se copie alors à la main, avec exactement les mêmes
 * propriétés : elle ne contient rien de secret.
 */
export function encodePairingCode(code: PairingCode): string {
  const joined = new Uint8Array(code.id.length + code.publicKey.length);
  joined.set(code.id, 0);
  joined.set(code.publicKey, code.id.length);
  return toBase64(joined).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodePairingCode(text: string): PairingCode {
  const normalized = text.trim().replace(/-/g, "+").replace(/_/g, "/");
  const bytes = fromBase64(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));

  // 16 octets d'identifiant + 32 de clé X25519. Une longueur inattendue signale une saisie
  // tronquée, pas une attaque — mais échouer ici vaut mieux que de sceller dans le vide.
  if (bytes.length !== 48) {
    throw new Error("Code d'appairage invalide ou incomplet.");
  }

  return { id: bytes.slice(0, 16), publicKey: bytes.slice(16) };
}

export function depositPairing(api: Api, id: Uint8Array, payload: Uint8Array): Promise<unknown> {
  return api.depositPairing(id, payload);
}

/**
 * Attend que l'appareil d'origine dépose le paquet.
 *
 * Le serveur ne notifie pas : on interroge. La fenêtre est courte — le paquet contient de quoi
 * prendre le contrôle du compte, et le serveur le fait expirer au bout de cinq minutes.
 */
export async function awaitPairing(
  id: Uint8Array,
  signal: { cancelled: boolean },
): Promise<Uint8Array | null> {
  const deadline = Date.now() + 5 * 60 * 1000;

  while (!signal.cancelled && Date.now() < deadline) {
    const payload = await Api.claimPairing(id);
    if (payload) return payload;
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
  return null;
}
