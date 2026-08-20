/**
 * Vérification du journal auditable des clés, côté client.
 *
 * # Le trou que ce module ferme
 *
 * Les attestations empêchent le serveur d'**ajouter** un appareil à un compte. Elles ne
 * l'empêchent pas de mentir sur la clé du compte **au premier contact** : quand on demande le
 * compte de quelqu'un pour la première fois, on n'a rien à quoi comparer. Le serveur peut
 * servir sa propre clé et relayer en clair entre deux sessions parfaitement chiffrées.
 *
 * Une preuve d'inclusion dans un arbre de Merkle append-only ne se fabrique pas. Le serveur
 * doit publier la clé qu'il sert, et il ne peut plus la retirer ensuite.
 *
 * # Les trois contrôles, et pourquoi il en faut trois
 *
 * 1. **Signature de la tête** — elle vient bien du journal.
 * 2. **Inclusion** — la clé qu'on me sert est celle du journal, pas une autre.
 * 3. **Cohérence** — le journal d'aujourd'hui prolonge celui que j'ai vu hier.
 *
 * Sans le troisième, le serveur remplace une clé déjà publiée et sert un journal tout aussi
 * cohérent : les deux premiers passent, et le journal ne prouve plus rien sur le passé.
 *
 * # Ce qu'aucun des trois n'attrape
 *
 * Un serveur qui tient **deux journaux** et en sert un à chacun. Chaque victime voit un journal
 * signé, cohérent, où sa propre vue est parfaite. Seule la comparaison des têtes entre clients
 * — le gossip, dans les messages chiffrés que le serveur ne peut ni lire ni falsifier — révèle
 * la bifurcation. Voir `Session.gossip`.
 */
import type { Api, SignedHead } from "./api";
import type { Crypto } from "./wasm";

/** Dernière tête acceptée, conservée d'une session à l'autre. */
export interface SeenHead {
  size: number;
  root: Uint8Array;
  logKey: Uint8Array;
}

export type Verdict =
  | { ok: true }
  /**
   * Le serveur a échoué à prouver ce qu'il affirme. Ce n'est pas une erreur réseau à
   * réessayer : c'est le signal que le dispositif existe pour produire.
   */
  | { ok: false; reason: string };

/**
 * Vérifie la signature d'une tête servie par le serveur.
 *
 * La clé publique du journal est elle-même servie par le serveur — pis-aller assumé, voir le
 * commentaire de `SignedHead` côté serveur. On refuse au moins qu'elle **change** en cours de
 * route : un journal qui se met à signer avec une autre clé est un autre journal.
 */
export function acceptHead(
  crypto: Crypto,
  head: SignedHead,
  seen: SeenHead | undefined,
): Verdict {
  if (seen && !equal(seen.logKey, head.logKey)) {
    return { ok: false, reason: "la clé du journal a changé : ce n'est plus le même journal." };
  }

  const valide = crypto.verifyTreeHead(
    head.logKey,
    BigInt(head.size),
    head.root,
    BigInt(head.timestamp),
    head.signature,
  );

  if (!valide) return { ok: false, reason: "tête de journal mal signée." };

  // Un journal ne rétrécit pas. Une tête plus petite que la dernière vue est soit un rejeu,
  // soit une amputation — les deux méritent le même refus.
  if (seen && head.size < seen.size) {
    return { ok: false, reason: "le journal a rétréci : des entrées ont disparu." };
  }

  return { ok: true };
}

/**
 * Vérifie qu'une clé de compte figure dans le journal, et que celui-ci prolonge ce qu'on
 * connaissait.
 *
 * Retourne la nouvelle tête à mémoriser en cas de succès. En cas d'échec, **rien n'est
 * mémorisé** : accepter une tête qu'on vient de refuser reviendrait à l'entériner.
 */
export async function verifyAccount(
  api: Api,
  crypto: Crypto,
  handle: string,
  identityKey: Uint8Array,
  seen: SeenHead | undefined,
): Promise<{ verdict: Verdict; head?: SeenHead }> {
  const proof = await api.logProof(handle);

  const tete = acceptHead(crypto, proof.head, seen);
  if (!tete.ok) return { verdict: tete };

  // La feuille est **recalculée** à partir du handle et de la clé qu'on nous sert. Utiliser
  // celle du serveur reviendrait à lui faire prouver ses dires avec ses dires.
  const leaf = crypto.logLeaf(handle, identityKey);

  if (
    !crypto.verifyInclusion(leaf, proof.index, proof.head.size, proof.proof, proof.head.root)
  ) {
    return {
      verdict: {
        ok: false,
        reason: `la clé servie pour @${handle} ne figure pas dans le journal.`,
      },
    };
  }

  if (!equal(identityKey, proof.identityKey)) {
    return {
      verdict: {
        ok: false,
        reason: `le journal publie une autre clé pour @${handle} que celle qui nous est servie.`,
      },
    };
  }

  if (seen) {
    const coherence = await verifyExtends(api, crypto, seen, proof.head);
    if (!coherence.ok) return { verdict: coherence };
  }

  return {
    verdict: { ok: true },
    head: { size: proof.head.size, root: proof.head.root, logKey: proof.head.logKey },
  };
}

/**
 * Vérifie que le journal courant prolonge une tête donnée.
 *
 * Sert deux usages qui n'en font qu'un : notre propre tête précédente, et **celle qu'un
 * correspondant nous a transmise**. Dans le second cas, c'est ce qui détecte un serveur qui
 * tiendrait deux journaux — il ne peut pas prouver que le nôtre prolonge une vue qu'il n'a
 * jamais servie.
 */
export async function verifyExtends(
  api: Api,
  crypto: Crypto,
  ancre: SeenHead,
  courante: SignedHead,
): Promise<Verdict> {
  if (ancre.size > courante.size) {
    return { ok: false, reason: "le journal est plus court que la vue de référence." };
  }

  const { proof } = await api.logConsistency(ancre.size);

  if (
    !crypto.verifyConsistency(ancre.size, ancre.root, courante.size, courante.root, proof)
  ) {
    return {
      ok: false,
      reason: "le journal ne prolonge pas la vue de référence : des clés ont été réécrites.",
    };
  }

  return { ok: true };
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
