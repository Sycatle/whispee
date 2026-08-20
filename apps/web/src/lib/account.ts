/**
 * Résolution d'un compte en appareils, et vérification de ce que le serveur raconte.
 *
 * # Pourquoi ce module existe
 *
 * Dès qu'un compte regroupe plusieurs appareils, quelqu'un doit dire lesquels. Ce quelqu'un
 * est le serveur : c'est lui qui tient la liste, et lui qui la sert. Une liste qu'il compose
 * librement lui suffirait à s'inviter dans n'importe quelle conversation — le message resterait
 * chiffré de bout en bout, simplement l'un des bouts serait lui.
 *
 * Chaque appareil servi porte donc une attestation signée par le compte. Ce module la
 * revérifie, systématiquement, avant que le moindre appareil n'entre dans un groupe.
 *
 * # Ce que l'attestation n'empêche pas
 *
 * Le serveur peut encore **omettre** un appareil légitime de la liste. La victime constate
 * alors qu'un de ses appareils cesse de recevoir les nouvelles conversations : c'est de la
 * censure, bruyante et sans intérêt pour qui veut lire en silence. Le détecter demanderait un
 * journal auditable de type key transparency, hors périmètre.
 *
 * L'asymétrie est le gain : le serveur peut retrancher, jamais ajouter.
 *
 * # Ne pas se fier à la vérification du serveur
 *
 * Le serveur vérifie déjà les attestations à l'écriture, mais c'est précisément lui qu'on
 * soupçonne : sa vérification n'est qu'un filtre précoce, jamais une garantie. Toute la
 * protection tient à ce que ce fichier refasse le travail.
 */
import type { Api } from "./api";
import type { AttestedDevice, Crypto } from "./wasm";

export interface ResolvedAccount {
  handle: string;
  /** Clé publique du compte. C'est elle qu'on compare hors bande, via son empreinte. */
  identityKey: Uint8Array;
  /** Empreinte à afficher. Stable quand le compte gagne ou perd un appareil. */
  fingerprint: string;
  /** Appareils actifs dont l'attestation a été vérifiée ici même. */
  devices: AttestedDevice[];
  /**
   * Appareils dont la révocation a été vérifiée ici même.
   *
   * Servis par le serveur plutôt que tus, pour que l'omission reste distinguable de la
   * révocation. Leurs clés MLS alimentent la politique de groupe : c'est ce qui autorise un
   * membre non-admin à les évincer sans attendre le retour d'un admin.
   */
  revoked: AttestedDevice[];
  /**
   * Clés de signature MLS des appareils révoqués, prêtes pour `Client.process`.
   *
   * Un contexte vide n'est pas neutre : il fait refuser exactement le retrait d'un appareil
   * volé. C'est le piège d'implémentation le plus probable, d'où ce champ tout préparé plutôt
   * qu'un filtrage à refaire chez chaque appelant.
   */
  revokedKeys: Uint8Array[];
  /**
   * Appareils servis par le serveur mais rejetés.
   *
   * Non vide signifie que le serveur a servi quelque chose qu'il n'aurait pas dû pouvoir
   * produire. Ce n'est pas une erreur bénigne à absorber en silence : c'est le signal exact
   * qu'on cherchait à obtenir, et l'interface doit le montrer.
   */
  rejected: AttestedDevice[];
}

/**
 * Interroge le serveur et ne garde que ce qui vérifie.
 *
 * L'appelant reçoit une liste dont chaque élément a été prouvé rattaché au compte. Les
 * autres sont rendus séparément plutôt que jetés : les faire disparaître reviendrait à
 * masquer une tentative de substitution.
 */
export async function resolveAccount(
  api: Api,
  crypto: Crypto,
  handle: string,
): Promise<ResolvedAccount> {
  const { identityKey, devices } = await api.listAccountDevices(handle);

  const verified: AttestedDevice[] = [];
  const revoked: AttestedDevice[] = [];
  const rejected: AttestedDevice[] = [];

  for (const device of devices) {
    const attested = crypto.verifyAttestation(
      identityKey,
      handle,
      device.id,
      device.authKey,
      device.mlsKey,
      device.attestation,
    );

    if (!attested) {
      rejected.push(device);
      continue;
    }

    if (device.revokedAt === undefined || device.revocation === undefined) {
      verified.push(device);
      continue;
    }

    // Une révocation annoncée sans certificat valide n'est pas une révocation : c'est le
    // serveur qui tente d'écarter un appareil légitime. On la refuse et on garde l'appareil
    // actif — le traiter comme révoqué reviendrait à exécuter la censure qu'on cherche à
    // détecter.
    const certifie = crypto.verifyRevocation(
      identityKey,
      handle,
      device.id,
      BigInt(device.revokedAt),
      device.revocation,
    );

    if (certifie) {
      revoked.push(device);
    } else {
      rejected.push(device);
    }
  }

  return {
    handle,
    identityKey,
    fingerprint: crypto.accountFingerprint(identityKey),
    devices: verified,
    revoked,
    revokedKeys: revoked.map((device) => device.mlsKey),
    rejected,
  };
}
