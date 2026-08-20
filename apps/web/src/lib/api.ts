/**
 * Client du delivery service.
 *
 * Chaque requête est signée avec la clé Ed25519 de l'appareil. Le message signé couvre la
 * méthode, le chemin, l'horodatage et l'empreinte du corps : une signature capturée sur un
 * endpoint n'est donc rejouable ni sur un autre chemin, ni avec un corps modifié.
 */
import { type DeviceKeys, exportAuthPublicKey, fromBase64, sign, toBase64, toHex } from "./keys";
import type { AttestedDevice } from "./wasm";

/** Voir la note sur `buffer` dans `keys.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export const BASE_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8787";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function signingPayload(
  method: string,
  path: string,
  timestamp: number,
  body: Uint8Array,
): Promise<Uint8Array> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(body)));
  const prefix = new TextEncoder().encode(`${method}\n${path}\n${timestamp}\n`);

  const payload = new Uint8Array(prefix.length + digest.length);
  payload.set(prefix, 0);
  payload.set(digest, prefix.length);
  return payload;
}

export class Api {
  constructor(
    /**
     * Identifiant de cet appareil.
     *
     * Public : la trame `identify` de la gateway doit le nommer explicitement, le handshake
     * WebSocket ne portant aucun en-tête pour le dire avant.
     */
    readonly deviceId: string,
    private readonly keys: DeviceKeys,
  ) {}

  /**
   * Crée un compte pseudonyme. Non signé — aucune clé n'est encore connue du serveur.
   *
   * Trust on first use : rien ne prouve que le premier à réclamer un handle en est le
   * propriétaire légitime. Seule une key transparency répondrait à cela ; voir le README.
   */
  static async createAccount(handle: string, identityKey: Uint8Array): Promise<void> {
    const response = await fetch(`${BASE_URL}/v1/accounts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle, identity_key: toBase64(identityKey) }),
    });

    if (!response.ok) {
      throw new ApiError(
        response.status,
        response.status === 409
          ? "Ce pseudonyme est déjà pris par un autre compte."
          : await response.text(),
      );
    }
  }

  /**
   * Enregistre l'appareil et son rattachement attesté au compte.
   *
   * L'attestation est ce qui empêche quiconque — serveur compris — de déclarer un appareil
   * dans le compte d'autrui et de se faire inviter dans ses conversations.
   */
  static async register(
    deviceId: string,
    handle: string,
    keys: DeviceKeys,
    mlsKey: Uint8Array,
    attestation: Uint8Array,
  ): Promise<void> {
    const response = await fetch(`${BASE_URL}/v1/devices`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: deviceId,
        handle,
        auth_key: await exportAuthPublicKey(keys),
        mls_key: toBase64(mlsKey),
        attestation: toBase64(attestation),
      }),
    });

    if (!response.ok) {
      throw new ApiError(
        response.status,
        response.status === 409
          ? "Cet identifiant est déjà pris par un autre appareil."
          : await response.text(),
      );
    }
  }

  private async request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const encoded = body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(body));
    return this.requestRaw(method, path, encoded, "json");
  }

  /** Variante binaire, pour les corps qui ne sont pas du JSON. */
  private async requestRaw<T>(
    method: "GET" | "POST",
    path: string,
    encoded: Uint8Array,
    expect: "json" | "bytes",
  ): Promise<T> {
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await sign(this.keys, await signingPayload(method, path, timestamp, encoded));

    const response = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: {
        // Le serveur n'inspecte pas le corps : ce type est indicatif, et les pièces jointes
        // sont de toute façon des octets opaques.
        "content-type": "application/octet-stream",
        "x-device-id": this.deviceId,
        "x-timestamp": String(timestamp),
        "x-signature": signature,
      },
      body: method === "GET" ? undefined : buffer(encoded),
    });

    if (!response.ok) throw new ApiError(response.status, await response.text());

    if (expect === "bytes") {
      return new Uint8Array(await response.arrayBuffer()) as T;
    }
    return response.json() as Promise<T>;
  }

  /** Réapprovisionne le stock. Chaque KeyPackage est à usage unique. */
  publishKeyPackages(packages: Uint8Array[]): Promise<{ published: number }> {
    return this.request("POST", "/v1/key-packages", { packages: packages.map(toBase64) });
  }

  /** À surveiller : à zéro, plus personne ne peut ouvrir de conversation avec cet appareil. */
  keyPackageStock(): Promise<{ remaining: number }> {
    return this.request("GET", "/v1/key-packages/stock");
  }

  async claimKeyPackage(deviceId: string): Promise<{ package: Uint8Array; remaining: number }> {
    const body = await this.request<{ package: string; remaining: number }>(
      "POST",
      `/v1/key-packages/${encodeURIComponent(deviceId)}/claim`,
    );
    return { package: fromBase64(body.package), remaining: body.remaining };
  }

  /**
   * Appareils déclarés d'un compte, tels que le serveur les rapporte.
   *
   * **Le résultat n'est pas fiable en l'état.** C'est l'endroit exact par lequel un serveur
   * malveillant introduirait un appareil qu'il contrôle. Passer systématiquement par
   * `resolveAccount` dans `account.ts`, qui revérifie chaque attestation.
   */
  async listAccountDevices(handle: string): Promise<{
    identityKey: Uint8Array;
    devices: AttestedDevice[];
  }> {
    const body = await this.request<{
      identity_key: string;
      devices: {
        id: string;
        auth_key: string;
        mls_key: string;
        attestation: string;
        revoked_at?: number;
        revocation?: string;
        last_seen?: number;
      }[];
    }>("GET", `/v1/accounts/${encodeURIComponent(handle)}/devices`);

    return {
      identityKey: fromBase64(body.identity_key),
      devices: body.devices.map((device) => ({
        id: device.id,
        authKey: fromBase64(device.auth_key),
        mlsKey: fromBase64(device.mls_key),
        attestation: fromBase64(device.attestation),
        revokedAt: device.revoked_at,
        revocation: device.revocation ? fromBase64(device.revocation) : undefined,
        lastSeen: device.last_seen,
      })),
    };
  }

  /**
   * Révoque un appareil, certificat signé par le compte à l'appui.
   *
   * Le certificat n'est pas là pour le serveur — il connaît déjà la clé du compte et pourrait
   * s'en passer. Il est là pour les **autres membres des groupes**, qui doivent pouvoir
   * constater la révocation sans nous croire, et commiter le retrait MLS en conséquence.
   */
  revokeDevice(
    deviceId: string,
    revocation: Uint8Array,
    revokedAt: number,
  ): Promise<{ revoked: string }> {
    return this.request("POST", `/v1/devices/${encodeURIComponent(deviceId)}/revoke`, {
      revocation: toBase64(revocation),
      revoked_at: revokedAt,
    });
  }

  /**
   * Change la clé d'identité du compte.
   *
   * C'est la seule réponse réelle à un appareil volé : celui-ci détient la graine, donc le
   * compte entier. Le révoquer ne l'empêche pas d'en attester un nouveau ; changer la clé rend
   * en revanche invérifiables **toutes** les attestations existantes d'un seul coup.
   */
  rotateAccount(
    handle: string,
    newIdentityKey: Uint8Array,
    rotation: Uint8Array,
    rotatedAt: number,
  ): Promise<{ handle: string }> {
    return this.request("POST", `/v1/accounts/${encodeURIComponent(handle)}/rotate`, {
      new_identity_key: toBase64(newIdentityKey),
      rotation: toBase64(rotation),
      rotated_at: rotatedAt,
    });
  }

  /** Tête courante du journal, telle que le serveur la publie. */
  async logHead(): Promise<SignedHead> {
    return decodeHead(await this.request<RawHead>("GET", "/v1/log/sth"));
  }

  /** Preuve que la clé servie pour ce compte figure dans le journal. */
  async logProof(handle: string): Promise<{
    identityKey: Uint8Array;
    index: number;
    proof: Uint8Array[];
    head: SignedHead;
  }> {
    const body = await this.request<{
      identity_key: string;
      index: number;
      proof: string[];
      head: RawHead;
    }>("GET", `/v1/log/proof/${encodeURIComponent(handle)}`);

    return {
      identityKey: fromBase64(body.identity_key),
      index: body.index,
      proof: body.proof.map(fromBase64),
      head: decodeHead(body.head),
    };
  }

  /** Preuve que le journal courant prolonge celui de taille `from`. */
  async logConsistency(from: number): Promise<{ proof: Uint8Array[]; head: SignedHead }> {
    const body = await this.request<{ proof: string[]; head: RawHead }>(
      "GET",
      `/v1/log/consistency?from=${from}`,
    );

    return { proof: body.proof.map(fromBase64), head: decodeHead(body.head) };
  }

  /** Retire des appareils de la liste de diffusion d'un groupe. */
  removeGroupMembers(groupId: Uint8Array, deviceIds: string[]): Promise<{ removed: number }> {
    return this.request("POST", `/v1/groups/${toHex(groupId)}/members/remove`, {
      device_ids: deviceIds,
    });
  }

  /** Dépose un paquet d'appairage déjà scellé. Le serveur n'en voit qu'un blob. */
  depositPairing(id: Uint8Array, payload: Uint8Array): Promise<{ deposited: boolean }> {
    return this.request("POST", `/v1/pairings/${toHex(id)}`, { payload: toBase64(payload) });
  }

  /**
   * Relève le paquet d'appairage. **Non signé** : le nouvel appareil n'a pas encore d'identité
   * connue du serveur — c'est justement ce que l'appairage va lui donner.
   *
   * La sécurité ne tient donc pas à l'authentification mais au chiffrement : sans la clé
   * privée éphémère, le paquet est illisible. Retourne `null` tant qu'il n'y a rien.
   */
  static async claimPairing(id: Uint8Array): Promise<Uint8Array | null> {
    const response = await fetch(`${BASE_URL}/v1/pairings/${toHex(id)}`);
    if (response.status === 404) return null;
    if (!response.ok) throw new ApiError(response.status, await response.text());

    const body = (await response.json()) as { payload: string };
    return fromBase64(body.payload);
  }

  /** Dépose des messages chiffrés dans le coffre du compte. */
  storeVault(
    groupId: Uint8Array,
    entries: { seq: number; payload: Uint8Array }[],
  ): Promise<{ stored: number }> {
    return this.request("POST", `/v1/vault/${toHex(groupId)}`, {
      entries: entries.map((entry) => ({ seq: entry.seq, payload: toBase64(entry.payload) })),
    });
  }

  /** Relève le coffre du compte. Le serveur ne sert que celui de l'appareil signataire. */
  async fetchVault(
    groupId: Uint8Array,
    after: number,
  ): Promise<{ seq: number; payload: Uint8Array }[]> {
    const rows = await this.request<{ seq: number; payload: string }[]>(
      "GET",
      `/v1/vault/${toHex(groupId)}?after=${after}`,
    );
    return rows.map((row) => ({ seq: row.seq, payload: fromBase64(row.payload) }));
  }

  /**
   * Dernière activité des comptes demandés.
   *
   * `POST` et non `GET` : les handles restent hors de l'URL, donc hors des journaux d'accès de
   * tout proxy traversé. Même argument que celui qui a écarté `EventSource` pour le flux — et le
   * corps est de toute façon couvert par la signature.
   *
   * Le serveur renvoie sa propre horloge avec la réponse : la fraîcheur se juge en comparant
   * deux horodatages, et celui du navigateur peut être n'importe quoi.
   */
  presence(handles: string[]): Promise<{
    now: number;
    accounts: { handle: string; last_seen: number }[];
  }> {
    return this.request("POST", "/v1/presence", { handles });
  }

  /** Coupe ou rétablit la diffusion de sa présence. Réciproque : couper, c'est cesser de voir. */
  setPresenceOptout(optout: boolean): Promise<void> {
    return this.request("POST", "/v1/presence/optout", { optout });
  }

  /** Groupes où le serveur nous a déclaré membre — comment on découvre un Welcome. */
  listGroups(): Promise<string[]> {
    return this.request("GET", "/v1/groups");
  }

  /**
   * Déclare des membres auprès du serveur.
   *
   * `postingKey` n'est acceptée qu'à la **création** du groupe : le serveur l'ignore ensuite.
   * Permettre de la changer laisserait un membre rendre tous les autres muets, sans qu'aucune
   * erreur ne l'explique.
   */
  addMembers(
    groupId: Uint8Array,
    deviceIds: string[],
    postingKey?: Uint8Array,
  ): Promise<{ added: number }> {
    return this.request("POST", `/v1/groups/${toHex(groupId)}/members`, {
      device_ids: deviceIds,
      ...(postingKey ? { posting_key: toBase64(postingKey) } : {}),
    });
  }

  /**
   * Dépose une enveloppe.
   *
   * Avec une clé de dépôt, la requête n'est **pas signée** : elle porte un MAC qui prouve
   * l'appartenance au groupe sans dire lequel de ses membres écrit. Sans clé, on retombe sur
   * la signature d'appareil — et le serveur apprend qui parle à qui, quand.
   */
  postEnvelope(
    groupId: Uint8Array,
    payload: Uint8Array,
    posting?: { key: Uint8Array; mac: PostMac },
  ): Promise<{ seq: number }> {
    const path = `/v1/groups/${toHex(groupId)}/envelopes`;
    const body = { payload: toBase64(payload) };

    if (!posting) return this.request("POST", path, body);

    // Le corps est sérialisé **une seule fois** : le MAC couvre les octets exacts qui partent.
    // Re-sérialiser pour l'envoi produirait potentiellement d'autres octets, et le serveur
    // rejetterait tout.
    const encoded = new TextEncoder().encode(JSON.stringify(body));
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const mac = posting.mac(posting.key, groupId, nonce, encoded);

    return this.anonymous(path, encoded, nonce, mac);
  }

  /** Dépôt sans signature d'appareil : le serveur n'apprend pas qui écrit. */
  private async anonymous<T>(
    path: string,
    encoded: Uint8Array,
    nonce: Uint8Array,
    mac: Uint8Array,
  ): Promise<T> {
    const response = await fetch(`${BASE_URL}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        // Ni `x-device-id`, ni `x-signature`, ni horodatage : c'est tout l'objet. Les
        // envoyer « au cas où » annulerait le dispositif sans qu'aucun test ne le signale.
        "x-group-nonce": toBase64(nonce),
        "x-group-mac": toBase64(mac),
      },
      body: buffer(encoded),
    });

    if (!response.ok) throw new ApiError(response.status, await response.text());
    return response.json() as Promise<T>;
  }

  /**
   * Dépose une pièce jointe **déjà chiffrée**.
   *
   * Le corps part en binaire brut : encoder en base64 coûterait un tiers de bande passante
   * pour rien. La signature couvre l'empreinte du corps, donc le procédé reste identique.
   */
  async uploadAttachment(groupId: Uint8Array, ciphertext: Uint8Array): Promise<{ id: string }> {
    return this.requestRaw("POST", `/v1/groups/${toHex(groupId)}/attachments`, ciphertext, "json");
  }

  async downloadAttachment(groupId: Uint8Array, id: string): Promise<Uint8Array> {
    return this.requestRaw(
      "GET",
      `/v1/groups/${toHex(groupId)}/attachments/${encodeURIComponent(id)}`,
      new Uint8Array(),
      "bytes",
    );
  }

  /**
   * Signe le défi émis par le serveur à l'ouverture d'une session gateway.
   *
   * # Pourquoi un défi, là où le HTTP se contente d'un horodatage
   *
   * L'API `WebSocket` du navigateur n'accepte **aucun en-tête**, pas plus qu'`EventSource`. On
   * ne peut donc pas authentifier le handshake sans mettre la signature dans l'URL, où elle
   * atterrirait dans les journaux d'accès de tout intermédiaire. La socket s'ouvre donc sans
   * identité, et rien n'est servi avant cette signature.
   *
   * Le nonce venant du serveur et n'étant valable qu'une fois, il n'y a ici aucune fenêtre de
   * rejeu — contrairement aux soixante secondes que laisse l'authentification HTTP.
   *
   * Le message signé est construit par le module WebAssembly — son format canonique vit dans la
   * crate `attest`, et le réécrire en TypeScript le dupliquerait. Il est passé en paramètre
   * plutôt qu'importé, pour la même raison que [`PostMac`] : ce module ne doit pas dépendre du
   * chargement du WASM, qui est asynchrone et n'a pas lieu au même moment.
   */
  signGatewayChallenge(nonce: Uint8Array, format: GatewayChallenge): Promise<string> {
    return sign(this.keys, format(this.deviceId, nonce));
  }

  /** Dépose un signal éphémère. Le serveur le relaie et l'oublie : rien n'est stocké. */
  async postSignal(
    groupId: Uint8Array,
    payload: Uint8Array,
    posting: { key: Uint8Array; mac: PostMac },
  ): Promise<void> {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const mac = posting.mac(posting.key, groupId, nonce, payload);

    const response = await fetch(`${BASE_URL}/v1/groups/${toHex(groupId)}/signals`, {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        // Comme le dépôt d'enveloppe : aucune signature d'appareil. Le serveur constate
        // qu'un membre écrit, jamais lequel.
        "x-group-nonce": toBase64(nonce),
        "x-group-mac": toBase64(mac),
      },
      body: buffer(payload),
    });

    if (!response.ok) throw new ApiError(response.status, await response.text());
  }

  async fetchEnvelopes(
    groupId: Uint8Array,
    after: number,
  ): Promise<{ seq: number; payload: Uint8Array }[]> {
    const rows = await this.request<{ seq: number; payload: string }[]>(
      "GET",
      `/v1/groups/${toHex(groupId)}/envelopes?after=${after}`,
    );
    return rows.map((row) => ({ seq: row.seq, payload: fromBase64(row.payload) }));
  }
}

/** Tête de journal signée, décodée. */
export interface SignedHead {
  size: number;
  root: Uint8Array;
  timestamp: number;
  signature: Uint8Array;
  /**
   * Clé publique du journal.
   *
   * Servie par le serveur qu'elle est censée surveiller — pis-aller assumé et documenté. Le
   * client refuse au moins qu'elle change en cours de route.
   */
  logKey: Uint8Array;
}

interface RawHead {
  size: number;
  root: string;
  timestamp: number;
  signature: string;
  log_key: string;
}

function decodeHead(raw: RawHead): SignedHead {
  return {
    size: raw.size,
    root: fromBase64(raw.root),
    timestamp: raw.timestamp,
    signature: fromBase64(raw.signature),
    logKey: fromBase64(raw.log_key),
  };
}

/**
 * Calcul du MAC de dépôt, fourni par le module WebAssembly.
 *
 * Passé en paramètre plutôt qu'importé : `api.ts` ne doit pas dépendre du chargement du
 * module WASM, qui est asynchrone et n'a pas lieu au même moment.
 */
export type PostMac = (
  key: Uint8Array,
  groupId: Uint8Array,
  nonce: Uint8Array,
  body: Uint8Array,
) => Uint8Array;

/**
 * Construction du message signé à l'ouverture d'une session gateway.
 *
 * Fourni par le module WebAssembly, pour la même raison que [`PostMac`] : le format canonique
 * vit dans la crate `attest` et ne doit exister qu'en un seul exemplaire.
 */
export type GatewayChallenge = (deviceId: string, nonce: Uint8Array) => Uint8Array;
