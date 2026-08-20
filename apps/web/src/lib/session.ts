/**
 * Orchestration : module WASM, delivery service et stockage local.
 *
 * C'est ici que vivent les décisions qui ne sont ni de la crypto ni du transport, et que le
 * protocole ne tranche pas : quand réapprovisionner les KeyPackages, comment un invité
 * découvre le groupe qui l'attend, quand persister l'état.
 */
import { type ResolvedAccount, resolveAccount } from "./account";
import { Api, ApiError, type PostMac } from "./api";
import { deviceNameCandidates, detectDeviceKind } from "./device";
import { type PairingCode, awaitPairing, decodePairingCode, encodePairingCode } from "./pairing";
import { type AttachmentRef, downloadAndDecrypt, encryptAndUpload } from "./attachments";
import * as content from "./content";
import * as envelope from "./envelope";
import { fromBase64, toBase64, toHex } from "./keys";
import { type LockEnvelope, changePassword, createLock, exporterMaster, openLock } from "./lock";
import * as biometrics from "./biometrics";
import type { SignalSettings } from "./storage";
import { type Decision, type Etapes, type Presence, decider, migrer } from "./migration";
import {
  type Ancrage,
  ancrageCourant,
  ancrageNatif,
  ancrageNeuf,
  ancrageWebExistant,
  effacerTout,
} from "./persistence";
import { isTauri } from "./platform";
import { type ReceiptBook, pending, record, statusOf } from "./receipts";
import {
  type Typing,
  TYPING_DEBOUNCE_MS,
  fresh,
  openTyping,
  sealTyping,
  without,
} from "./signals";
import { LockedCipher, type DeviceCipher } from "./cipher";
import { Gateway } from "./gateway";
import * as vault from "./vault";
import * as log from "./transparency";
import * as padding from "./padding";
import {
  type AccountKey,
  type AttestedDevice,
  type Client,
  type CreatedAccount,
  type Crypto,
  type Incoming,
  type Invitation,
  type Peer,
  type Sealed,
  loadCrypto,
} from "./wasm";

/** Nombre de KeyPackages maintenus en stock sur le serveur. */
const KEY_PACKAGE_TARGET = 10;
/** Seuil de réapprovisionnement. À zéro, plus personne ne peut nous joindre. */
const KEY_PACKAGE_LOW_WATER = 3;

export interface Message {
  seq: number;
  sender: string | null;
  mine: boolean;
  /**
   * Le contenu déchiffré ne vit qu'en mémoire. Il n'est jamais persisté : l'écrire sur le
   * disque annulerait une partie du bénéfice du chiffrement.
   */
  content: content.Content;
}

export type VerificationState =
  | { status: "unverified" }
  | { status: "verified" }
  /** L'empreinte a changé depuis la vérification : réinstallation, ou substitution. */
  | { status: "changed"; previous: string };

/** Rôles d'un groupe : un admin unique, des modérateurs sous lui. */
export interface Roles {
  admin: string;
  moderators: string[];
}

export interface ConversationView {
  groupId: Uint8Array;
  /** Clé d'affichage stable : `Uint8Array` ne s'utilise pas comme clé de Map ou de React. */
  key: string;
  messages: Message[];
  /** Un par appareil membre. Deux appareils d'un même compte y figurent deux fois. */
  peers: Peer[];
  /**
   * Correspondants regroupés par compte, attestations revérifiées.
   *
   * Rempli à la relève plutôt qu'au rendu : la résolution passe par le réseau, et un composant
   * React n'est pas l'endroit où décider de faire confiance à quelqu'un.
   */
  accounts: ResolvedAccount[];
  epoch: bigint;
  cursor: number;
  /**
   * Notre tête de journal a-t-elle déjà été diffusée dans cette conversation ?
   *
   * Volontairement non persisté : à chaque session, une nouvelle diffusion. Le contrôle porte
   * sur l'existence d'une bifurcation, et la refaire de temps en temps coûte un message.
   */
  gossiped?: boolean;
  /**
   * L'historique archivé a-t-il déjà été rapatrié dans cette session ?
   *
   * Même raisonnement que `gossiped` : volontairement non persisté, parce que les messages ne
   * vivent qu'en mémoire. Chaque session doit donc redemander le coffre — une fois, à
   * l'ouverture de la conversation, pas à chaque relève.
   */
  hydrated?: boolean;
  /**
   * Clé de dépôt du groupe, si nous la connaissons.
   *
   * Sa présence fait basculer les envois sur le chemin anonyme : le serveur cesse d'apprendre
   * lequel des membres écrit. Son absence n'est pas une erreur — les conversations créées
   * avant le sealed sender continuent d'utiliser le dépôt signé.
   */
  postingKey?: Uint8Array;
  /** La clé a-t-elle déjà été diffusée dans cette conversation, cette session ? */
  postingKeyShared?: boolean;
  /**
   * Séquences que nous avons nous-mêmes déposées.
   *
   * Elles sont déjà appliquées localement et MLS refuse de les relire. On les saute donc à la
   * relève — mais **sans faire avancer le curseur jusqu'à elles** : le numéro que le serveur
   * attribue à notre message ne dit rien des enveloppes qui le précèdent. Sauter jusque-là
   * enjambe les commits des autres, et le groupe se fige à une epoch périmée sans qu'aucune
   * erreur ne le signale.
   */
  mine: Set<number>;
  /**
   * Ce que chaque compte a accusé, dans cette conversation.
   *
   * Non persisté : un accusé vaut « à ce moment », et le rejouer d'une session à l'autre
   * afficherait un état de lecture que personne n'a confirmé depuis. Les accusés reviennent
   * d'eux-mêmes à la relève suivante.
   */
  receipts: ReceiptBook;
  /**
   * Plus grand numéro d'un **message reçu et affichable**.
   *
   * # Pourquoi il ne suffit pas de réutiliser `cursor`
   *
   * `cursor` avance sur toute enveloppe traitée, accusés compris. Accuser réception jusqu'à
   * `cursor` fait donc accuser réception des accusés : chaque accusé en fait naître un autre,
   * et la conversation ne s'arrête plus jamais. Mesuré, en production locale : dix enveloppes
   * en quarante secondes pour deux personnes qui ne disent rien.
   *
   * Un accusé annonce « j'ai reçu tes messages jusqu'à N », où N est un message. C'est le seul
   * curseur qui a une borne : le trafic de protocole ne le fait pas avancer, donc il finit par
   * se taire.
   */
  contentCursor: number;
  /** Jusqu'où l'utilisateur a effectivement vu la conversation à l'écran. */
  readCursor: number;
  /** Correspondants actuellement en train d'écrire, avec leur horodatage d'expiration. */
  typing: Typing[];
  /** Dernière émission d'un indicateur de frappe, pour le débounce. */
  typingSentAt?: number;
}

/**
 * État de signalisation d'une conversation neuve.
 *
 * Rien de tout cela n'est persisté : un accusé ou un indicateur de frappe vaut « maintenant ».
 * Les restaurer d'une session à l'autre afficherait un état que personne n'a confirmé depuis.
 */
function freshSignalState(): Pick<
  ConversationView,
  "receipts" | "contentCursor" | "readCursor" | "typing"
> {
  return { receipts: new Map(), contentCursor: 0, readCursor: 0, typing: [] };
}

export class Session {
  private constructor(
    readonly deviceId: string,
    readonly handle: string,
    private readonly client: Client,
    private account: AccountKey,
    private readonly crypto: Crypto,
    private readonly api: Api,
    /**
     * Où l'état est rangé, et sous quelle identité.
     *
     * Une paire et non deux champs : la clé qui ouvre l'état doit être celle sous laquelle il a
     * été scellé, et les dissocier permettrait d'assembler un store avec le chiffreur de
     * l'autre plateforme — un état illisible, sans autre symptôme qu'un échec de déchiffrement.
     */
    private readonly ancrage: Ancrage,
    /**
     * Ce qui chiffre l'état au repos.
     *
     * Le socle de l'ancrage quand aucun verrou n'est posé ; un `LockedCipher` sinon, dont la
     * clé maîtresse n'existe qu'en mémoire après saisie du mot de passe. L'identité, elle, ne
     * bascule pas : c'est toujours le socle qui signe.
     */
    private atRest: DeviceCipher,
    private lock: LockEnvelope | undefined,
    /**
     * Clé du coffre. Présente par défaut ; `null` seulement si l'utilisateur a coupé la
     * sauvegarde, ou si sa dérivation a échoué.
     *
     * Dérivée de la phrase de récupération, donc **stable dans le temps** : c'est ce qui
     * permet à un appareil neuf de relire l'historique, et c'est exactement ce à quoi on
     * renonce en la gardant. Voir `vault.ts`.
     */
    private vaultCipher: CryptoKey | null,
    readonly conversations: Map<string, ConversationView>,
    private verified: Record<string, string>,
    private knownDevices: Record<string, string[]>,
    /**
     * Réglages de signalisation.
     *
     * Les accusés de lecture sont **actifs par défaut**, comme dans les applications
     * grand public : les désactiver silencieusement rendrait l'affichage de l'autre côté
     * incompréhensible. C'est un choix de produit, et il est réversible d'un clic.
     */
    private signals: SignalSettings = { readReceipts: true, typingIndicator: true, presence: true },
  ) {}

  /** Session temps réel, quand elle est ouverte. Sa panne ne retire aucune fonctionnalité. */
  private gateway?: Gateway;

  /**
   * Dernière tête de journal acceptée.
   *
   * Sert d'ancre : le serveur devra prouver que son journal la prolonge. Sans mémoire, il
   * pourrait réécrire une clé déjà publiée et servir un journal tout aussi cohérent.
   */
  private seenHead: log.SeenHead | undefined;

  /**
   * Anomalies du journal constatées depuis le démarrage.
   *
   * Conservées et affichées plutôt que jetées : une preuve qui ne vérifie pas n'est pas une
   * erreur réseau à réessayer, c'est le signal exact que tout ce dispositif existe pour
   * produire.
   */
  readonly logAlerts: string[] = [];

  /**
   * Relève en cours, s'il y en a une.
   *
   * Le polling est déclenché par un `setInterval` : sans ce verrou, une relève plus lente que
   * l'intervalle se retrouve en concurrence avec la suivante. Les deux lisent le même curseur
   * avant que l'une n'ait écrit le sien, retraitent les mêmes enveloppes — et MLS refuse la
   * seconde lecture, les clés ayant été détruites. Le message est alors perdu définitivement.
   *
   * Le symptôme est déroutant : tout fonctionne tant que le réseau est rapide, puis des
   * messages disparaissent dès qu'une opération allonge la relève.
   */
  private polling: Promise<void> | null = null;

  /** Empreinte du compte, à comparer hors bande avec son correspondant. */
  accountFingerprint(): string {
    return this.account.fingerprint();
  }

  /**
   * État de vérification d'un pair.
   *
   * Sans comparaison hors bande, un serveur malveillant peut servir à chacun un KeyPackage
   * qu'il contrôle et relayer en clair entre deux sessions parfaitement chiffrées. Aucune
   * vérification cryptographique ne le détecte — c'est le maillon faible réel de tout
   * déploiement E2EE, et la raison pour laquelle cet état est affiché en permanence plutôt
   * que rangé dans un menu.
   */
  verificationOf(account: ResolvedAccount): VerificationState {
    const known = this.verified[account.handle];
    if (!known) return { status: "unverified" };
    if (known === account.fingerprint) return { status: "verified" };
    return { status: "changed", previous: known };
  }

  async markVerified(account: ResolvedAccount): Promise<void> {
    this.verified[account.handle] = account.fingerprint;
    await this.persist();
  }

  /**
   * Crée un compte neuf et son premier appareil.
   *
   * Retourne la phrase de récupération **avec** la session : elle n'existe qu'ici et ne peut
   * plus être réaffichée ensuite. C'est délibéré — une phrase que l'application sait
   * remontrer est une phrase que quiconque tient l'appareil déverrouillé peut remontrer.
   */
  static async create(handle: string): Promise<[Session, string]> {
    const crypto = await loadCrypto();
    const created = crypto.AccountKey.generate() as CreatedAccount;

    await Api.createAccount(handle, created.identityKey);

    const account = crypto.AccountKey.restore(created.phrase);
    const session = await Session.attach(crypto, account, handle);
    return [session, created.phrase];
  }

  /**
   * Rattache un nouvel appareil à un compte existant, depuis sa phrase de récupération.
   *
   * L'appareil s'atteste lui-même, ce qui suppose de détenir la clé du compte. Sans elle, le
   * serveur refuse l'enregistrement — c'est ce qui empêche un tiers de se déclarer appareil
   * d'un compte dont il connaîtrait seulement le pseudonyme.
   *
   * Ce que ce chemin ne fait pas : rejoindre les conversations existantes. Elles vivent dans
   * des groupes MLS dont cet appareil n'est pas membre ; il faut qu'un appareil déjà présent
   * l'y ajoute, ce que fera l'appairage par QR code.
   */
  /**
   * Rattache cet appareil au compte dont on vient de recevoir la graine par appairage.
   *
   * Chemin normal d'ajout d'un appareil : la phrase de récupération n'est jamais ressaisie, et
   * n'a donc pas à être exposée une seconde fois.
   */
  static async fromSeed(handle: string, seed: Uint8Array, ancrage?: Ancrage): Promise<Session> {
    const crypto = await loadCrypto();
    return Session.attach(crypto, crypto.AccountKey.fromSeed(seed), handle, ancrage);
  }

  static async restoreFromPhrase(handle: string, phrase: string): Promise<Session> {
    const crypto = await loadCrypto();
    const account = crypto.AccountKey.restore(phrase.trim());
    return Session.attach(crypto, account, handle);
  }

  /** Enregistre un appareil sous un compte dont on détient déjà la clé. */
  private static async attach(
    crypto: Crypto,
    account: AccountKey,
    handle: string,
    /**
     * Ancrage imposé, pour la migration : elle enregistre un appareil natif depuis un appareil
     * web, donc le défaut de la plateforme ne dit pas ce qu'il faut faire.
     */
    impose?: Ancrage,
  ): Promise<Session> {
    // L'ancrage décide où vivront les clés : dans le processus natif sous Tauri, dans
    // IndexedDB ailleurs. L'enregistrement n'a pas à savoir lequel des deux — il ne manipule
    // que la moitié publique.
    const ancrage = impose ?? (await ancrageNeuf());
    const authKey = await ancrage.cipher.authPublicKey();

    // L'identifiant est qualifié par le handle : sans cela l'espace de noms serait global et
    // le premier arrivé accaparerait « desktop » et « mobile » pour tout le monde. Le serveur
    // impose ce préfixe, ce n'est pas une simple convention côté client.
    //
    // Le nom est détecté, jamais demandé, et décliné en cas de collision : un compte peut
    // légitimement avoir deux ordinateurs, et ce n'est pas à l'utilisateur de le gérer.
    let client: Client | null = null;
    let deviceId = "";

    for (const name of deviceNameCandidates(detectDeviceKind())) {
      deviceId = `${handle}:${name}`;

      // Le credential MLS porte le **handle**, pas l'identifiant d'appareil : c'est le
      // correspondant qu'on affiche, et il est de toute façon en clair dans l'arbre public.
      // L'appareil se distingue par sa clé de signature, et se nomme dans l'attestation.
      const candidate = crypto.Client.create(handle);
      const mlsKey = candidate.signatureKey();

      // Les deux clés sont attestées ensemble. Les attester séparément permettrait de
      // recombiner l'attestation d'un appareil légitime avec la clé MLS d'un appareil hostile.
      const attestation = account.attest(handle, deviceId, authKey, mlsKey);

      try {
        await Api.register(deviceId, handle, authKey, mlsKey, attestation);
        client = candidate;
        break;
      } catch (error) {
        // 409 : ce nom est déjà pris sur ce compte. Toute autre erreur est réelle.
        if (!(error instanceof ApiError) || error.status !== 409) throw error;
      }
    }

    if (!client) {
      throw new Error("Trop d'appareils portant ce nom sur ce compte.");
    }

    // Sans verrou, l'état est chiffré par le socle lui-même ; poser un verrou l'enveloppera
    // sans toucher à l'identité de l'appareil.
    const api = new Api(deviceId, ancrage.cipher);
    const session = new Session(
      deviceId,
      handle,
      client,
      account,
      crypto,
      api,
      ancrage,
      // Pas de verrou à la création : l'utilisateur le pose s'il le souhaite, depuis
      // l'application. L'imposer ici mettrait une saisie de mot de passe juste avant l'écran
      // de la phrase de récupération, qui mérite toute l'attention disponible.
      ancrage.cipher,
      undefined,
      // Coffre actif dès la création, donc dès le premier message.
      //
      // Renoncer à la forward secrecy sur l'historique reste un vrai renoncement — mais une
      // messagerie dont la conversation repart vide à chaque rechargement n'en est pas une, et
      // faire porter ce choix à un écran de réglage revenait à le refuser pour presque tout le
      // monde. Le compromis est donc pris ici, énoncé sur l'écran de la phrase de récupération
      // (qui est aussi la clé du coffre), et révocable dans les réglages.
      await vault.importVaultKey(account.vaultKey()),
      new Map(),
      {},
      {},
    );

    await session.replenishKeyPackages(KEY_PACKAGE_TARGET);
    await session.persist();
    return session;
  }

  /**
   * Enregistre un appareil natif à partir de celui-ci, puis s'efface.
   *
   * # Pourquoi c'est l'ancien appareil qui pilote
   *
   * Lui seul est membre des groupes MLS. Le nouvel appareil ne peut pas s'y inviter : MLS ne
   * rattrape pas un membre absent de l'arbre, il faut qu'un membre l'ajoute. C'est exactement
   * ce que fait `propagateOwnDevices` à chaque relève, sans rien de spécifique à la migration.
   *
   * # L'ordre est dans `migration.ts`
   *
   * Ici, seulement de quoi l'exécuter. La séparation n'est pas cosmétique : l'enchaînement est
   * le seul endroit qu'une interruption peut abîmer, et il ne serait pas testable mêlé à MLS,
   * au réseau et à la webview.
   */
  async migrerVersNatif(
    decision: Decision,
    natif: Ancrage,
    progres?: (etape: string) => void,
  ): Promise<Session> {
    // Ouverte d'abord si elle existe déjà : une reprise ne réenregistre pas: le serveur
    // décline les noms pris, donc un second enregistrement créerait un appareil de plus.
    let nouvelle = await Session.ouvrir(natif);

    const etapes: Etapes = {
      progres,
      enregistrerAppareilNatif: async () => {
        nouvelle = await Session.fromSeed(this.handle, this.account.exportSeed(), natif);
        return nouvelle.deviceId;
      },
      propagerDepuisAncien: () => this.poll(),
      avancement: async () => {
        // La nouvelle session relève avant d'être comptée : les groupes n'arrivent pas par
        // l'ajout lui-même, mais par les Welcome qu'elle doit aller chercher.
        await nouvelle?.poll();
        return {
          rejointes: nouvelle?.conversations.size ?? 0,
          attendues: this.conversations.size,
        };
      },
      restaurerHistorique: async () => {
        for (const view of nouvelle?.conversations.values() ?? []) {
          // Une conversation dont l'historique manque reste utilisable : mieux vaut une
          // migration qui aboutit avec un fil incomplet qu'un compte bloqué sur une entrée
          // d'archive illisible.
          await nouvelle?.hydrate(view).catch((error: unknown) => {
            console.warn("historique non restauré pour une conversation", error);
          });
        }
      },
      revoquerAncien: (ancien) => {
        if (!nouvelle) throw new Error("migration : aucun appareil natif à qui confier la suite");
        return nouvelle.revokeOwnDevice(ancien);
      },
      oublierWeb: () => this.forget(),
    };

    await migrer(decision, etapes, this.deviceId);

    if (!nouvelle) throw new Error("migration : l'appareil natif n'a pas été enregistré");
    return nouvelle;
  }

  /**
   * Indique si une session verrouillée attend un mot de passe.
   *
   * Permet à l'interface de demander la saisie **avant** de tenter une restauration, plutôt
   * que de traiter l'absence de mot de passe comme une erreur de déchiffrement.
   */
  static async isLocked(): Promise<boolean> {
    const ancrage = await ancrageCourant();
    const stored = await ancrage?.store.load();
    return Boolean(stored?.state && stored.lock);
  }

  /**
   * Recharge la session précédente, ou `null` s'il n'y en a pas.
   *
   * `password` est requis si un verrou est posé. Un mot de passe faux fait échouer l'AEAD :
   * il n'y a rien à comparer, donc pas de comparaison à rendre constante, et pas de « hash du
   * mot de passe » stocké à côté qui offrirait une cible d'attaque hors ligne de plus.
   */
  static async restore(ouverture?: string | CryptoKey): Promise<Session | null> {
    const ancrage = await ancrageCourant();
    return ancrage === undefined ? null : Session.ouvrir(ancrage, ouverture);
  }

  /**
   * Recharge la session rangée dans un ancrage précis.
   *
   * Séparé de `restore` pour la migration, qui doit tenir les **deux** sessions ouvertes en
   * même temps : l'ancienne introduit la nouvelle dans les groupes, et seule l'ancienne peut le
   * faire — elle seule en est membre.
   */
  static async ouvrir(
    ancrage: Ancrage,
    /**
     * De quoi ouvrir le verrou, s'il y en a un.
     *
     * Deux formes et non une, parce que les deux chemins n'ont pas la même entrée : le mot de
     * passe dérive la clé maîtresse, la biométrie la rend directement. Les réunir derrière une
     * chaîne obligerait à encoder une clé en texte, c'est-à-dire à la faire passer par un
     * format dont personne n'a besoin.
     */
    ouverture?: string | CryptoKey,
  ): Promise<Session | null> {
    const stored = await ancrage.store.load();
    if (!stored?.state) return null;

    if (stored.lock && ouverture === undefined) {
      throw new Error("Cette session est verrouillée : mot de passe requis.");
    }

    const master =
      typeof ouverture === "string" && stored.lock
        ? await openLock(stored.lock, ouverture)
        : typeof ouverture === "object"
          ? ouverture
          : undefined;

    const atRest =
      stored.lock && master ? new LockedCipher(ancrage.cipher, master) : ancrage.cipher;

    const crypto = await loadCrypto();
    const state = await atRest.open(stored.state);
    const client = crypto.Client.restore(state, stored.groupIds);
    const account = crypto.AccountKey.fromSeed(await atRest.open(stored.accountSeed));
    // Le socle et non `atRest` : c'est l'identité qui signe les requêtes, et elle ne bascule
    // pas avec le verrou — le serveur ne doit voir aucune différence.
    const api = new Api(stored.deviceId, ancrage.cipher);

    const conversations = new Map<string, ConversationView>();
    for (const groupId of stored.groupIds) {
      conversations.set(toHex(groupId), {
        groupId,
        key: toHex(groupId),
        messages: [],
        peers: client.peerFingerprints(groupId) as Peer[],
        accounts: [],
        epoch: client.epoch(groupId),
        cursor: stored.cursors?.[toHex(groupId)] ?? 0,
        // Les séquences déjà traitées sont derrière le curseur : rien à retenir au rechargement.
        mine: new Set<number>(),
        // Sans cette restauration, le dépôt anonyme et l'indicateur de frappe restent inertes
        // jusqu'à ce qu'un autre membre rediffuse la clé — donc potentiellement jamais.
        postingKey: stored.postingKeys?.[toHex(groupId)]
          ? fromBase64(stored.postingKeys[toHex(groupId)])
          : undefined,
        ...freshSignalState(),
      });
    }

    return new Session(
      stored.deviceId,
      stored.handle,
      client,
      account,
      crypto,
      api,
      ancrage,
      atRest,
      stored.lock,
      // Trois valeurs, pas deux, et c'est toute la migration des comptes existants : `false`
      // signifie que l'utilisateur a explicitement coupé la sauvegarde, et cela se respecte ;
      // `undefined` signifie qu'il n'a jamais eu à en décider, et se traite comme un compte
      // neuf, donc actif. Confondre les deux reviendrait à réactiver le coffre dans le dos de
      // quelqu'un qui l'avait refusé.
      stored.vaultEnabled === false ? null : await vaultCipherOf(crypto, account),
      conversations,
      stored.verified ?? {},
      stored.knownDevices ?? {},
      // `presence` absent vaut activé : c'est le défaut, le drapeau ne retient qu'un refus.
      { readReceipts: true, typingIndicator: true, ...stored.signals },
    );
  }

  /**
   * Dernière activité connue de chaque correspondant, en millisecondes.
   *
   * **Jamais persistée**, pour la même raison que les accusés et les indicateurs de frappe : une
   * présence restaurée d'une session à l'autre afficherait en ligne quelqu'un que personne n'a
   * vu depuis. Elle revient d'elle-même au premier tour de relève.
   */
  private presence = new Map<string, number>();

  /**
   * Horloge du serveur au moment de la dernière relève de présence.
   *
   * Conservée parce que la fraîcheur se juge en comparant deux horodatages, et que celui du
   * navigateur peut être n'importe quoi.
   */
  private presenceNow = 0;

  /** Dernière activité d'un compte, ou `undefined` si le serveur n'a rien à en dire. */
  presenceOf(handle: string): number | undefined {
    return this.presence.get(handle);
  }

  /** Horloge du serveur à la dernière relève : la référence pour juger de la fraîcheur. */
  get presenceClock(): number {
    return this.presenceNow;
  }

  /** Le coffre est-il actif sur ce compte ? */
  get archiving(): boolean {
    return this.vaultCipher !== null;
  }

  /**
   * Réactive le coffre après une coupure explicite.
   *
   * Les messages **déjà échangés** ne seront pas archivés : leurs clés MLS sont détruites, et
   * rien ne permet de les reconstituer. L'archivage reprend maintenant, jamais rétroactivement
   * — l'interface doit le dire, sans quoi l'utilisateur croira avoir récupéré un passé qui
   * n'existe plus. C'est vrai de la période pendant laquelle il l'avait coupé.
   */
  async enableVault(): Promise<void> {
    this.vaultCipher = await vault.importVaultKey(this.account.vaultKey());
    await this.persist();
  }

  /**
   * Désactive le coffre. **N'efface pas ce qui a déjà été archivé** : le serveur conserve les
   * entrées, et la clé qui les ouvre reste dérivable de la phrase.
   *
   * Le dire plutôt que de laisser croire à un effacement : promettre une suppression qu'on ne
   * contrôle pas — le serveur pouvant garder des copies — serait un mensonge de sécurité.
   */
  async disableVault(): Promise<void> {
    this.vaultCipher = null;
    await this.persist();
  }

  /**
   * Recharge l'historique archivé d'une conversation.
   *
   * Appelé sur demande plutôt qu'au démarrage : la restauration passe par le réseau et
   * déchiffre message par message, ce qui n'a pas à retarder l'affichage.
   */
  async restoreHistory(view: ConversationView): Promise<number> {
    if (!this.vaultCipher) return 0;

    const { messages, illisibles } = await vault.restore(this.api, this.vaultCipher, view.groupId);
    const nouveaux = vault.merge(view.messages, messages);

    // Rien de lisible alors qu'il y avait des entrées : la clé du coffre n'est plus la bonne,
    // c'est-à-dire que le compte a été tourné. Le dire plutôt que de rendre un fil vide.
    if (messages.length === 0 && illisibles > 0) {
      throw new Error(
        "L'historique archivé n'est plus lisible : la phrase de récupération a changé.",
      );
    }

    view.messages.push(...nouveaux);
    return nouveaux.length;
  }

  /**
   * Rapatrie l'historique archivé, une seule fois par conversation et par session.
   *
   * Appelé à l'ouverture d'une conversation, pas au démarrage : la restauration passe par le
   * réseau et déchiffre entrée par entrée, ce qui n'a pas à retarder l'affichage de la liste.
   * Et surtout pas depuis la relève périodique, qui repasse toutes les trente secondes sur
   * **toutes** les conversations — ce serait un aller-retour réseau par groupe, en boucle.
   *
   * # Ce qu'elle ne touche pas, et pourquoi
   *
   * Ni `contentCursor`, ni `readCursor`, ni `receipts`. Un message restauré a déjà été accusé
   * lors d'une session antérieure ; faire avancer le curseur annoncé ferait ré-émettre un accusé
   * à chaque rechargement, et chaque accusé en engendrerait un autre. C'est le seul chemin par
   * lequel la boucle décrite dans le README peut renaître.
   *
   * Ni `view.cursor` non plus : il appartient à l'état MLS, pas à l'affichage. Le coffre ne dit
   * rien du ratchet.
   */
  async hydrate(view: ConversationView): Promise<number> {
    if (view.hydrated || !this.vaultCipher) return 0;

    // Posé **avant** l'attente : deux rendus rapprochés lanceraient sinon deux rapatriements
    // concurrents de la même conversation.
    view.hydrated = true;
    return this.restoreHistory(view);
  }

  /** Archive les messages qui viennent d'être lus ou envoyés, si le coffre est actif. */
  private async archive(view: ConversationView, messages: Message[]): Promise<void> {
    if (!this.vaultCipher || messages.length === 0) return;

    try {
      await vault.store(this.api, this.vaultCipher, view.groupId, messages);
    } catch (error) {
      // Un échec d'archivage ne doit pas empêcher la conversation : le message est déjà
      // délivré, seule la sauvegarde manque. Elle sera retentée au prochain envoi.
      console.warn("archivage reporté", error);
    }
  }

  /** Un verrou est-il posé sur cet appareil ? */
  get locked(): boolean {
    return this.lock !== undefined;
  }

  /**
   * Pose un verrou : l'état bascule de la clé d'IndexedDB vers une clé maîtresse dérivée.
   *
   * La bascule est un simple `persist()` : l'état est ré-chiffré sous la nouvelle clé, et
   * l'ancienne version est écrasée. La clé non-extractable reste dans IndexedDB — elle sert
   * toujours à signer les requêtes HTTP — mais ne déchiffre plus rien.
   */
  async enableLock(password: string): Promise<void> {
    if (this.lock) throw new Error("Un verrou est déjà posé.");

    const [envelope, master] = await createLock(password);
    this.lock = envelope;
    this.atRest = new LockedCipher(this.ancrage.cipher, master);
    await this.persist();
  }

  /**
   * Retire le verrou. Exige le mot de passe courant.
   *
   * Sans cette exigence, quiconque trouve un appareil déverrouillé le désarme définitivement
   * en un clic — le verrou ne protégerait plus que jusqu'au premier oubli d'écran.
   */
  async disableLock(password: string): Promise<void> {
    if (!this.lock) return;

    await openLock(this.lock, password);
    this.lock = undefined;
    this.atRest = this.ancrage.cipher;

    // La clé rangée pour la biométrie n'a plus rien à ouvrir, et la laisser serait pire
    // qu'inutile : elle survivrait au verrou qui la justifiait.
    await biometrics.retirerBiometrie().catch(() => {});
    await this.persist();
  }

  /**
   * Fait garder la clé maîtresse par le système, derrière l'empreinte ou le visage.
   *
   * # Ce que l'utilisateur échange
   *
   * Son mot de passe n'était nulle part ; sa clé maîtresse le sera. Elle est scellée par les
   * secrets du processus natif, eux-mêmes en clair dans le répertoire privé de l'application :
   * la protection devient celle du système et de son invite, solide contre qui prend l'appareil
   * en main, sans valeur contre qui en extrait le stockage. L'interface doit l'annoncer avant.
   *
   * # Pourquoi le mot de passe n'est pas redemandé
   *
   * Il vient de l'être : sans lui, cette session ne serait pas ouverte. Le redemander
   * n'ajouterait aucune preuve — quelqu'un qui tient un appareil déverrouillé lit déjà tout —
   * et ferait payer un geste de sécurité par une gêne sans contrepartie.
   */
  async activerBiometrie(): Promise<void> {
    if (!(this.atRest instanceof LockedCipher)) {
      throw new Error("Posez d'abord un verrou : la biométrie garde sa clé, elle n'en crée pas.");
    }

    await biometrics.activerBiometrie(await exporterMaster(this.atRest.cleMaitresse()));
  }

  /** Retire le déverrouillage biométrique. Le verrou reste posé, le mot de passe l'ouvre encore. */
  async retirerBiometrie(): Promise<void> {
    await biometrics.retirerBiometrie();
  }

  /**
   * Change le mot de passe sans re-chiffrer l'état.
   *
   * Seuls les 32 octets de la clé maîtresse sont re-scellés. L'état, qui pèse plusieurs
   * kilooctets et grandit avec les conversations, n'est pas touché — et ne repasse donc pas
   * en clair en mémoire au moment le plus délicat.
   */
  async changeLockPassword(ancien: string, nouveau: string): Promise<void> {
    if (!this.lock) throw new Error("Aucun verrou à modifier.");
    this.lock = await changePassword(this.lock, ancien, nouveau);
    await this.persist();
  }

  /**
   * Efface l'identité de cet appareil.
   *
   * # Pourquoi un drapeau, et pas seulement un `clearSession`
   *
   * L'effacement est suivi d'un rechargement de page, qui n'est pas instantané. Pendant ce
   * délai, une relève **déjà en vol** se termine et appelle `persist()` — qui réécrit dans la
   * base l'identité qu'on vient d'effacer. Le rechargement la retrouve alors intacte.
   *
   * Le symptôme observé : l'écran de création de compte apparaît, on crée une nouvelle
   * identité, et au rechargement suivant c'est l'ancienne qui revient. Rien ne signale
   * l'échec.
   *
   * Ce n'est pas un défaut cosmétique : l'utilisateur croit ses clés détruites alors
   * qu'elles sont toujours là. Le drapeau condamne définitivement cette instance — plus
   * aucune écriture ne partira d'elle, quelle que soit l'opération encore en cours.
   */
  private forgotten = false;

  async forget(): Promise<void> {
    this.forgotten = true;
    await this.ancrage.store.clear();
  }

  /** Efface sans détenir de session — cas d'un verrou dont on a perdu le mot de passe. */
  static async forget(): Promise<void> {
    await effacerTout();
  }

  fingerprint(): string {
    return this.client.fingerprint();
  }

  /**
   * Persiste l'état MLS, chiffré.
   *
   * À appeler après **toute** opération qui fait avancer un groupe. Un état persisté en
   * retard puis restauré ferait reculer les epochs et rejouerait des clés déjà utilisées.
   *
   * **L'historique ne passe pas par ici.** Rien de ce qui est écrit sur ce disque ne contient
   * de message : les conserver localement demanderait de les chiffrer sous la clé d'état, ce qui
   * est faisable, mais fabriquerait un second historique par appareil, à tenir cohérent avec le
   * premier. C'est le coffre serveur (`vault.ts`) qui tient ce rôle, désormais par défaut, et
   * la conversation se repeuple à l'ouverture via `hydrate`.
   */
  private async persist(): Promise<void> {
    // Voir `forget` : une écriture qui gagnerait la course contre le rechargement
    // ressusciterait une identité que l'utilisateur croit détruite.
    if (this.forgotten) return;

    const groupIds = this.client.conversationIds();
    const cursors = Object.fromEntries(
      [...this.conversations.values()].map((view) => [view.key, view.cursor]),
    );

    await this.ancrage.store.save({
      cursors,
      deviceId: this.deviceId,
      handle: this.handle,
      // La graine est chiffrée comme l'état MLS : elle vaut le compte entier.
      accountSeed: await this.atRest.seal(this.account.exportSeed()),
      lock: this.lock,
      vaultEnabled: this.vaultCipher !== null,
      state: await this.atRest.seal(this.client.exportState()),
      groupIds,
      verified: this.verified,
      knownDevices: this.knownDevices,
      signals: this.signals,
      postingKeys: Object.fromEntries(
        [...this.conversations.values()]
          .filter((view) => view.postingKey)
          .map((view) => [view.key, toBase64(view.postingKey as Uint8Array)]),
      ),
    });
  }

  /**
   * Recharge le stock si nécessaire.
   *
   * Appelé à chaque relève. L'opération est idempotente et bon marché : une requête de
   * comptage, puis une publication seulement sous le seuil.
   */
  private async replenishKeyPackagesIfLow(): Promise<void> {
    const { remaining } = await this.api.keyPackageStock();
    if (remaining <= KEY_PACKAGE_LOW_WATER) {
      await this.replenishKeyPackages(KEY_PACKAGE_TARGET - remaining);
    }
  }

  private async replenishKeyPackages(count: number): Promise<void> {
    if (count <= 0) return;
    const packages = Array.from({ length: count }, () => this.client.publishKeyPackage());
    await this.api.publishKeyPackages(packages);
  }

  /**
   * Résout un pseudonyme en appareils vérifiés.
   *
   * Passe systématiquement par `resolveAccount`, qui recontrôle chaque attestation. La liste
   * vient du serveur : sans ce contrôle, il lui suffirait d'y glisser un appareil qu'il
   * contrôle pour lire toutes les conversations du compte.
   */
  async resolve(handle: string): Promise<ResolvedAccount> {
    const account = await resolveAccount(this.api, this.crypto, handle);

    // Les attestations prouvent qu'un appareil appartient au compte. Elles ne disent rien de
    // la clé du COMPTE, qu'on découvre ici pour la première fois — c'est le trou que le
    // journal ferme.
    try {
      const { verdict, head } = await log.verifyAccount(
        this.api,
        this.crypto,
        handle,
        account.identityKey,
        this.seenHead,
      );

      if (verdict.ok) {
        // La tête n'est mémorisée qu'en cas de succès : entériner une tête qu'on vient de
        // refuser reviendrait à valider ce qu'on rejette.
        this.seenHead = head;
      } else {
        this.raiseLogAlert(verdict.reason);
      }
    } catch (error) {
      // Journal injoignable : on n'invente pas une alerte de sécurité pour une panne réseau.
      // Mais on ne mémorise rien non plus, donc le contrôle sera refait.
      console.warn("vérification du journal reportée", error);
    }

    return account;
  }

  /**
   * Diffuse notre vue du journal à un correspondant.
   *
   * # Ce que cela ajoute aux preuves
   *
   * Un serveur peut tenir **deux journaux** et en servir un à chacun. Les preuves de chaque
   * victime vérifient parfaitement : chacune voit un journal signé et cohérent. Rien du côté
   * client seul ne peut le détecter.
   *
   * La comparaison entre deux personnes le peut — à condition de passer par un canal que le
   * serveur ne contrôle pas. Ce canal est la conversation elle-même : il en transporte les
   * octets sans pouvoir les lire ni les modifier.
   *
   * # Pourquoi c'est parcimonieux
   *
   * Une tête par conversation et par session suffit : le contrôle porte sur l'existence d'une
   * bifurcation, pas sur son instant. En émettre à chaque message ajouterait du trafic sans
   * rien détecter de plus.
   */
  private async gossip(view: ConversationView): Promise<void> {
    if (!this.seenHead || view.gossiped) return;
    view.gossiped = true;

    await this.sendContent(view, {
      kind: "gossip",
      head: { size: this.seenHead.size, root: this.seenHead.root },
    });
  }

  /**
   * Confronte la vue d'un correspondant à la nôtre.
   *
   * On ne compare pas les racines directement — nos deux journaux ont des tailles différentes,
   * et une divergence de taille est normale. On demande au serveur de **prouver** que le
   * journal qu'il nous sert prolonge celui qu'il a servi à l'autre.
   *
   * S'il a servi deux journaux distincts, il ne le peut pas : aucune preuve de cohérence ne
   * relie deux arbres qui ont bifurqué. C'est le seul contrôle qui attrape ce cas.
   */
  private async checkGossip(head: content.GossipHead): Promise<void> {
    try {
      const courante = await this.api.logHead();

      const verdict = await log.verifyExtends(
        this.api,
        this.crypto,
        { size: head.size, root: head.root, logKey: courante.logKey },
        courante,
      );

      if (!verdict.ok) {
        this.raiseLogAlert(
          "Un correspondant voit un journal de clés différent du nôtre. " +
            "Le serveur en présente deux versions : c'est une attaque, pas une panne.",
        );
      }
    } catch (error) {
      console.warn("comparaison des journaux reportée", error);
    }
  }

  /**
   * De quoi déposer sans s'identifier, si nous détenons la clé du groupe.
   *
   * `undefined` fait retomber sur le dépôt signé. Ce n'est pas une panne : les conversations
   * créées avant le sealed sender n'ont pas de clé, et continuer à les servir vaut mieux que
   * les rendre muettes.
   */
  private posting(view: ConversationView): { key: Uint8Array; mac: PostMac } | undefined {
    if (!view.postingKey) return undefined;
    return { key: view.postingKey, mac: this.crypto.postMac };
  }

  /**
   * Même clé que [`Session.posting`], **autre domaine**.
   *
   * Le serveur vérifie les signaux sous `wac-signal-mac-v1` et les dépôts sous `wac-post-v1` :
   * réutiliser le second pour un signal produit un 403 que rien n'explique côté client, la
   * requête étant lancée sans attendre sa réponse. La séparation existe pour qu'un MAC de
   * signal — dont le rejeu n'est pas contrôlé — ne vaille pas comme MAC de dépôt.
   */
  private signalPosting(
    view: ConversationView,
  ): { key: Uint8Array; mac: PostMac } | undefined {
    if (!view.postingKey) return undefined;
    return { key: view.postingKey, mac: this.crypto.signalMac };
  }

  /**
   * Émet un signal éphémère par la session, ou par HTTP si elle est fermée.
   *
   * Les deux chemins sont **anonymes** : le serveur vérifie le même MAC de groupe et apprend
   * qu'un membre écrit, jamais lequel. La session ne fait que rendre le trajet moins cher — une
   * trame au lieu d'une requête, pour un événement qui se produit à chaque frappe.
   *
   * Le repli n'est donc pas une dégradation de confidentialité, et c'est ce qui permet de le
   * prendre sans hésiter plutôt que de renoncer au signal.
   */
  private async emitSignal(
    groupId: Uint8Array,
    payload: Uint8Array,
    posting: { key: Uint8Array; mac: PostMac },
  ): Promise<void> {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const mac = posting.mac(posting.key, groupId, nonce, payload);

    if (this.gateway?.signal(groupId, nonce, mac, payload)) return;

    await this.api.postSignal(groupId, payload, posting);
  }

  /**
   * Transmet la clé de dépôt aux autres membres d'un groupe.
   *
   * Émise une fois par session et par groupe, par celui qui la détient. Un membre qui ne l'a
   * pas encore reçue poste en mode signé entre-temps — moins discret, mais fonctionnel. Faire
   * l'inverse, refuser d'écrire tant que la clé n'est pas là, transformerait une dégradation
   * de confidentialité en panne.
   */
  private async sharePostingKey(view: ConversationView): Promise<void> {
    if (!view.postingKey || view.postingKeyShared || view.peers.length === 0) return;
    view.postingKeyShared = true;

    await this.sendContent(view, { kind: "posting-key", key: view.postingKey });
  }

  /** Enregistre une anomalie du journal, sans doublon. */
  private raiseLogAlert(reason: string): void {
    if (!this.logAlerts.includes(reason)) this.logAlerts.push(reason);
  }

  /**
   * Cherche une conversation dont les participants sont exactement ceux demandés.
   *
   * La composition est lue dans l'**arbre MLS** (`view.peers`), pas dans un champ local :
   * l'arbre est l'état authentifié, et c'est lui qui décide qui est membre. Un journal local
   * divergerait au premier retrait manqué.
   *
   * On compare des ensembles, pas des listes : l'ordre de saisie ne doit pas produire deux
   * groupes différents. Un compte à plusieurs appareils apparaît plusieurs fois dans l'arbre,
   * d'où le passage par un `Set`.
   */
  private findConversation(handles: string[]): ConversationView | undefined {
    const cherche = [...new Set(handles)].sort().join("\u0000");

    for (const view of this.conversations.values()) {
      const membres = [...new Set(view.peers.map((peer) => peer.name))]
        .filter((name) => name !== this.handle)
        .sort()
        .join("\u0000");

      if (membres === cherche) return view;
    }

    return undefined;
  }

  /**
   * Ouvre une conversation avec un ou plusieurs comptes, en y ajoutant **tous** leurs
   * appareils.
   *
   * # Parité
   *
   * Un appareil oublié est un appareil qui ne reçoit rien : le correspondant verrait la
   * conversation apparaître sur son téléphone et pas sur sa tablette, sans explication. Tous
   * les appareils d'un compte ont le même accès, partout — c'est l'invariant que
   * `addMissingDevices` maintient ensuite à chaque relève.
   *
   * # Plat ou administré
   *
   * À deux comptes, la conversation est **plate** : des rôles d'administration n'y auraient
   * aucun sens, et le groupe plat est la forme correcte d'un 1-to-1. Au-delà, le créateur
   * devient le premier admin.
   */
  async startConversation(handles: string | string[]): Promise<ConversationView> {
    const wanted = [...new Set(typeof handles === "string" ? [handles] : handles)].filter(
      (handle) => handle !== this.handle,
    );
    if (wanted.length === 0) throw new Error("aucun correspondant indiqué.");

    // Une conversation par interlocuteur, un groupe par composition.
    //
    // Sans cette recherche, réécrire le même pseudonyme ouvre un second groupe MLS avec les
    // mêmes membres : les messages se répartissent entre les deux au gré de celui qu'on a
    // sélectionné, et l'utilisateur conclut que des messages se perdent. Rien dans le
    // protocole ne l'interdit — c'est à l'application de décider qu'une conversation est
    // identifiée par ses participants.
    const existante = this.findConversation(wanted);
    if (existante) return existante;

    const peers: ResolvedAccount[] = [];
    for (const handle of wanted) {
      const peer = await this.resolve(handle);

      if (peer.rejected.length > 0) {
        // On refuse d'ouvrir la conversation plutôt que d'ignorer discrètement l'intrus. Le
        // serveur a servi un appareil qu'il n'aurait pas pu produire : c'est le signal qu'on
        // cherchait, et le taire reviendrait à annuler tout l'intérêt du dispositif.
        throw new Error(
          `Le serveur a présenté ${peer.rejected.length} appareil(s) non attesté(s) pour @${handle}. ` +
            "Conversation refusée.",
        );
      }
      if (peer.devices.length === 0) {
        throw new Error(`@${handle} n'a aucun appareil joignable.`);
      }
      peers.push(peer);
    }

    // Un groupe est administré, un 1-to-1 ne l'est pas. Le créateur est le premier admin ;
    // il pourra en désigner d'autres, mais jamais se retirer seul — la politique refuse de
    // laisser un groupe sans admin, ce qui le gèlerait définitivement.
    const groupId =
      peers.length > 1
        ? this.client.createGroup(this.handle)
        : this.client.createConversation();

    const invited: string[] = [];
    /** Enveloppes que nous avons nous-mêmes déposées, et qu'il ne faut pas relire. */
    const emitted = new Set<number>();

    // Clé de dépôt du groupe : elle permettra à chaque membre d'écrire sans s'identifier
    // auprès du serveur. Générée ici, déclarée au serveur à la création, puis distribuée aux
    // autres membres **par MLS** — la faire transiter en clair reviendrait à demander au
    // serveur de distribuer le moyen de ne pas lui parler.
    const postingKey = crypto.getRandomValues(new Uint8Array(32));

    for (const device of peers.flatMap((peer) => peer.devices)) {
      const claimed = await this.api.claimKeyPackage(device.id);
      const invitation = this.client.invite(groupId, claimed.package) as Invitation;

      // Le serveur doit connaître le membre avant qu'aucun message ne circule : c'est lui
      // qui contrôle l'accès à la boîte. La clé de dépôt n'est acceptée qu'au premier appel,
      // celui qui crée le groupe.
      await this.api.addMembers(
        groupId,
        [this.deviceId, device.id],
        invited.length === 0 ? postingKey : undefined,
      );

      // Publier le commit AVANT de l'appliquer.
      //
      // Chaque ajout fait avancer le groupe d'une epoch, et les membres déjà présents doivent
      // appliquer ce commit sous peine de rester à l'ancienne. Si la publication échouait
      // après application, nous aurions changé d'epoch sans que le commit existe nulle part :
      // le groupe serait mort en silence.
      //
      // Au premier tour il n'y a personne à informer, ce qui masque le problème jusqu'à ce
      // qu'un correspondant ait deux appareils.
      if (invited.length > 0) {
        const posted = await this.api.postEnvelope(groupId, envelope.encodeMls(invitation.commit));
        emitted.add(posted.seq);
      }

      // L'arbre de ratchet n'existe qu'une fois le commit appliqué : avant, il ne contient
      // pas le nouveau membre et son Welcome serait rejeté.
      const tree = this.client.applyPending(groupId);
      const welcomed = await this.api.postEnvelope(
        groupId,
        envelope.encodeWelcome(invitation.welcome, tree),
      );
      emitted.add(welcomed.seq);
      invited.push(device.id);
    }

    for (const peer of peers) {
      this.knownDevices[peer.handle] = peer.devices.map((device) => device.id);
    }

    const view: ConversationView = {
      groupId,
      key: toHex(groupId),
      messages: [],
      peers: this.client.peerFingerprints(groupId) as Peer[],
      accounts: peers,
      epoch: this.client.epoch(groupId),
      cursor: 0,
      mine: emitted,
      postingKey,
      ...freshSignalState(),
    };

    this.conversations.set(view.key, view);
    this.syncScope();
    await this.persist();
    return view;
  }

  /**
   * Résout tous les correspondants d'une conversation, nous exclus.
   *
   * Un échec réseau ne doit pas vider la liste affichée : on conserve alors ce qu'on avait,
   * plutôt que de faire disparaître l'état de vérification à la première coupure.
   */
  private async resolvePeers(view: ConversationView): Promise<ResolvedAccount[]> {
    const handles = [...new Set(view.peers.map((peer) => peer.name))].filter(
      (handle) => handle !== this.handle,
    );

    const resolved: ResolvedAccount[] = [];
    for (const handle of handles) {
      try {
        resolved.push(await this.resolve(handle));
      } catch (error) {
        console.warn(`compte @${handle} non résolu`, error);
        const previous = view.accounts.find((account) => account.handle === handle);
        if (previous) resolved.push(previous);
      }
    }
    return resolved;
  }

  /** Rôles d'une conversation, ou `null` si elle est plate (cas du 1-to-1). */
  roles(view: ConversationView): Roles | null {
    return this.client.roster(view.groupId) as Roles | null;
  }

  /**
   * Remplace les rôles d'un groupe.
   *
   * Le roster vit dans le group context MLS, donc dans l'état authentifié : il n'est ni
   * rejouable ni falsifiable isolément. **MLS ne l'applique pas pour autant** — ce sont les
   * clients qui refusent un commit non autorisé, chacun de son côté. Un client qui appliquerait
   * une autre règle ne provoquerait pas une erreur mais un fork silencieux du groupe.
   *
   * Passer un `admin` différent de l'actuel **transmet le groupe**, sans retour possible.
   */
  async setRoles(view: ConversationView, admin: string, moderators: string[]): Promise<void> {
    const commit = this.client.setRoles(view.groupId, admin, moderators);
    await this.publishAndApply(view, commit);
    this.refreshView(view);
    await this.persist();
  }

  /** Nomme ou révoque un modérateur. L'admin seul en a le pouvoir. */
  async setModerator(view: ConversationView, handle: string, moderator: boolean): Promise<void> {
    const roles = this.roles(view);
    if (!roles) throw new Error("cette conversation n'a pas de rôles.");

    const moderators = roles.moderators.filter((m) => m !== handle);
    if (moderator) moderators.push(handle);

    await this.setRoles(view, roles.admin, moderators);
  }

  /**
   * Retire un compte entier d'un groupe, tous ses appareils à la fois.
   *
   * La parité impose le « tous » : laisser un appareil d'un compte évincé continuerait de lui
   * donner accès, et l'interface aurait menti.
   */
  async removeAccount(view: ConversationView, handle: string): Promise<void> {
    const account = view.accounts.find((candidate) => candidate.handle === handle);
    if (!account) throw new Error(`@${handle} n'est pas dans cette conversation.`);

    for (const device of account.devices) {
      const commit = this.client.removeMember(view.groupId, device.mlsKey);
      await this.publishAndApply(view, commit);
      await this.api.removeGroupMembers(view.groupId, [device.id]);
    }

    view.accounts = view.accounts.filter((candidate) => candidate.handle !== handle);
    this.refreshView(view);
    await this.persist();
  }

  /**
   * Désigne le successeur d'un admin qui s'en va.
   *
   * # La contrainte qui dicte la règle
   *
   * La succession doit être calculable **à l'identique par tous les clients**. Deux clients
   * qui désigneraient des successeurs différents ne produiraient pas une erreur : ils
   * installeraient deux rosters incompatibles et le groupe forkerait en silence.
   *
   * D'où l'ordre de l'arbre MLS, seule chronologie que tous partagent sans rien s'échanger.
   *
   * # L'approximation, et pourquoi elle est assumée
   *
   * MLS **réutilise les feuilles libérées** : un arrivant tardif peut hériter de la place d'un
   * membre parti et se retrouver en tête. L'ordre de l'arbre approche donc l'ancienneté sans
   * la restituer exactement. La vraie ancienneté demanderait de tenir l'ordre d'arrivée dans
   * le roster et de le mettre à jour à chaque ajout — un commit de plus à chaque entrée. Le
   * choix ici privilégie le déterminisme, qui est ce qui protège du fork.
   */
  private successor(view: ConversationView, roles: Roles): string | null {
    const membres = view.peers.map((peer) => peer.name).filter((name) => name !== this.handle);

    // Le rang immédiatement en dessous : un modérateur, s'il en reste un dans le groupe.
    const moderateur = membres.find((name) => roles.moderators.includes(name));
    if (moderateur !== undefined) return moderateur;

    // À défaut, le membre le plus ancien au sens de l'arbre.
    return membres[0] ?? null;
  }

  /**
   * Demande à quitter un groupe.
   *
   * # Le départ est une demande, pas un fait
   *
   * La RFC 9420 interdit de se retirer soi-même dans un commit qu'on génère : celui-ci se
   * signe sous le secret de l'epoch qu'il produit, précisément celle dont on vient d'être
   * exclu. Un autre membre doit reprendre la proposition.
   *
   * Conséquence à afficher honnêtement plutôt qu'à masquer : **tant qu'aucun autre membre n'a
   * commité, le départ n'a pas eu lieu.** Faire disparaître la conversation de l'écran
   * laisserait croire le contraire à quelqu'un qui continue d'être lu.
   *
   * # La transmission de l'administration, avant le départ
   *
   * Un groupe sans admin est gelé : plus personne ne peut ajouter, retirer, ni même désigner
   * un admin, l'extension étant elle-même sous leur contrôle. La politique refuse donc de
   * retirer le dernier admin.
   *
   * Le transfert a lieu **avant** la demande de départ, et par nos soins : nous sommes encore
   * admin, donc encore autorisés à modifier le roster. Le faire après serait impossible, et le
   * faire dans le même commit demanderait au successeur de valider une règle de succession
   * plutôt qu'un roster — plus de surface pour diverger, pour aucun gain.
   */
  async requestLeave(view: ConversationView): Promise<void> {
    const roles = this.roles(view);

    if (roles !== null && roles.admin === this.handle) {
      const heritier = this.successor(view, roles);
      if (heritier === null) {
        throw new Error(
          "Vous êtes administrateur et dernier membre : quitter revient à supprimer la conversation.",
        );
      }

      // Le successeur est promu admin et sort de la liste des modérateurs : il est désormais
      // au-dessus, l'y laisser rendrait le roster ambigu.
      await this.setRoles(
        view,
        heritier,
        roles.moderators.filter((m) => m !== heritier),
      );
    }

    const proposal = this.client.leaveGroup(view.groupId);
    const posted = await this.api.postEnvelope(view.groupId, envelope.encodeMls(proposal));
    view.mine.add(posted.seq);
    await this.persist();
  }

  /**
   * Supprime les conversations dont nous sommes le dernier membre.
   *
   * Un groupe à un seul membre n'est plus une conversation : c'est un groupe MLS que personne
   * ne lira jamais, et qui continuerait pourtant d'apparaître dans la liste, d'être relevé et
   * d'accepter des messages. Le laisser serait une promesse d'interlocuteur qui n'existe plus.
   *
   * La suppression est **locale**. Le serveur garde la boîte : rien ne prouverait qu'il l'ait
   * réellement effacée, et le prétendre serait pire que de ne rien dire. Nos enveloppes y
   * restent chiffrées sous des clés que plus personne ne détient.
   */
  private async dropEmptyConversations(): Promise<void> {
    let supprimees = 0;

    for (const [key, view] of this.conversations) {
      if (view.peers.length > 0) continue;

      await this.api.removeGroupMembers(view.groupId, [this.deviceId]).catch(() => {
        // Le retrait de la liste de diffusion est du confort : la conversation disparaît de
        // notre côté quoi qu'il arrive.
      });
      this.conversations.delete(key);
      supprimees += 1;
    }

    if (supprimees > 0) await this.persist();
  }

  /**
   * Révoque un de nos appareils : certificat signé, puis retrait MLS de tous les groupes.
   *
   * # Ce que cela protège, et ce que cela ne protège pas
   *
   * Contre un appareil **perdu ou hors service**, c'est la bonne réponse : il cesse de recevoir
   * et le commit de retrait re-clé l'arbre, donc il ne déchiffre plus la suite.
   *
   * Contre un appareil **volé**, cela ne suffit pas. Tous les appareils d'un compte détiennent
   * la graine — c'est la condition de leur parité — donc le voleur détient le compte et
   * s'atteste un nouvel appareil dans la foulée. La seule réponse est [`Session.rotateAccount`].
   */
  async revokeOwnDevice(deviceId: string): Promise<void> {
    if (deviceId === this.deviceId) {
      throw new Error("un appareil ne se révoque pas lui-même : révoquez-le depuis un autre.");
    }

    const revokedAt = Math.floor(Date.now() / 1000);
    const certificat = this.account.revoke(this.handle, deviceId, BigInt(revokedAt));

    await this.api.revokeDevice(deviceId, certificat, revokedAt);

    // Le retrait des groupes suit à la relève : `reconcileMembers` le fera en lisant le
    // certificat qu'on vient de déposer, comme le ferait n'importe quel autre membre. Passer
    // par le même chemin plutôt que par un raccourci garantit qu'il est réellement exercé.
    await this.poll();
  }

  /**
   * Change la clé d'identité du compte. **La seule réponse réelle à un appareil volé.**
   *
   * # Pourquoi la révocation ne suffit pas
   *
   * Chaque appareil détient la graine du compte : c'est ce qui leur donne à tous les mêmes
   * droits, sans hiérarchie ni appareil « principal ». La contrepartie est qu'un appareil volé
   * détient le compte entier. Le révoquer ne l'empêche pas d'en attester un nouveau dans la
   * seconde qui suit.
   *
   * # Ce que la rotation fait, presque gratuitement
   *
   * Changer la clé rend **invérifiables toutes les attestations existantes** d'un coup,
   * puisque chaque client les recalcule contre la clé courante du compte. La révocation totale
   * n'est pas un mécanisme séparé : c'est une conséquence. Cet appareil se ré-atteste
   * immédiatement ; les autres, légitimes, devront être ré-appairés par QR.
   *
   * # Les trois prix à payer, à annoncer avant et non après
   *
   * L'empreinte du compte change, donc tous les correspondants voient l'alerte de changement
   * d'identité. Elle est **correcte** : la clé a bien changé. Et le voleur détient la même clé
   * que nous — il peut tourner le premier. Le serveur ne peut pas les distinguer et applique
   * la première rotation valide qui se présente.
   *
   * Le troisième est apparu avec le coffre par défaut : sa clé dérive de la phrase de
   * récupération, donc **tout l'historique déjà archivé devient définitivement illisible**.
   * Tant que le coffre était optionnel, celui qui tournait sa clé savait qu'il en avait un ;
   * ce n'est plus le cas, et l'interface doit le dire avant de proposer le bouton.
   *
   * Retourne la nouvelle phrase de récupération. L'ancienne ne vaut plus rien.
   */
  async rotateAccount(): Promise<string> {
    const created = this.crypto.AccountKey.generate() as CreatedAccount;
    const rotatedAt = Math.floor(Date.now() / 1000);

    // Signé par l'ANCIENNE clé : c'est elle qui désigne sa remplaçante. Sans cette continuité,
    // n'importe qui reprendrait le handle d'autrui.
    const signature = this.account.rotate(this.handle, created.identityKey, BigInt(rotatedAt));

    await this.api.rotateAccount(this.handle, created.identityKey, signature, rotatedAt);

    this.account = this.crypto.AccountKey.restore(created.phrase);

    // Ré-attestation immédiate. Sans elle, cet appareil serait rejeté par tous les clients —
    // y compris par nous-mêmes à la relève suivante — puisque son attestation porte la
    // signature d'une clé morte.
    const authKey = await this.ancrage.cipher.authPublicKey();
    const mlsKey = this.client.signatureKey();
    await Api.register(
      this.deviceId,
      this.handle,
      authKey,
      mlsKey,
      this.account.attest(this.handle, this.deviceId, authKey, mlsKey),
    );

    // Le coffre est chiffré sous une clé dérivée de l'ancienne graine : les entrées déjà
    // déposées deviennent illisibles, définitivement. Le dire est préférable à laisser
    // découvrir un historique vide.
    if (this.vaultCipher) {
      this.vaultCipher = await vault.importVaultKey(this.account.vaultKey());
    }

    await this.persist();
    return created.phrase;
  }

  /**
   * Appaire un nouvel appareil à partir du code lu sur son écran.
   *
   * Scelle la graine du compte sous le secret X25519 et la dépose. Sans elle, le nouvel
   * appareil ne pourrait ni s'attester lui-même ni attester les suivants — il resterait
   * subordonné à celui-ci, ce qui est fragile pour un compte censé survivre à ses appareils.
   *
   * Retourne le code de confirmation, à comparer avec celui affiché en face.
   */
  async pairDevice(code: string): Promise<string> {
    const offer: PairingCode = decodePairingCode(code);

    const sealed = this.crypto.sealPairing(
      offer.publicKey,
      offer.id,
      this.account.exportSeed(),
    ) as Sealed;

    await this.api.depositPairing(offer.id, sealed.payload);
    return sealed.confirmation;
  }

  /**
   * Ajoute nos autres appareils à toutes les conversations en cours.
   *
   * Appelé à chaque relève, et **idempotent** par construction : MLS ne rattrape pas un membre
   * absent de l'arbre, et un appareil appairé mais jamais ajouté verrait la liste de ses
   * conversations sans pouvoir en déchiffrer une seule ligne. L'appareil d'origine peut se
   * fermer au milieu de la propagation ; il n'y a aucune raison de laisser une conversation
   * orpheline jusqu'à ce qu'on y repense.
   */
  private async propagateOwnDevices(): Promise<void> {
    if (this.conversations.size === 0) return;

    const mine = await this.resolve(this.handle);
    const others = mine.devices.filter((device) => device.id !== this.deviceId);
    if (others.length === 0) return;

    for (const view of this.conversations.values()) {
      await this.addMissingDevices(view, others);
      this.refreshView(view);
    }

    await this.persist();
  }

  /**
   * Ajoute à une conversation les appareils qui devraient y être et n'y sont pas.
   *
   * # L'invariant de parité
   *
   * Tous les appareils d'un compte ont le même accès partout. Un appareil absent d'une
   * conversation n'est pas « en retard » : il est cassé. Il voit la conversation dans sa liste
   * et n'en déchiffre pas une ligne, sans qu'aucune erreur ne dise pourquoi — MLS ne rattrape
   * pas un membre absent de l'arbre.
   *
   * D'où une réconciliation à chaque relève, **idempotente** : elle compare l'arbre à la liste
   * vérifiée des appareils et comble l'écart. L'appareil d'origine peut se fermer au milieu ;
   * la relève suivante reprend là où elle en était.
   */
  private async addMissingDevices(
    view: ConversationView,
    devices: AttestedDevice[],
  ): Promise<void> {
    // L'arbre MLS est la vérité sur qui est membre. S'appuyer sur un journal local
    // divergerait dès le premier échec réseau.
    const present = new Set(view.peers.map((peer) => peer.fingerprint));

    for (const device of devices) {
      if (present.has(this.crypto.accountFingerprint(device.mlsKey))) continue;

      try {
        const claimed = await this.api.claimKeyPackage(device.id);
        const invitation = this.client.invite(view.groupId, claimed.package) as Invitation;

        await this.api.addMembers(view.groupId, [device.id]);

        const tree = await this.publishAndApply(view, invitation.commit);

        const welcomed = await this.api.postEnvelope(
          view.groupId,
          envelope.encodeWelcome(invitation.welcome, tree),
        );
        view.mine.add(welcomed.seq);
      } catch (error) {
        // Stock de KeyPackages épuisé, ou appareil déjà membre : on réessaiera à la relève
        // suivante plutôt que d'interrompre toute la réconciliation.
        console.warn(`ajout de ${device.id} reporté`, error);
      }
    }
  }

  /**
   * Évince de l'arbre les appareils dont la révocation a été vérifiée.
   *
   * # Pourquoi ce n'est pas le serveur qui le fait
   *
   * Le serveur cesse bien de servir les enveloppes à un appareil révoqué, mais ce filtre ne
   * lui retire **rien** : il détient les secrets du groupe et déchiffrerait tout ce qu'il
   * obtiendrait par un autre chemin. Seul le commit de retrait re-clé l'arbre. C'est la
   * post-compromise security, et elle commence au commit, pas à la révocation.
   *
   * # Pourquoi n'importe quel membre peut le faire
   *
   * Le certificat est vérifiable par tous. Réserver l'éviction aux admins laisserait
   * l'appareil volé d'un non-admin dans le groupe jusqu'au retour en ligne d'un admin —
   * exactement le délai que la révocation existe pour supprimer.
   *
   * # Ce que cela ne règle pas
   *
   * Un appareil volé détient la graine du compte, donc peut s'en attester un nouveau. Le
   * retrait ne vaut que contre la perte ; contre le vol, la seule réponse est
   * [`Session.rotateAccount`].
   */
  private async reconcileMembers(): Promise<void> {
    for (const view of this.conversations.values()) {
      // Toutes les révocations vérifiées, tous comptes confondus — y compris le nôtre.
      const revoked = new Map<string, string>();
      for (const account of [...view.accounts, await this.resolve(this.handle)]) {
        for (const device of account.revoked) {
          revoked.set(this.crypto.accountFingerprint(device.mlsKey), device.id);
        }
      }
      if (revoked.size === 0) continue;

      const keys = this.client.peerSignatureKeys(view.groupId) as Uint8Array[];

      for (const key of keys) {
        const deviceId = revoked.get(this.crypto.accountFingerprint(key));
        if (deviceId === undefined) continue;

        try {
          const commit = this.client.removeMember(view.groupId, key);
          await this.publishAndApply(view, commit);
          await this.api.removeGroupMembers(view.groupId, [deviceId]);
        } catch (error) {
          // Un autre membre nous a peut-être devancés : l'appareil n'est alors plus dans
          // l'arbre et l'état voulu est atteint. On réessaiera au prochain tour sinon.
          console.warn(`éviction de ${deviceId} reportée`, error);
        }
      }

      this.refreshView(view);
    }

    await this.persist();
  }

  /**
   * Publie un commit **puis** l'applique, et retourne l'arbre de ratchet à jour.
   *
   * L'ordre n'est pas un détail de style. Appliquer avant de publier est irrattrapable : si la
   * publication échoue, nous avons changé d'epoch pendant que les autres restent à l'ancienne,
   * et le commit qui les aurait réconciliés n'existe plus nulle part. Le groupe meurt en
   * silence — plus personne ne déchiffre, et rien ne dit pourquoi.
   *
   * Ce helper existe pour qu'il n'y ait qu'un seul endroit où cet ordre peut être inversé.
   */
  private async publishAndApply(view: ConversationView, commit: Uint8Array): Promise<Uint8Array> {
    const posted = await this.api.postEnvelope(view.groupId, envelope.encodeMls(commit));

    // Déjà appliquée localement : on la note pour ne pas la relire, sans avancer le curseur
    // au-delà — les enveloppes intermédiaires restent à traiter.
    view.mine.add(posted.seq);

    return this.client.applyPending(view.groupId);
  }

  /** Resynchronise la vue affichée avec l'état réel du groupe. */
  private refreshView(view: ConversationView): void {
    view.peers = this.client.peerFingerprints(view.groupId) as Peer[];
    view.epoch = this.client.epoch(view.groupId);
  }

  /**
   * Signale les appareils apparus chez un correspondant depuis la dernière fois.
   *
   * C'est **cette notification, et non l'empreinte, qui détecte un appareil hostile**.
   * L'empreinte porte sur la clé du compte et reste volontairement stable : la faire changer
   * à chaque appareil ajouté obligerait à revérifier après chaque événement légitime, et
   * serait ignorée en quelques semaines.
   *
   * Ce que cela ne couvre pas : un appareil ajouté par un compte réellement compromis. Il est
   * dûment attesté, donc indiscernable d'un ajout légitime. Seul l'utilisateur peut dire s'il
   * possède bien cet appareil — d'où l'affichage, plutôt qu'un verdict automatique.
   */
  async newDevicesOf(handle: string): Promise<string[]> {
    const peer = await this.resolve(handle);
    const known = new Set(this.knownDevices[handle] ?? []);
    const fresh = peer.devices.map((device) => device.id).filter((id) => !known.has(id));

    if (fresh.length > 0) {
      this.knownDevices[handle] = peer.devices.map((device) => device.id);
      await this.persist();
    }
    return fresh;
  }

  async send(view: ConversationView, text: string): Promise<void> {
    await this.sendContent(view, { kind: "text", text });
  }

  /**
   * Chiffre le fichier, le dépose, puis envoie son descripteur dans un message MLS.
   *
   * L'ordre compte : la pièce jointe doit exister sur le serveur avant que le message qui la
   * référence ne parte, sinon le destinataire reçoit un lien vers un fichier absent.
   */
  async sendAttachment(view: ConversationView, file: File): Promise<void> {
    const ref = await encryptAndUpload(this.api, view.groupId, file);
    await this.sendContent(view, { kind: "attachment", ref });
  }

  /** Récupère et déchiffre une pièce jointe reçue. */
  openAttachment(view: ConversationView, ref: AttachmentRef): Promise<Blob> {
    return downloadAndDecrypt(this.api, view.groupId, ref);
  }

  /**
   * Marque la conversation comme vue jusqu'à son dernier message.
   *
   * Appelée par l'affichage, pas par la relève : « lu » désigne ce qu'une personne a eu sous
   * les yeux. L'accusé lui-même part au tour suivant, avec les autres.
   */
  markRead(view: ConversationView): void {
    view.readCursor = Math.max(view.readCursor, view.contentCursor);
  }

  /** État à afficher sur un message qu'on a envoyé : envoyé, reçu, lu. */
  statusOf(view: ConversationView, seq: number): "sent" | "delivered" | "read" {
    const handles = [...new Set(view.accounts.map((account) => account.handle))].filter(
      (handle) => handle !== this.handle,
    );
    return statusOf(view.receipts, handles, seq, this.signals.readReceipts);
  }

  /** Correspondants en train d'écrire, expirés exclus. */
  typingIn(view: ConversationView): string[] {
    view.typing = fresh(view.typing, Date.now());
    return [...new Set(view.typing.map((entry) => entry.handle))].filter(
      (handle) => handle !== this.handle,
    );
  }

  /**
   * Signale qu'on est en train d'écrire.
   *
   * # Ce qui ne se produit pas ici
   *
   * Rien n'est stocké, ni chez nous ni chez le serveur. Le signal est chiffré sous la clé
   * d'epoch du groupe, déposé sans signature d'appareil, relayé aux membres connectés, puis
   * oublié. C'est la raison d'être du canal séparé : `envelopes` n'est jamais purgée, et y
   * faire transiter la frappe conserverait indéfiniment la trace de qui a hésité.
   *
   * # Ce que le serveur apprend malgré tout
   *
   * Qu'un dépôt a lieu vers ce groupe. À deux, il en déduit qu'un des deux membres écrit.
   * Le sealed sender cache *qui*, pas *que* — seul le réglage le supprime vraiment.
   */
  async notifyTyping(view: ConversationView): Promise<void> {
    if (!this.signals.typingIndicator) return;

    const posting = this.signalPosting(view);
    // Sans clé de dépôt, il faudrait signer la requête : le serveur apprendrait qui écrit,
    // en temps réel, pour une fonctionnalité de confort. On s'abstient plutôt.
    if (!posting) return;

    const maintenant = Date.now();
    if (view.typingSentAt !== undefined && maintenant - view.typingSentAt < TYPING_DEBOUNCE_MS) {
      return;
    }
    view.typingSentAt = maintenant;

    const key = this.client.signalKey(view.groupId);
    const payload = await sealTyping(key, this.handle);
    await this.emitSignal(view.groupId, payload, posting);
  }

  /**
   * Ouvre un signal reçu par le flux temps réel.
   *
   * Un signal illisible est le cas ordinaire — il a été émis sous l'epoch précédente et est
   * arrivé après le commit — et n'est donc pas remonté comme une erreur.
   */
  async absorbSignal(groupId: Uint8Array, payload: Uint8Array): Promise<void> {
    const view = this.conversations.get(toHex(groupId));
    if (!view) return;

    const handle = await openTyping(this.client.signalKey(view.groupId), payload);
    if (handle === undefined || handle === this.handle) return;

    const maintenant = Date.now();
    view.typing = [...without(fresh(view.typing, maintenant), handle), { handle, at: maintenant }];
  }

  /**
   * Réagit à un message, ou retire sa réaction avec un emoji vide.
   *
   * Contrairement aux accusés, une réaction **est** un message : elle s'affiche, elle
   * s'archive, et son auteur l'assume. C'est pourquoi elle ne passe pas par `isControl`.
   */
  reactTo(view: ConversationView, target: number, emoji: string): Promise<void> {
    return this.sendContent(view, { kind: "reaction", target, emoji });
  }

  /** Répond en citant un message antérieur. */
  replyTo(view: ConversationView, target: number, text: string): Promise<void> {
    return this.sendContent(view, { kind: "reply", target, text });
  }

  /** Réglages de signalisation, tels qu'ils s'appliquent maintenant. */
  signalSettings(): SignalSettings {
    return { ...this.signals };
  }

  /**
   * Change un réglage de signalisation.
   *
   * Désactiver les accusés de lecture cesse aussi de montrer ceux des autres : voir sans être
   * vu serait exactement ce que le réglage prétend empêcher.
   *
   * La présence est le seul de ces réglages qui doive **remonter au serveur** : lui seul peut
   * cesser d'enregistrer. Un réglage qui se contenterait de ne plus afficher laisserait le
   * registre se remplir quand même, ce qui n'est pas ce que l'utilisateur a demandé.
   */
  async setSignalSetting<K extends keyof SignalSettings>(
    key: K,
    value: SignalSettings[K],
  ): Promise<void> {
    if (key === "presence") {
      await this.api.setPresenceOptout(!value);
      // Ce que le serveur vient d'effacer ne doit pas rester à l'écran jusqu'à la relève.
      this.presence = new Map();
    }

    this.signals[key] = value;
    await this.persist();
  }

  private async sendContent(view: ConversationView, body: content.Content): Promise<void> {
    // Rembourré **avant** chiffrement : c'est la taille du texte clair qui détermine celle du
    // chiffré. Rembourrer après ne cacherait rien de plus et coûterait autant.
    const encoded = padding.pad(content.encode(body));

    const ciphertext = this.client.encrypt(view.groupId, encoded);
    const { seq } = await this.api.postEnvelope(
      view.groupId,
      envelope.encodeMls(ciphertext),
      this.posting(view),
    );

    // On note la séquence pour ne pas tenter de la relire, sans toucher au curseur : les
    // enveloppes déposées entre-temps par d'autres restent à traiter.
    view.mine.add(seq);

    // Le throttle repart de zéro : après un envoi, la frappe suivante ouvre un nouveau message
    // et doit être annoncée tout de suite. La laisser sous le seuil ferait attendre jusqu'à une
    // seconde et demie avant que le correspondant ne voie qu'on répond de nouveau.
    view.typingSentAt = undefined;

    // Le trafic de protocole ne rejoint ni le fil ni le coffre. Il emprunte le même canal
    // chiffré que les messages — c'est tout l'intérêt — mais ce n'est pas une conversation.
    if (content.isControl(body)) {
      await this.persist();
      return;
    }

    const message: Message = { seq, sender: this.deviceId, content: body, mine: true };
    view.messages.push(message);
    await this.archive(view, [message]);
    await this.persist();
  }

  /**
   * Relève les nouveaux messages et rejoint les conversations où l'on nous a ajoutés.
   *
   * Le polling est volontairement simple. Un vrai client utiliserait un WebSocket ou du
   * push — ce qui ne changerait rien à la cryptographie, seulement à la latence et à la
   * consommation.
   */
  /**
   * Ouvre le flux temps réel, et le maintient.
   *
   * # Ce que cela ne change pas
   *
   * La correction. Le flux ne fait que déclencher plus tôt une relève qui serait de toute
   * façon arrivée. Un navigateur qui bloque la connexion, un proxy qui la coupe, un serveur
   * qui la refuse : l'application continue de fonctionner, simplement au rythme de la relève
   * périodique.
   *
   * C'est une contrainte de conception, pas une observation : dès que le flux deviendrait
   * nécessaire à la correction, il faudrait le rendre fiable — et on aurait reconstruit un
   * transport au-dessus du transport.
   */
  startStream(onChange: () => void): void {
    this.gateway?.close();

    this.gateway = new Gateway(
      this.api,
      {
        onEnvelope: (groupId) => {
          // On ne se fie pas au numéro annoncé : on relève par le chemin normal, qui revérifie
          // l'appartenance et fait avancer le curseur d'une seule main.
          if (!this.conversations.has(toHex(groupId))) return;
          void this.poll().then(onChange).catch(() => {});
        },
        onSignal: (groupId, payload) => {
          void this.absorbSignal(groupId, payload).then(onChange).catch(() => {});
        },
      },
      // Évalués à chaque (re)connexion, jamais figés : entre deux tentatives, la relève a pu
      // avancer, et un curseur périmé ferait réannoncer des séquences déjà lues.
      () =>
        [...this.conversations.values()].map((view) => ({
          groupId: view.groupId,
          seq: view.cursor,
        })),
      this.crypto.gatewayChallenge,
    );

    this.gateway.start();
    this.syncScope();
  }

  stopStream(): void {
    this.gateway?.close();
    this.gateway = undefined;
  }

  /**
   * Aligne la portée de la session sur les conversations connues.
   *
   * Remplace la réouverture complète qu'imposait le flux SSE, dont le serveur figeait la liste
   * à la connexion. L'ajustement est incrémental : une conversation découverte coûte une trame,
   * plus une reconnexion avec son défi, sa signature et son rattrapage.
   *
   * Sans appel : une conversation créée après l'ouverture n'est jamais abonnée, et ses
   * indicateurs de frappe n'arrivent pas — panne silencieuse, puisque tout le reste continue
   * de fonctionner par la relève.
   */
  private syncScope(): void {
    if (!this.gateway) return;

    for (const view of this.conversations.values()) this.gateway.subscribe(view.groupId);
  }

  poll(): Promise<void> {
    // Une relève déjà en cours est renvoyée telle quelle : l'appelant attend la même, plutôt
    // que d'en lancer une concurrente.
    this.polling ??= this.pollOnce().finally(() => {
      this.polling = null;
    });
    return this.polling;
  }

  private async pollOnce(): Promise<void> {
    // Le stock de clés d'accueil se reconstitue tout seul. Sans cela, il s'épuise en
    // silence et l'appareil devient injoignable sans que rien ne le signale — exactement
    // le genre de tâche d'entretien qu'un utilisateur ne devrait jamais avoir à porter.
    await this.replenishKeyPackagesIfLow().catch((error) => {
      console.warn("réapprovisionnement des clés d'accueil impossible", error);
    });

    const connues = this.conversations.size;
    await this.discoverNewConversations();

    // Une conversation découverte doit entrer dans la portée de la session, faute de quoi ses
    // indicateurs de frappe n'arriveraient jamais. `subscribe` étant idempotent, on peut
    // resynchroniser sans comparer.
    if (this.conversations.size !== connues) this.syncScope();

    // Rattrape les appareils du compte absents d'une conversation. Idempotent : sans ce
    // rattrapage, une propagation interrompue laisserait un appareil sourd indéfiniment.
    await this.propagateOwnDevices().catch((error: unknown) => {
      console.warn("propagation vers nos autres appareils reportée", error);
    });

    // Évince les appareils dont la révocation est certifiée. Après la propagation : ajouter
    // d'abord évite qu'un appareil légitime attende un tour de plus derrière une éviction qui
    // échoue.
    await this.reconcileMembers().catch((error: unknown) => {
      console.warn("éviction des appareils révoqués reportée", error);
    });

    // Après les évictions : un groupe peut venir de perdre son dernier autre membre.
    await this.dropEmptyConversations();

    // Une tête par conversation et par session : le contrôle porte sur l'existence d'une
    // bifurcation, pas sur son instant.
    for (const view of this.conversations.values()) {
      await this.gossip(view).catch((error: unknown) => {
        console.warn("diffusion de la tête de journal reportée", error);
      });

      await this.sharePostingKey(view).catch((error: unknown) => {
        console.warn("diffusion de la clé de dépôt reportée", error);
      });
    }

    for (const view of this.conversations.values()) {
      const envelopes = await this.api.fetchEnvelopes(view.groupId, view.cursor);
      const avant = view.messages.length;

      for (const row of envelopes) {
        try {
          if (!view.mine.has(row.seq)) this.absorb(view, row.seq, row.payload);
        } catch (error) {
          // Un message illisible ne bloque pas la conversation. Le curseur avance quand même :
          // une enveloppe qu'on ne sait pas lire aujourd'hui — message déjà traité, enveloppe
          // corrompue, commit qu'on a soi-même émis — ne deviendra pas lisible demain, et s'y
          // arrêter figerait la conversation pour de bon.
          console.warn(`enveloppe ${row.seq} ignorée`, error);
        }
        view.cursor = Math.max(view.cursor, row.seq);
      }

      view.epoch = this.client.epoch(view.groupId);
      view.peers = this.client.peerFingerprints(view.groupId) as Peer[];

      await this.archive(view, view.messages.slice(avant));

      // Persister ICI, avant tout nouvel appel réseau.
      //
      // `process` fait avancer le ratchet même lorsqu'il finit par échouer. Si une erreur
      // ultérieure — une résolution de compte, une coupure — empêchait d'enregistrer le
      // curseur, l'état MLS repartirait en avance sur lui : on relirait des enveloppes que le
      // ratchet a déjà dépassées, et MLS les refuserait pour de bon. Le message serait perdu
      // sans que rien ne le signale.
      //
      // Le curseur appartient à l'état cryptographique, pas à l'affichage. Les deux avancent
      // ensemble ou pas du tout.
      await this.persist();

      // La résolution des comptes est cosmétique et passe par le réseau : elle vient après,
      // et son échec ne doit rien annuler.
      try {
        view.accounts = await this.resolvePeers(view);
      } catch (error) {
        console.warn("comptes non résolus pour cette conversation", error);
      }

      // En dernier : un accusé est une enveloppe, et l'émettre avant d'avoir tout absorbé
      // annoncerait un numéro qu'on n'a pas encore traité.
      await this.acknowledge(view).catch((error: unknown) => {
        console.warn("accusé reporté", error);
      });
    }

    await this.refreshPresence().catch((error: unknown) => {
      console.warn("présence non relevée", error);
    });
  }

  /**
   * Relève la présence de tous les correspondants connus, en une requête.
   *
   * # Pourquoi c'est ici et pas sur un minuteur à part
   *
   * Parce qu'un minuteur dédié redonnerait au serveur le journal d'activité à la seconde que le
   * flux lui a précisément retiré — pour un point de couleur. La relève existe déjà, elle passe
   * toutes les trente secondes, et c'est une granularité honnête pour cette information.
   *
   * Et pas non plus par le flux : le point vert en dépendrait, or un flux bloqué par un proxy
   * afficherait alors tout le monde hors ligne. Une interface fausse est pire qu'une interface
   * en retard.
   */
  private async refreshPresence(): Promise<void> {
    if (!this.signals.presence) return;

    const handles = [
      ...new Set(
        [...this.conversations.values()]
          .flatMap((view) => view.accounts.map((account) => account.handle))
          .filter((handle) => handle !== this.handle),
      ),
    ];
    if (handles.length === 0) return;

    // Le serveur plafonne à 64 par requête. Au-delà, on relève les premiers : c'est une
    // limite visible plutôt qu'un 400 silencieux, et un carnet de cette taille demanderait
    // de toute façon un autre découpage.
    const { now, accounts } = await this.api.presence(handles.slice(0, 64));

    this.presenceNow = now * 1000;
    this.presence = new Map(accounts.map((entry) => [entry.handle, entry.last_seen * 1000]));
  }

  /**
   * Annonce ce qu'on a reçu, et ce qu'on a lu.
   *
   * # Pourquoi rien ne part la plupart du temps
   *
   * `pending` ne rend un numéro que s'il dépasse ce que **notre compte** a déjà accusé — et
   * nos propres accusés nous reviennent comme aux autres. Un tour de relève sans nouveauté
   * n'émet donc rien, ce qui est la seule chose qui empêche la conversation de se nourrir
   * d'elle-même indéfiniment.
   */
  private async acknowledge(view: ConversationView): Promise<void> {
    const livre = pending(view.receipts, this.handle, "delivered", view.contentCursor);
    if (livre !== undefined) {
      record(view.receipts, this.handle, "delivered", livre);
      await this.sendContent(view, { kind: "receipt", state: "delivered", seq: livre });
    }

    // Le réglage coupe l'émission à la source. Il coupe aussi l'affichage, dans `statusOf` :
    // la réciprocité doit tenir même si l'un des deux endroits est oublié.
    if (!this.signals.readReceipts) return;

    const lu = pending(view.receipts, this.handle, "read", view.readCursor);
    if (lu !== undefined) {
      record(view.receipts, this.handle, "read", lu);
      await this.sendContent(view, { kind: "receipt", state: "read", seq: lu });
    }
  }

  private absorb(view: ConversationView, seq: number, payload: Uint8Array): void {
    const parsed = envelope.decode(payload);

    // Un Welcome pour un groupe qu'on a déjà rejoint : rien à faire.
    if (parsed.kind === "welcome") return;

    // Les clés révoquées **vérifiées** de tous les comptes de la conversation. Sans elles, la
    // politique de groupe refuse le retrait d'un appareil volé commité par un non-admin —
    // c'est-à-dire précisément le cas qu'elle existe pour permettre.
    const revoked = view.accounts.flatMap((account) => account.revokedKeys);

    const incoming = this.client.process(view.groupId, parsed.payload, revoked) as Incoming;
    if (incoming.kind !== "application") return;

    const decode = content.decode(padding.unpad(incoming.plaintext));

    // Le trafic de protocole est traité puis écarté du fil : l'afficher noierait la
    // conversation sous des bulles vides.
    if (content.isControl(decode)) {
      if (decode.kind === "gossip") void this.checkGossip(decode.head);
      // La clé de dépôt vient de MLS, donc d'un membre authentifié : le serveur l'a
      // transportée sans pouvoir la lire ni la remplacer.
      if (decode.kind === "posting-key") view.postingKey ??= decode.key;
      // Le handle vient du credential MLS, pas du corps du message : un membre ne peut pas
      // accuser réception au nom d'un autre. C'est aussi ce qui fait fonctionner la
      // déduplication entre les appareils d'un même compte — ils portent le même handle.
      if (decode.kind === "receipt" && incoming.sender) {
        record(view.receipts, incoming.sender, decode.state, decode.seq);
      }
      return;
    }

    // L'auteur vient d'envoyer : il n'écrit plus. Aucun signal « a cessé d'écrire » n'est
    // nécessaire — le message lui-même en est la preuve, et il ne peut pas se perdre puisqu'on
    // ne l'attend pas. Sans cela, l'expéditeur paraît continuer d'écrire tout le temps du TTL
    // après avoir appuyé sur Entrée.
    if (incoming.sender) view.typing = without(view.typing, incoming.sender);

    view.messages.push({
      seq,
      sender: incoming.sender,
      content: decode,
      mine: false,
    });

    // Seuls les messages font avancer ce curseur. Voir sa définition : c'est ce qui empêche
    // les accusés de s'engendrer les uns les autres.
    view.contentCursor = Math.max(view.contentCursor, seq);
  }

  /**
   * Détecte les groupes où le serveur nous a déclaré membre et y cherche **notre** Welcome.
   *
   * Un groupe en contient plusieurs dès qu'un compte a plusieurs appareils : un par membre
   * ajouté. Ils sont indiscernables de l'extérieur — c'est voulu, le serveur n'a pas à savoir
   * lequel s'adresse à qui. Il faut donc les essayer tous et garder celui qui s'ouvre.
   *
   * Prendre le premier venu échoue avec « No matching key package was found » : le Welcome
   * était chiffré pour le KeyPackage d'un autre appareil.
   */
  private async discoverNewConversations(): Promise<void> {
    const groups = await this.api.listGroups();

    for (const hex of groups) {
      if (this.conversations.has(hex)) continue;

      const groupId = hexToBytes(hex);
      const envelopes = await this.api.fetchEnvelopes(groupId, 0);

      for (const row of envelopes) {
        let parsed: envelope.Parsed;
        try {
          parsed = envelope.decode(row.payload);
        } catch {
          continue;
        }
        if (parsed.kind !== "welcome") continue;

        try {
          const joined = this.client.join(parsed.welcome, parsed.ratchetTree);
          this.conversations.set(hex, {
            groupId: joined,
            key: hex,
            messages: [],
            peers: this.client.peerFingerprints(joined) as Peer[],
            accounts: [],
            epoch: this.client.epoch(joined),
            cursor: row.seq,
            mine: new Set<number>(),
            ...freshSignalState(),
        ...freshSignalState(),
          });
          break;
        } catch {
          // Welcome destiné à un autre appareil : rien d'anormal, on essaie le suivant.
        }
      }
    }
  }
}

function hexToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export { fromBase64 };


/**
 * Importe la clé du coffre depuis le compte.
 *
 * Isolé en fonction pour que `Session.restore` reste lisible : la dérivation elle-même est
 * dans `crypto-core`, ce module ne fait que la transformer en `CryptoKey`.
 *
 * Retourne `null` plutôt que de lever. Depuis que le coffre est actif par défaut, cet appel est
 * sur le chemin d'ouverture de **toute** session : y laisser une exception rendrait les messages
 * inaccessibles parce que leur sauvegarde a échoué. On perd l'archivage, jamais la conversation.
 */
async function vaultCipherOf(_crypto: Crypto, account: AccountKey): Promise<CryptoKey | null> {
  try {
    return await vault.importVaultKey(account.vaultKey());
  } catch (error) {
    console.warn("clé de coffre indisponible : archivage désactivé pour cette session", error);
    return null;
  }
}

/**
 * Ce que le démarrage propose : une migration, à laquelle il ne procède pas.
 *
 * Elle enregistre un appareil et **en révoque un autre**. Ce sont des gestes de compte, visibles
 * du serveur et des correspondants, et rien dans « ouvrir l'application » ne les demande. Les
 * exécuter d'office reviendrait à décider à la place de quelqu'un qui n'a rien demandé.
 *
 * Différer ne coûte rien : l'application continue exactement comme avant, et la proposition
 * revient au démarrage suivant.
 */
export interface MigrationProposee {
  /**
   * A-t-elle déjà commencé ?
   *
   * Change ce qu'il faut dire, pas ce qu'il faut faire : deux appareils sont alors actifs — un
   * état sain, seulement redondant — et l'utilisateur mérite de savoir pourquoi il en voit deux
   * dans ses réglages.
   */
  reprise: boolean;
  executer(progres?: (etape: string) => void): Promise<Session>;
}

/**
 * Ce qu'il faut faire au démarrage.
 *
 * # Pourquoi ce n'est pas dans `Session.restore`
 *
 * Une migration tient **deux** sessions ouvertes en même temps — l'ancienne est la seule membre
 * des groupes, donc la seule à pouvoir y introduire la nouvelle — et `restore` en rend une.
 *
 * # Le repli n'est pas un échec silencieux
 *
 * Quand la migration est impossible — coffre coupé, ou stockage natif occupé par un autre compte
 * — l'application continue sur IndexedDB et `repli` porte la raison. La taire laisserait croire à
 * une durabilité qui n'existe pas.
 */
export async function demarrer(
  /**
   * De quoi ouvrir le verrou : le mot de passe saisi, ou la clé maîtresse rendue par l'invite
   * du système. Les deux mènent au même endroit, par des chemins qui n'ont pas la même entrée.
   */
  ouverture?: string | CryptoKey,
): Promise<{ session: Session | null; migration?: MigrationProposee; repli?: string }> {
  if (!isTauri()) return { session: await Session.restore(ouverture) };

  const natif = ancrageNatif();
  const web = await ancrageWebExistant();

  const decision = decider(await presenceDe(web), await presenceDe(natif));

  if (decision.quoi === "repli") {
    return { session: web ? await Session.ouvrir(web, ouverture) : null, repli: decision.raison };
  }

  if (decision.quoi !== "demarrer" && decision.quoi !== "reprendre") {
    return { session: await Session.restore(ouverture) };
  }

  // L'ancienne session doit être ouverte : elle seule est membre des groupes. Un verrou posé
  // impose donc de proposer la migration après la saisie, pas avant.
  const ancienne = web ? await Session.ouvrir(web, ouverture) : null;
  if (!ancienne) return { session: await Session.restore(ouverture) };

  return {
    session: ancienne,
    migration: {
      reprise: decision.quoi === "reprendre",
      executer: (progres) => ancienne.migrerVersNatif(decision, natif, progres),
    },
  };
}

/** Ce qu'un ancrage révèle sans être ouvert : de quoi décider, et rien de plus. */
async function presenceDe(ancrage: Ancrage | undefined): Promise<Presence | undefined> {
  const stored = await ancrage?.store.load();
  if (!stored?.state) return undefined;

  return { handle: stored.handle, vaultEnabled: stored.vaultEnabled };
}
