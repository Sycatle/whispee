/* tslint:disable */
/* eslint-disable */

/**
 * Poignée du compte pseudonyme.
 *
 * Séparée de [`Client`] à dessein : un compte survit à ses appareils, et un appareil peut
 * exister le temps d'un appairage sans détenir la clé du compte. Les fusionner ferait croire
 * que l'un implique l'autre.
 *
 * **Cet objet détient la clé racine du compte.** La perdre équivaut à perdre le compte ; la
 * divulguer équivaut à le céder.
 */
export class AccountKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Signe l'appartenance d'un appareil à ce compte.
     */
    attest(handle: string, device_id: string, auth_key: Uint8Array, mls_key: Uint8Array): Uint8Array;
    /**
     * Graine à transmettre à un appareil qu'on appaire. **Vaut le compte entier.**
     */
    exportSeed(): Uint8Array;
    /**
     * Empreinte du compte, à comparer hors bande.
     *
     * Stable quand le compte gagne ou perd un appareil : la détection d'un appareil hostile
     * passe par la notification d'ajout, pas par un changement d'empreinte qui serait ignoré
     * à force de se produire légitimement.
     */
    fingerprint(): string;
    /**
     * Reconstruit le compte depuis la graine reçue lors d'un appairage.
     */
    static fromSeed(seed: Uint8Array): AccountKey;
    /**
     * Crée un compte et retourne `{phrase, identityKey}`.
     */
    static generate(): any;
    identityKey(): Uint8Array;
    /**
     * Reconstruit le compte depuis sa phrase de récupération.
     */
    static restore(phrase: string): AccountKey;
    /**
     * Signe la révocation d'un appareil de ce compte.
     *
     * Le certificat est vérifiable par n'importe qui détenant la clé publique du compte :
     * c'est ce qui permet à un **autre** membre du groupe de commiter le retrait sans croire
     * le serveur sur parole.
     */
    revoke(handle: string, device_id: string, revoked_at: bigint): Uint8Array;
    /**
     * Signe le passage de ce compte à une nouvelle clé d'identité.
     *
     * À appeler sur l'**ancien** compte, qui désigne ainsi son successeur.
     *
     * C'est la seule réponse réelle à un appareil volé : celui-ci détient la graine, donc le
     * compte entier, et le révoquer ne l'empêche pas d'en attester un nouveau. La rotation,
     * elle, rend invérifiables toutes les attestations d'un coup.
     */
    rotate(handle: string, new_identity_key: Uint8Array, rotated_at: bigint): Uint8Array;
    /**
     * Clé symétrique du coffre de sauvegarde, dérivée à la demande.
     */
    vaultKey(): Uint8Array;
}

/**
 * Poignée unique côté JavaScript : une identité d'appareil et ses conversations.
 *
 * Les conversations sont indexées par identifiant de groupe plutôt qu'exposées comme objets
 * séparés. Manipuler deux poignées appariées depuis JS — une identité, une conversation —
 * invite à les mélanger, et chiffrer avec la mauvaise identité est une erreur silencieuse.
 */
export class Client {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Applique le commit préparé par `invite`, une fois celui-ci publié.
     *
     * Retourne l'arbre de ratchet à jour, à transmettre à l'invité avec son Welcome. Il ne
     * peut pas être produit plus tôt : tant que le commit n'est pas appliqué, l'arbre ne
     * contient pas le nouveau membre et son Welcome serait rejeté.
     */
    applyPending(group_id: Uint8Array): Uint8Array;
    /**
     * Commite les propositions en attente — typiquement la demande de sortie d'un membre.
     */
    commitPending(group_id: Uint8Array): Uint8Array;
    /**
     * Identifiants des conversations ouvertes, à persister à côté de l'état pour pouvoir
     * les recharger via [`Client::restore`].
     */
    conversationIds(): Uint8Array[];
    /**
     * Crée une identité d'appareil.
     *
     * `name` est transporté en clair dans le credential MLS et visible du serveur comme de
     * tous les membres du groupe. N'y mettez rien de sensible.
     */
    static create(name: string): Client;
    /**
     * Crée une conversation et retourne son identifiant de groupe.
     */
    createConversation(): Uint8Array;
    /**
     * Crée un groupe administré. Le créateur en est l'admin, seul et unique.
     *
     * À réserver aux vrais groupes. Un 1-to-1 doit passer par `createConversation` : des rôles
     * n'y ont aucun sens, et le groupe plat est la forme correcte.
     */
    createGroup(admin: string): Uint8Array;
    encrypt(group_id: Uint8Array, plaintext: Uint8Array): Uint8Array;
    /**
     * Epoch courante du groupe. Deux membres à des epochs différentes ne peuvent pas se
     * lire : c'est la première chose à regarder quand un message ne passe pas.
     */
    epoch(group_id: Uint8Array): bigint;
    /**
     * Exporte l'état complet des sessions.
     *
     * **Ce blob contient les clés privées en clair.** Il ne doit jamais atteindre
     * `localStorage`, ni un backup, ni le serveur. Le chiffrer d'abord avec une clé
     * `CryptoKey` non-extractable détenue dans IndexedDB.
     *
     * Ne jamais restaurer un état *ancien* : cela fait reculer le groupe d'epoch et rejoue
     * des clés déjà utilisées, ce qui détruit la forward secrecy.
     */
    exportState(): Uint8Array;
    fingerprint(): string;
    /**
     * Prépare l'ajout d'un membre. Retourne `{commit, welcome}` **sans rien appliquer**.
     *
     * Les deux parties ne vont pas au même endroit : le `commit` aux membres déjà présents,
     * le `welcome` au seul invité.
     *
     * Le groupe reste à son epoch actuelle jusqu'à [`Client::applyPending`]. Publier d'abord,
     * appliquer ensuite : l'inverse casse le groupe sans recours si la publication échoue —
     * l'émetteur aurait changé d'epoch, les autres non, et le commit serait perdu.
     */
    invite(group_id: Uint8Array, key_package: Uint8Array): any;
    /**
     * Rejoint une conversation depuis un Welcome. Retourne l'identifiant de groupe.
     */
    join(welcome: Uint8Array, ratchet_tree: Uint8Array): Uint8Array;
    /**
     * Demande à quitter le groupe. Retourne une **proposition**, pas un commit.
     *
     * La RFC 9420 interdit de se retirer soi-même dans un commit qu'on génère : un autre
     * membre doit la reprendre via `commitPending`. Conséquence à afficher honnêtement —
     * tant que personne ne commite, le départ n'a pas eu lieu et la conversation continue
     * d'être lue.
     */
    leaveGroup(group_id: Uint8Array): Uint8Array;
    /**
     * Nom de cet appareil, tel qu'inscrit dans le credential MLS.
     */
    name(): string;
    /**
     * Empreintes des autres membres, à comparer hors bande.
     *
     * L'interface doit rendre cette comparaison possible et compréhensible. Sans elle, un
     * serveur malveillant peut se placer au milieu de deux sessions parfaitement chiffrées
     * sans qu'aucune vérification cryptographique ne le détecte.
     */
    peerFingerprints(group_id: Uint8Array): any;
    /**
     * Clés de signature MLS des autres membres, telles qu'elles figurent dans l'arbre.
     *
     * Vient de l'état authentifié, pas du serveur. C'est ce qui permet au client de constater
     * qu'un membre de l'arbre ne figure plus parmi les appareils actifs de son compte.
     */
    peerSignatureKeys(group_id: Uint8Array): any;
    /**
     * Traite un message entrant : applicatif ou changement de groupe.
     *
     * Le résultat doit être traité dans les deux cas. Ignorer un `groupChanged` laisse
     * l'appareil à une epoch périmée, et tout ce qui suit devient indéchiffrable.
     */
    process(group_id: Uint8Array, message: Uint8Array, revoked: Uint8Array[]): any;
    /**
     * Produit un KeyPackage à publier sur le serveur.
     *
     * **À usage unique.** Le serveur doit le retirer du stock dès qu'il le sert, et
     * l'appelant doit en réapprovisionner régulièrement : sans stock disponible, plus
     * personne ne peut ouvrir de conversation avec cet appareil.
     */
    publishKeyPackage(): Uint8Array;
    /**
     * Prépare le retrait d'un membre, désigné par sa clé de signature MLS.
     *
     * C'est ce retrait — et non le filtrage côté serveur — qui prive effectivement l'appareil
     * de la suite : le commit re-clé l'arbre. Même discipline que `invite` : publier, puis
     * `applyPending`.
     */
    removeMember(group_id: Uint8Array, mls_key: Uint8Array): Uint8Array;
    /**
     * Reconstruit un client depuis un état exporté.
     *
     * `groupIds` est la liste des conversations à recharger. Le stockage MLS ne fournit pas
     * d'énumération : c'est à l'appelant de conserver cette liste, à côté de l'état.
     *
     * Ne restaurez **jamais** un état plus ancien que le dernier exporté : les groupes
     * reculeraient d'epoch et rejoueraient des clés déjà utilisées. Un état MLS n'est pas
     * une sauvegarde ordinaire — il ne doit exister qu'une seule copie vivante.
     */
    static restore(state: Uint8Array, group_ids: Uint8Array[]): Client;
    /**
     * Roster du groupe : `{admin, moderators}`, ou `null` si le groupe est plat.
     */
    roster(group_id: Uint8Array): any;
    /**
     * Remplace les rôles du groupe. Comme tout commit, à publier avant `applyPending`.
     *
     * Passer un `admin` différent de l'actuel **transmet le groupe** : l'émetteur ne pourra
     * pas se le reprendre.
     */
    setRoles(group_id: Uint8Array, admin: string, moderators: string[]): Uint8Array;
    /**
     * Clé symétrique du canal éphémère de ce groupe, pour l'epoch courante.
     *
     * **Ces octets ne doivent servir qu'aux signaux jetables.** Ils ne passent pas par le
     * ratchet applicatif, donc ils n'offrent aucune forward secrecy à l'intérieur d'une
     * epoch, et ils n'authentifient pas l'émetteur — la clé est celle du groupe. Y faire
     * transiter un message vaudrait annuler les deux propriétés pour lesquelles MLS a été
     * choisi.
     *
     * La clé change à chaque commit : un membre retiré perd ce canal en même temps que le
     * reste, sans traitement particulier.
     */
    signalKey(group_id: Uint8Array): Uint8Array;
    /**
     * Empreinte de cet appareil, à afficher pour que le correspondant la compare.
     * Clé publique de signature MLS de cet appareil.
     *
     * Elle doit être attestée par le compte **en même temps** que la clé d'authentification
     * HTTP : attestées séparément, on pourrait recombiner l'attestation d'un appareil
     * légitime avec la clé MLS d'un appareil hostile.
     */
    signatureKey(): Uint8Array;
}

/**
 * Offre d'appairage détenue par le **nouvel** appareil.
 *
 * C'est lui qui affiche le QR, l'ancien qui scanne. Ce sens est obligatoire : un QR est
 * photographiable, il ne doit donc contenir aucun secret. Ici il ne porte qu'une clé publique
 * éphémère et une adresse de dépôt.
 */
export class Pairing {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Identifiant d'appairage : l'adresse de dépôt sur le serveur. Public, sans valeur seul.
     */
    id(): Uint8Array;
    constructor();
    /**
     * Ouvre le paquet déposé par l'appareil d'origine.
     *
     * Consomme l'offre : le secret éphémère ne sert qu'une fois, ce qui interdit de rejouer
     * un ancien paquet contre la même clé. Un second appel échoue, délibérément.
     */
    open(sealed: Uint8Array): any;
    /**
     * Clé publique éphémère à publier dans le QR.
     */
    publicKey(): Uint8Array;
}

/**
 * Empreinte d'un compte dont on ne détient que la clé publique.
 */
export function accountFingerprint(identity_key: Uint8Array): string;

/**
 * Dérive la clé de déverrouillage locale depuis un mot de passe.
 *
 * Argon2id, 64 Mio, 3 passes. **Environ une seconde** : c'est le prix à payer une fois par
 * déverrouillage, et à chaque essai par un attaquant qui aurait obtenu la base.
 *
 * Cette fonction n'existe pas dans WebCrypto. PBKDF2, lui, y est — mais il ne coûte que du
 * calcul, ce qu'un GPU fait par milliards. Le coût mémoire d'Argon2id est ce qui ramène une
 * attaque parallèle au niveau d'un processeur ordinaire.
 *
 * Appeler cette fonction gèle le fil d'exécution pendant sa durée. À lancer depuis un Worker
 * si l'interface doit rester réactive.
 */
export function deriveUnlockKey(password: string, salt: Uint8Array): Uint8Array;

/**
 * Hash de feuille d'une entrée du journal, tel que le serveur doit l'avoir calculé.
 *
 * Le client le recalcule lui-même à partir du handle et de la clé qu'on lui sert : accepter le
 * hash fourni par le serveur reviendrait à lui demander de prouver ce qu'il affirme avec ce
 * qu'il affirme.
 */
export function logLeaf(handle: string, identity_key: Uint8Array): Uint8Array;

/**
 * Authentifie un dépôt d'enveloppe sans révéler qui dépose.
 *
 * # Ce que ce MAC dit au serveur
 *
 * Que le déposant détient la clé du groupe, donc qu'il en est membre. Rien de plus. Le serveur
 * n'a jamais eu besoin de savoir **qui** poste — seulement que le posteur a le droit de le
 * faire, pour ne pas servir de boîte aux lettres ouverte. Ce sont deux choses distinctes, et
 * la seconde suffit.
 *
 * L'expéditeur réel reste authentifié **par MLS**, à l'intérieur du chiffré : les
 * destinataires le lisent, le serveur non.
 *
 * # Pourquoi le calcul est fait ici et pas en JavaScript
 *
 * Le message authentifié a un format canonique, partagé avec le vérificateur. Le réécrire côté
 * client dupliquerait la définition — exactement ce que la crate `attest` existe pour
 * supprimer. Un octet de divergence, et tous les dépôts sont refusés.
 */
export function postMac(posting_key: Uint8Array, group_id: Uint8Array, nonce: Uint8Array, body: Uint8Array): Uint8Array;

/**
 * Scelle un paquet à destination du nouvel appareil, depuis les valeurs lues dans le QR.
 *
 * Retourne `{payload, confirmation}`. Le code de confirmation doit être **affiché des deux
 * côtés et comparé par l'utilisateur** : c'est ce qui atteste que les deux appareils parlent
 * bien du même échange.
 */
export function sealPairing(offer_public: Uint8Array, offer_id: Uint8Array, plaintext: Uint8Array): any;

/**
 * MAC accompagnant le dépôt d'un **signal éphémère**.
 *
 * Jumeau de [`post_mac`], au domaine près — voir `attest::signal_message` pour la raison de
 * cette séparation. Il prouve la même chose : l'appartenance au groupe, pas l'identité.
 */
export function signalMac(posting_key: Uint8Array, group_id: Uint8Array, nonce: Uint8Array, body: Uint8Array): Uint8Array;

/**
 * Vérifie une attestation d'appareil servie par le serveur.
 *
 * **À rappeler systématiquement côté client.** Le serveur vérifie déjà à l'écriture, mais
 * c'est précisément le serveur qu'on soupçonne : sa vérification n'est qu'un filtre précoce,
 * jamais une garantie. Voir le test
 * `un_appareil_fantome_injecte_en_sql_ne_passe_pas_la_verification_du_client`.
 */
export function verifyAttestation(identity_key: Uint8Array, handle: string, device_id: string, auth_key: Uint8Array, mls_key: Uint8Array, attestation: Uint8Array): boolean;

/**
 * Vérifie que le journal actuel **prolonge** celui qu'on avait déjà vu, sans réécriture.
 *
 * Sans ce contrôle, le serveur pourrait remplacer une clé déjà publiée et servir un journal
 * tout aussi cohérent : le journal ne prouverait plus rien sur le passé.
 */
export function verifyConsistency(from: number, old_root: Uint8Array, to: number, new_root: Uint8Array, proof: Uint8Array[]): boolean;

/**
 * Vérifie qu'une clé figure bien dans le journal, à l'indice annoncé.
 *
 * **C'est ce qui ferme le trou du premier contact.** Les attestations empêchent le serveur
 * d'ajouter un appareil ; elles ne l'empêchent pas de servir sa propre clé de compte à
 * quelqu'un qui n'a rien à quoi comparer. Une preuve d'inclusion, elle, ne se fabrique pas.
 */
export function verifyInclusion(leaf: Uint8Array, index: number, size: number, proof: Uint8Array[], root: Uint8Array): boolean;

/**
 * Vérifie un certificat de révocation servi par le serveur.
 *
 * **À appeler systématiquement.** Un client qui croirait le serveur sur parole lui rendrait
 * le pouvoir de faire évincer les appareils de son choix — de la censure ciblée, durable, et
 * indiscernable d'une révocation légitime.
 */
export function verifyRevocation(identity_key: Uint8Array, handle: string, device_id: string, revoked_at: bigint, revocation: Uint8Array): boolean;

/**
 * Vérifie qu'une tête de journal a bien été signée par le journal.
 *
 * **Ce que cela prouve est étroit** : que la tête vient du journal. Pas qu'elle soit la seule
 * qu'il ait émise. Un serveur qui tient deux journaux signe deux têtes également valides ;
 * seule la comparaison entre clients l'attrape.
 */
export function verifyTreeHead(log_key: Uint8Array, size: bigint, root: Uint8Array, timestamp: bigint, signature: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_accountkey_free: (a: number, b: number) => void;
    readonly __wbg_client_free: (a: number, b: number) => void;
    readonly __wbg_pairing_free: (a: number, b: number) => void;
    readonly accountFingerprint: (a: number, b: number, c: number) => void;
    readonly accountkey_attest: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => void;
    readonly accountkey_exportSeed: (a: number, b: number) => void;
    readonly accountkey_fingerprint: (a: number, b: number) => void;
    readonly accountkey_fromSeed: (a: number, b: number, c: number) => void;
    readonly accountkey_generate: (a: number) => void;
    readonly accountkey_identityKey: (a: number, b: number) => void;
    readonly accountkey_restore: (a: number, b: number, c: number) => void;
    readonly accountkey_revoke: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => void;
    readonly accountkey_rotate: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => void;
    readonly accountkey_vaultKey: (a: number, b: number) => void;
    readonly client_applyPending: (a: number, b: number, c: number, d: number) => void;
    readonly client_commitPending: (a: number, b: number, c: number, d: number) => void;
    readonly client_conversationIds: (a: number, b: number) => void;
    readonly client_create: (a: number, b: number, c: number) => void;
    readonly client_createConversation: (a: number, b: number) => void;
    readonly client_createGroup: (a: number, b: number, c: number, d: number) => void;
    readonly client_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_epoch: (a: number, b: number, c: number, d: number) => void;
    readonly client_exportState: (a: number, b: number) => void;
    readonly client_fingerprint: (a: number, b: number) => void;
    readonly client_invite: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_join: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_leaveGroup: (a: number, b: number, c: number, d: number) => void;
    readonly client_name: (a: number, b: number) => void;
    readonly client_peerFingerprints: (a: number, b: number, c: number, d: number) => void;
    readonly client_peerSignatureKeys: (a: number, b: number, c: number, d: number) => void;
    readonly client_process: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly client_publishKeyPackage: (a: number, b: number) => void;
    readonly client_removeMember: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_restore: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly client_roster: (a: number, b: number, c: number, d: number) => void;
    readonly client_setRoles: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly client_signalKey: (a: number, b: number, c: number, d: number) => void;
    readonly client_signatureKey: (a: number, b: number) => void;
    readonly deriveUnlockKey: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly logLeaf: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly pairing_id: (a: number, b: number) => void;
    readonly pairing_new: () => number;
    readonly pairing_open: (a: number, b: number, c: number, d: number) => void;
    readonly pairing_publicKey: (a: number, b: number) => void;
    readonly postMac: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly sealPairing: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly signalMac: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly verifyAttestation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => number;
    readonly verifyConsistency: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly verifyInclusion: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly verifyRevocation: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => number;
    readonly verifyTreeHead: (a: number, b: number, c: bigint, d: number, e: number, f: bigint, g: number, h: number) => number;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
