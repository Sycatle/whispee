/**
 * Passage d'une installation de bureau au stockage natif.
 *
 * # Le problème, qui n'a pas de solution simple
 *
 * Une installation existante range ses clés dans IndexedDB. Elles y sont non extractables —
 * c'est leur seule raison d'être — donc **elle ne peut pas les déplacer**. Et le serveur refuse
 * de changer la clé d'authentification d'un appareil déjà enregistré (clause sur `auth_key` dans
 * `register_device`), ce qui ferme la dernière porte : cet appareil ne sera jamais natif.
 *
 * Déplacer le seul état MLS ne servirait à rien. Un état sauvé dont la clé d'authentification a
 * disparu est inutilisable : l'appareil ne peut plus émettre une requête. La demi-mesure
 * ressemblerait à une protection sans en être une, ce qui est pire que de ne rien faire.
 *
 * # Ce qu'on fait à la place
 *
 * On n'essaie pas de sauver l'appareil : on en enregistre un neuf, natif, attesté par la graine
 * du compte — qui, elle, est dans la session et donc disponible. L'ancien est révoqué. C'est le
 * mécanisme d'appairage existant, appliqué à soi-même, et il ne demande aucune fonction serveur
 * nouvelle.
 *
 * Le prix est réel et se paie une fois : l'identité MLS change, donc les groupes sont à
 * rejoindre et l'historique à relire depuis le coffre.
 *
 * # D'où le pré-requis
 *
 * **Sans coffre, pas de migration.** L'historique n'existe alors nulle part ailleurs que dans
 * l'état MLS de l'appareil courant, et le nouvel appareil ne peut pas en hériter : le ratchet a
 * détruit les clés au fur et à mesure. Migrer sans coffre échangerait une éviction *possible*
 * contre une perte *certaine*. L'installation reste sur IndexedDB, ce qu'elle faisait déjà.
 *
 * # Pourquoi l'état de la migration n'est pas mémorisé
 *
 * Il se déduit de ce qui existe : une session web seule est une migration à faire, les deux
 * ensemble une migration commencée, une session native seule une migration finie. Un marqueur
 * ajouterait une troisième source de vérité, qu'une interruption pourrait mettre en désaccord
 * avec les deux autres — précisément dans le cas où l'on compte dessus.
 */

/** Ce qu'on sait d'une session déjà rangée quelque part, sans l'avoir ouverte. */
export interface Presence {
  handle: string;
  /**
   * Le coffre est-il actif ?
   *
   * Trois valeurs, et la distinction est ici décisive : `false` est un refus explicite qui
   * interdit la migration, `undefined` est l'absence de décision, donc le défaut, donc actif.
   * Les confondre refuserait de migrer tous les comptes antérieurs au drapeau.
   */
  vaultEnabled?: boolean;
}

export type Decision =
  /** Rien de rangé : l'installation est neuve, elle démarre nativement sans rien migrer. */
  | { quoi: "neuve" }
  /** Migration finie, ou installation déjà native. */
  | { quoi: "native" }
  /** À faire, depuis le début. */
  | { quoi: "demarrer"; handle: string }
  /**
   * Commencée puis interrompue.
   *
   * Ce n'est pas un état dégradé : le compte a simplement deux appareils, ce qu'il a le droit
   * d'avoir. Reprendre revient à finir la propagation puis à révoquer l'ancien.
   */
  | { quoi: "reprendre"; handle: string }
  /**
   * On reste sur IndexedDB, et on dit pourquoi.
   *
   * `raison` est destinée à l'utilisateur : une migration silencieusement abandonnée laisserait
   * croire à une protection qui n'existe pas.
   */
  | { quoi: "repli"; raison: string };

const SANS_COFFRE =
  "La sauvegarde d'historique est désactivée : migrer vers le stockage natif ferait perdre " +
  "définitivement les conversations, que le nouvel appareil ne pourrait relire nulle part. " +
  "L'application continue de fonctionner comme avant.";

const CONFLIT =
  "Le stockage natif contient déjà la session d'un autre compte. Aucune migration n'est tentée : " +
  "l'écraser détruirait une identité que le serveur connaît encore et que plus rien ne prouverait.";

/**
 * Que faire au démarrage, sous Tauri.
 *
 * Fonction pure : elle ne regarde que ce qui existe, et c'est ce qui la rend vérifiable. Toute
 * la difficulté de la migration tient dans ce tableau de cas, pas dans les appels réseau.
 */
export function decider(web: Presence | undefined, natif: Presence | undefined): Decision {
  if (web === undefined) {
    return natif === undefined ? { quoi: "neuve" } : { quoi: "native" };
  }

  if (natif === undefined) {
    // Le refus est vérifié avant toute chose : c'est le seul cas où migrer serait destructeur.
    if (web.vaultEnabled === false) return { quoi: "repli", raison: SANS_COFFRE };
    return { quoi: "demarrer", handle: web.handle };
  }

  // Deux sessions de comptes différents ne sont pas une migration à moitié faite. Se tromper
  // ici écraserait une identité que le serveur connaît encore et que plus rien ne prouverait.
  if (natif.handle !== web.handle) return { quoi: "repli", raison: CONFLIT };

  return { quoi: "reprendre", handle: web.handle };
}

/**
 * Les étapes, telles que `session.ts` sait les exécuter.
 *
 * Isolées derrière une interface pour que l'enchaînement — le seul endroit où une interruption
 * peut faire des dégâts — soit testable sans serveur, sans MLS et sans webview.
 */
export interface Etapes {
  /**
   * Enregistre un appareil natif neuf, attesté par la graine du compte, et range sa session.
   *
   * Appelée seulement si aucune session native n'existe. Le serveur décline le nom en cas de
   * collision, donc un second appel créerait un appareil de plus au lieu d'échouer — c'est
   * pourquoi la décision, et non cette fonction, porte l'idempotence.
   */
  enregistrerAppareilNatif(): Promise<string>;

  /**
   * Fait ajouter le nouvel appareil à toutes les conversations, par l'ancien.
   *
   * C'est `propagateOwnDevices`, déjà idempotent et déjà appelé à chaque relève : MLS ne
   * rattrape pas un membre absent de l'arbre, donc l'opération est conçue pour être répétée.
   */
  propagerDepuisAncien(): Promise<void>;

  /** Combien de conversations le nouvel appareil a rejointes, sur combien l'ancien en a. */
  avancement(): Promise<{ rejointes: number; attendues: number }>;

  /** Relit l'historique archivé, conversation par conversation. */
  restaurerHistorique(): Promise<void>;

  /**
   * Révoque l'ancien appareil, depuis le nouveau.
   *
   * Dans ce sens et pas l'autre : un appareil ne se révoque pas lui-même, et surtout la
   * révocation doit être le **dernier** geste avant l'effacement. La faire plus tôt couperait
   * l'ancien appareil des groupes avant qu'il n'ait fini d'y introduire le nouveau.
   */
  revoquerAncien(ancien: string): Promise<void>;

  /** Efface la session web. Le seul geste irréversible, et donc le dernier. */
  oublierWeb(): Promise<void>;

  /** Signale l'avancement à l'interface : la migration prend plusieurs allers-retours. */
  progres?(etape: string): void;
}

/**
 * Nombre de tours d'attente avant d'abandonner la propagation.
 *
 * Abandonner laisse deux appareils actifs — un état sain, seulement redondant — et le démarrage
 * suivant repart de là. Attendre indéfiniment, en revanche, bloquerait l'application sur un
 * serveur muet.
 */
const TOURS_MAX = 20;

/** Signale que la propagation n'a pas abouti dans le temps imparti. */
export class PropagationIncomplete extends Error {
  constructor(rejointes: number, attendues: number) {
    super(
      `Migration inachevée : ${rejointes} conversation(s) sur ${attendues} rejointes. ` +
        "Elle reprendra au prochain démarrage ; les deux appareils restent actifs d'ici là.",
    );
    this.name = "PropagationIncomplete";
  }
}

/**
 * Exécute la migration, ou la reprend.
 *
 * L'ordre n'est pas négociable, et chaque étape supporte d'être rejouée : une interruption
 * laisse le compte avec deux appareils actifs, ce qui fonctionne, et le démarrage suivant
 * reprend là où celui-ci s'est arrêté.
 *
 * `attendre` est injecté pour que les tests n'attendent pas réellement.
 */
export async function migrer(
  decision: Decision,
  etapes: Etapes,
  ancien: string,
  attendre: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
): Promise<void> {
  if (decision.quoi !== "demarrer" && decision.quoi !== "reprendre") return;

  const dire = (etape: string) => etapes.progres?.(etape);

  if (decision.quoi === "demarrer") {
    dire("Enregistrement de l'appareil…");
    await etapes.enregistrerAppareilNatif();
  }

  dire("Transfert des conversations…");
  await etapes.propagerDepuisAncien();

  // La propagation est asynchrone de bout en bout : l'ancien appareil dépose des commits, le
  // nouveau doit les relever. On attend le résultat plutôt que le geste — sans quoi on
  // révoquerait l'ancien avant que le nouveau ne soit réellement dans les groupes, et les
  // conversations deviendraient inaccessibles de ce côté-ci.
  for (let tour = 0; ; tour += 1) {
    const { rejointes, attendues } = await etapes.avancement();
    if (rejointes >= attendues) break;

    if (tour >= TOURS_MAX) throw new PropagationIncomplete(rejointes, attendues);

    await attendre(1500);
    await etapes.propagerDepuisAncien();
  }

  dire("Restauration de l'historique…");
  await etapes.restaurerHistorique();

  dire("Retrait de l'ancien appareil…");
  await etapes.revoquerAncien(ancien);

  // En dernier, et seulement en dernier : tant que la session web existe, tout ce qui précède
  // peut être rejoué. Une fois effacée, plus rien ne peut l'être.
  await etapes.oublierWeb();
}
