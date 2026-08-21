/**
 * Persistance locale.
 *
 * # Deux implémentations, une interface
 *
 * Sur le web, IndexedDB. Sous Tauri, un fichier écrit par le processus Rust — parce que le
 * stockage d'une webview mobile **n'est pas garanti** : iOS évince les données de WKWebView
 * après sept jours d'inactivité, Android purge sous pression mémoire. Et la perte est
 * définitive : le ratchet MLS détruit ses clés au fur et à mesure.
 *
 * # Les clés ne passent pas par ici
 *
 * `StoredSession` n'en porte aucune. Sur le web elles existent bel et bien dans la même base —
 * ce sont des `CryptoKey` non extractables, qu'IndexedDB accepte telles quelles et qu'aucun
 * fichier ne pourrait recevoir — mais c'est l'affaire du store, pas de la session. Celle-ci
 * demande un scellement à `DeviceCipher` et ne voit jamais de matériel de clé, ce qui est
 * précisément ce qui lui permet d'être la même sur les deux plateformes.
 *
 * L'état MLS, lui, est chiffré avant d'arriver ici (voir `wrapState`).
 */
import { isTauri } from "./platform";
import type { DeviceKeys } from "./keys";
import type { LockEnvelope } from "./lock";

const DB_NAME = "whispee";
const DB_VERSION = 1;
const STORE = "device";

interface StoredSession {
  deviceId: string;
  /** Pseudonyme du compte. En clair côté serveur, comme le credential MLS. */
  handle: string;
  /**
   * Graine du compte, **chiffrée** avec la même clé que l'état MLS.
   *
   * Elle vaut le compte entier : elle permet d'attester de nouveaux appareils et d'en
   * révoquer. Elle est conservée parce qu'un appareil doit pouvoir en appairer un autre sans
   * redemander la phrase à l'utilisateur — mais elle ne doit jamais toucher le disque en
   * clair, ni partir sur le réseau autrement que scellée dans un blob d'appairage.
   */
  accountSeed: Uint8Array;
  /**
   * Verrou local, s'il est activé.
   *
   * Absent, l'état est chiffré par la clé non-extractable d'`DeviceKeys` : elle protège de
   * l'exfiltration par script, mais pas de qui obtient la session du navigateur. Présent,
   * l'état est chiffré par une clé maîtresse qui n'existe qu'en mémoire après saisie du mot
   * de passe.
   *
   * Rien de ce qui est stocké ici n'est secret : le sel est public, et la clé maîtresse y
   * figure chiffrée.
   */
  lock?: LockEnvelope;
  /**
   * Le coffre d'historique est-il actif ?
   *
   * **Absent vaut actif.** Le coffre est le défaut ; ce drapeau ne sert donc qu'à retenir un
   * refus. Trois valeurs, pas deux : `false` est une décision de l'utilisateur et se respecte,
   * `undefined` est l'absence de décision et se traite comme un compte neuf. Les confondre
   * rallumerait la sauvegarde dans le dos de quelqu'un qui l'avait coupée.
   *
   * Seul le drapeau est stocké : la clé se redérive de la graine du compte, elle-même
   * chiffrée juste au-dessus. La conserver ici ferait une copie de plus d'un secret qui
   * ouvre tout le passé archivé.
   */
  vaultEnabled?: boolean;
  /** État MLS chiffré. Jamais en clair sur le disque. */
  state?: Uint8Array;
  /** Le stockage MLS ne s'énumère pas : la liste des groupes se conserve à côté. */
  groupIds: Uint8Array[];
  /**
   * Empreintes de compte déjà vérifiées hors bande, par handle.
   *
   * Conserver la valeur vérifiée — et non un simple booléen — est ce qui permet de
   * **détecter un changement**. L'empreinte porte sur la clé du compte, pas sur celle d'un
   * appareil : elle ne bouge donc pas quand le correspondant ajoute un téléphone. Si elle
   * change malgré tout, c'est soit une récupération depuis la phrase, soit une substitution
   * par le serveur. L'un est rare, l'autre est l'attaque ; l'utilisateur seul peut trancher,
   * mais il faut d'abord le lui dire.
   */
  verified: Record<string, string>;
  /**
   * Dernière séquence traitée par conversation, indexée par identifiant de groupe en hex.
   *
   * Doit être persisté avec l'état MLS, et non recalculé au démarrage. Chaque clé de message
   * est consommée puis détruite à la lecture : reprendre le flux depuis le début ferait
   * échouer tous les messages déjà lus, et la conversation resterait vide après un simple
   * rechargement de page.
   */
  cursors: Record<string, number>;
  /**
   * Appareils connus de chaque correspondant, par handle.
   *
   * Sert à repérer un ajout : un appareil qui apparaît chez un pair est un événement à
   * signaler, et c'est cette notification — non l'empreinte, volontairement stable — qui
   * révèle un appareil hostile légitimement attesté par un compte compromis.
   */
  knownDevices: Record<string, string[]>;
  /**
   * Réglages de signalisation. Absent sur les sessions antérieures, d'où l'optionnalité.
   *
   * Ils vivent ici et nulle part ailleurs : ce sont des préférences locales, et les faire
   * connaître au serveur reviendrait à lui apprendre qui refuse d'être observé.
   */
  signals?: SignalSettings;
  /**
   * Clé de dépôt par conversation, indexée par identifiant de groupe en hex.
   *
   * # Pourquoi la persister
   *
   * Sans elle, chaque rechargement de page retire au client sa capacité de déposer
   * anonymement, jusqu'à ce qu'un autre membre la rediffuse — ce qui suppose qu'il soit en
   * ligne. Le sealed sender et l'indicateur de frappe retombaient silencieusement sur « rien »
   * pendant ce temps : la panne la plus difficile à voir, puisque tout le reste fonctionne.
   *
   * # Ce que cela n'expose pas
   *
   * Rien de neuf. Cette clé est déjà connue de tous les membres du groupe **et du serveur**,
   * qui doit vérifier les MAC. Elle n'ouvre aucun contenu ; elle prouve seulement
   * l'appartenance. Elle est de toute façon rangée dans l'état chiffré au repos, comme les
   * clés MLS qui, elles, valent bien davantage.
   */
  postingKeys?: Record<string, string>;
}

/** Ce que l'utilisateur accepte d'émettre. */
export interface SignalSettings {
  /**
   * Émettre — et donc voir — les accusés de lecture.
   *
   * Un seul drapeau pour les deux sens : la réciprocité est la règle, et deux drapeaux
   * distincts inviteraient à voir sans être vu.
   */
  readReceipts: boolean;
  /** Émettre l'indicateur de frappe. Le recevoir reste possible : rien à cacher à s'en priver. */
  typingIndicator: boolean;
  /**
   * Diffuser — et donc voir — sa présence.
   *
   * Un seul drapeau, comme pour les accusés de lecture, et pour la même raison : deux drapeaux
   * distincts inviteraient à voir sans être vu. La réciprocité est en outre **appliquée par le
   * serveur**, qui cesse d'enregistrer autant que de servir ; ce drapeau-ci ne fait qu'éviter
   * une requête inutile et refléter l'état à l'écran.
   *
   * Absent vaut activé : la présence est le défaut, ce drapeau ne sert qu'à retenir un refus.
   */
  presence?: boolean;
}

/**
 * Délai au-delà duquel on considère l'ouverture bloquée.
 *
 * IndexedDB ne signale pas toujours `onblocked` : une base en cours de suppression, ou un
 * autre onglet qui retient l'ancienne version, laisse la requête muette — ni succès, ni
 * erreur, indéfiniment. Sans ce garde-fou, l'application reste sur « Chargement… » sans que
 * rien n'indique pourquoi.
 */
const OPEN_TIMEOUT_MS = 5000;

const BLOCKED =
  "Base locale inaccessible. Un autre onglet de l'application la retient : fermez-le, puis rechargez.";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    const timer = setTimeout(() => reject(new Error(BLOCKED)), OPEN_TIMEOUT_MS);
    const settle = <T>(run: () => T) => {
      clearTimeout(timer);
      return run();
    };

    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => settle(() => resolve(request.result));
    request.onerror = () => settle(() => reject(request.error));
    request.onblocked = () => settle(() => reject(new Error(BLOCKED)));
  });
}

function transact<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>) {
  return open().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const request = run(db.transaction(STORE, mode).objectStore(STORE));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      }),
  );
}

/**
 * Où la session est rangée.
 *
 * Trois opérations et rien de plus : tout ce qui décide *quoi* ranger vit dans `Session`, et
 * tout ce qui décide *comment le protéger* vit dans `DeviceCipher`. Un port qui saurait aussi
 * chiffrer devrait connaître les clés, ce qui est précisément ce qu'on cherche à éviter.
 */
export interface SessionStore {
  load(): Promise<StoredSession | undefined>;
  save(session: StoredSession): Promise<void>;
  /**
   * Efface tout.
   *
   * Sur le web, les clés non extractables disparaissent avec la base : sans elles, l'état
   * chiffré résiduel est définitivement illisible, y compris par nous.
   */
  clear(): Promise<void>;
}

/** Ce qu'IndexedDB contient réellement : la session, plus les clés que seul le store manipule. */
interface StoredWithKeys extends StoredSession {
  keys: DeviceKeys;
}

/**
 * Le store du navigateur, qui range aussi les clés de l'appareil.
 *
 * Il les tient parce qu'il est le seul à pouvoir : elles ne se sérialisent pas, donc elles ne
 * peuvent vivre que là où le clonage structuré les accepte. La session, elle, les ignore — ce
 * qui lui permet d'être identique sous Tauri, où elles vivent dans un autre processus.
 */
export class IndexedDbStore implements SessionStore {
  private keys: DeviceKeys;

  constructor(keys: DeviceKeys) {
    this.keys = keys;
  }

  async load(): Promise<StoredSession | undefined> {
    const stored = await transact<StoredWithKeys | undefined>("readonly", (store) =>
      store.get("session"),
    );
    if (!stored) return undefined;

    // Les clés lues font autorité sur celles reçues à la construction : au rechargement, ce
    // sont les seules qui déchiffrent l'état déjà écrit.
    this.keys = stored.keys;
    return stored;
  }

  async save(session: StoredSession): Promise<void> {
    await transact("readwrite", (store) => store.put({ ...session, keys: this.keys }, "session"));
  }

  async clear(): Promise<void> {
    await transact("readwrite", (store) => store.clear());
  }
}

/**
 * Lit les clés déjà rangées dans la base, s'il y en a.
 *
 * Séparé de `load` parce que l'ordre l'exige : il faut les clés pour construire le chiffreur,
 * et le chiffreur pour ouvrir l'état. Sur le web les deux sortent de la même base, ce qui invite
 * à les confondre — sous Tauri elles viennent d'un autre processus, et la confusion se paierait.
 */
export async function readStoredKeys(): Promise<DeviceKeys | undefined> {
  const stored = await transact<StoredWithKeys | undefined>("readonly", (store) =>
    store.get("session"),
  );
  return stored?.keys;
}

export type { StoredSession };
