/**
 * Ce que la fenêtre laisse réellement voir.
 *
 * # Pourquoi `100vh` ne suffit pas, et n'a jamais suffi
 *
 * Sur mobile, `100vh` vaut la hauteur de la fenêtre **barres d'interface déployées** — la barre
 * d'adresse qui se rétracte au défilement, la barre système. Une mise en page qui s'y fie
 * dépasse l'écran d'une centaine de pixels : sur une messagerie, ce sont exactement le champ de
 * saisie et le dernier message qui passent dessous.
 *
 * `100dvh` corrige ce cas et se suffit à lui-même en CSS. Ce module traite ce que le CSS ne sait
 * pas dire.
 *
 * # Ce que le CSS ne sait pas dire : le clavier
 *
 * Quand le clavier logiciel s'ouvre, iOS ne redimensionne pas la fenêtre — il **fait glisser**
 * la page sous le clavier, sans rien en dire à la mise en page. Aucune requête média ne se
 * déclenche, `dvh` ne bouge pas, et le champ de saisie se retrouve masqué par le clavier qui
 * vient d'y donner le focus.
 *
 * Seul `visualViewport` le rapporte : sa hauteur est celle de la zone réellement visible, et
 * elle diminue à l'ouverture du clavier. C'est la seule source qui distingue « la fenêtre a
 * changé de taille » de « quelque chose recouvre la fenêtre ».
 *
 * # Ce que ce module ne fait pas
 *
 * Il ne décide de rien. Il rapporte une hauteur et une occlusion ; ce qu'il faut en faire —
 * remonter une barre de saisie, réduire une liste, ne rien changer — appartient aux composants,
 * qui seuls savent ce qui doit rester visible.
 */

export interface Viewport {
  /** Hauteur réellement visible, en pixels CSS. */
  hauteur: number;
  /**
   * Hauteur masquée en bas par le clavier logiciel, en pixels CSS. Zéro s'il est fermé.
   *
   * Mesurée par différence plutôt que demandée : aucune API ne dit « le clavier est ouvert »,
   * et l'inférer d'un focus se tromperait sur un clavier matériel, où le focus n'occulte rien.
   */
  occlusion: number;
}

/**
 * Mesure l'état courant.
 *
 * Se rabat sur `innerHeight` là où `visualViewport` n'existe pas — navigateurs anciens, et
 * environnements de test sans DOM. L'occlusion y vaut zéro : c'est faux seulement dans les cas
 * que ces navigateurs ne rencontrent pas.
 */
export function mesurer(): Viewport {
  const vue = globalThis.visualViewport;
  if (!vue) return { hauteur: globalThis.innerHeight ?? 0, occlusion: 0 };

  // `offsetTop` compte : la page glissée sous le clavier décale la vue vers le bas, et ce
  // décalage fait partie de ce qui est masqué.
  const masque = globalThis.innerHeight - vue.height - vue.offsetTop;

  // Un pixel ou deux d'écart apparaissent au repos, par arrondi. Les traiter comme une
  // occlusion ferait vibrer la mise en page à chaque défilement.
  return { hauteur: vue.height, occlusion: masque > 24 ? masque : 0 };
}

/**
 * S'abonne aux changements, et rend de quoi se désabonner.
 *
 * Les deux événements sont nécessaires et disent des choses différentes : `resize` couvre la
 * rotation et l'ouverture du clavier, `scroll` couvre le glissement de la page sous le clavier,
 * qui change l'occlusion sans changer la hauteur.
 */
export function observer(reagir: (vue: Viewport) => void): () => void {
  const vue = globalThis.visualViewport;
  const relever = () => reagir(mesurer());

  if (!vue) {
    globalThis.addEventListener?.("resize", relever);
    return () => globalThis.removeEventListener?.("resize", relever);
  }

  vue.addEventListener("resize", relever);
  vue.addEventListener("scroll", relever);
  return () => {
    vue.removeEventListener("resize", relever);
    vue.removeEventListener("scroll", relever);
  };
}
