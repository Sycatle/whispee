/**
 * Ce que devient l'application quand on la quitte des yeux.
 *
 * # Pourquoi une messagerie ne peut pas l'ignorer
 *
 * Sur mobile, passer en arrière-plan n'est pas une pause : le système gèle les minuteurs, coupe
 * les connexions ouvertes, et peut tuer le processus sans prévenir. Une application qui compte
 * sur son `setInterval` pour rester à jour se réveille avec un écran figé sur l'état d'il y a
 * une heure — et, plus perfidement, avec un WebSocket qui **paraît** ouvert alors que plus rien
 * ne passe.
 *
 * Le navigateur de bureau fait déjà une version atténuée de la même chose : Chrome limite les
 * minuteurs des onglets d'arrière-plan à un déclenchement par minute.
 *
 * # Reprendre, ce n'est pas continuer
 *
 * Au retour au premier plan, il ne suffit pas de laisser l'intervalle repartir : il faut relever
 * tout de suite et **rouvrir le flux**, sans chercher à savoir s'il est encore vivant. Cette
 * question n'a pas de réponse fiable — un socket coupé par le système reste `OPEN` jusqu'à la
 * première écriture — et la poser coûterait plus cher que de reconnecter à tort.
 *
 * # Ce que ce module ne fait pas
 *
 * Il ne connaît ni session ni réseau. Il rapporte des transitions ; ce qu'il faut en faire
 * appartient à l'appelant, seul à savoir ce qui doit être relevé, rouvert ou reverrouillé — le
 * verrouillage automatique, quand il arrivera, se branchera exactement ici.
 */

export type Transition =
  /** Retour au premier plan. Impose une relève et une réouverture du flux. */
  | { quoi: "reprise"; absenceMs: number }
  /** Passage en arrière-plan. */
  | { quoi: "veille" }
  /**
   * Le réseau est revenu.
   *
   * Distinct de la reprise : un ordinateur portable qui retrouve le Wi-Fi n'a jamais quitté le
   * premier plan, et une application qui n'écouterait que la visibilité y resterait muette
   * jusqu'à la relève suivante.
   */
  | { quoi: "reseau" };

/**
 * S'abonne aux transitions, et rend de quoi se désabonner.
 *
 * `maintenant` est injecté pour que la durée d'absence soit vérifiable sans horloge réelle.
 */
export function observerCycle(
  reagir: (transition: Transition) => void,
  maintenant: () => number = () => Date.now(),
): () => void {
  // Instant du passage en arrière-plan. La durée d'absence sert à l'appelant : une seconde
  // d'inattention et une nuit entière n'appellent pas le même rattrapage.
  let depuis = maintenant();

  const visibilite = () => {
    if (document.visibilityState === "hidden") {
      depuis = maintenant();
      reagir({ quoi: "veille" });
      return;
    }
    reagir({ quoi: "reprise", absenceMs: maintenant() - depuis });
  };

  const enLigne = () => reagir({ quoi: "reseau" });

  document.addEventListener("visibilitychange", visibilite);
  addEventListener("online", enLigne);

  return () => {
    document.removeEventListener("visibilitychange", visibilite);
    removeEventListener("online", enLigne);
  };
}

/**
 * Le réseau est-il déclaré disponible ?
 *
 * `false` est une information sûre — il n'y a aucune interface active — et mérite d'être
 * affichée. `true` ne garantit rien : un portail captif, un serveur éteint ou un DNS muet
 * répondent tous « en ligne ». C'est pourquoi cette valeur ne sert qu'à **expliquer** un échec,
 * jamais à décider d'en tenter un.
 */
export function reseauDeclare(): boolean {
  return navigator.onLine !== false;
}

/**
 * Absence au-delà de laquelle un appareil verrouillé redemande son mot de passe.
 *
 * # Pourquoi un délai, et pas un verrouillage immédiat
 *
 * Quitter l'application une seconde pour copier un code reçu par ailleurs est un geste courant,
 * et redemander le mot de passe à chaque aller-retour ferait retirer le verrou — un verrou trop
 * strict ne protège plus rien, il apprend seulement à s'en passer.
 *
 * # Pourquoi pas davantage
 *
 * La fenêtre est exactement celle où un appareil posé sur une table est lisible par qui le
 * ramasse. Cinq minutes est un compromis, non un seuil dérivé de quoi que ce soit ; il est ici
 * pour pouvoir être discuté et changé à un seul endroit.
 */
export const REVERROUILLAGE_MS = 5 * 60 * 1000;
