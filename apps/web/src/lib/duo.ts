/**
 * Y a-t-il la place d'afficher deux panneaux à la fois ?
 *
 * # Pourquoi la question se pose aussi en JavaScript
 *
 * Le CSS sait masquer un panneau ; il ne sait pas décider **lequel des deux** monter, ni offrir
 * un bouton retour, ni faire du bouton retour du système une fermeture de conversation. À un
 * seul panneau, la navigation change de nature : ce n'est plus une mise en page, c'est un état.
 *
 * # Le seuil est écrit deux fois, et c'est assumé
 *
 * `index.css` le porte aussi, dans la variante `duo:`. Aucun mécanisme ne permet à Tailwind de
 * lire une constante TypeScript, et l'inverse — dériver le JavaScript du CSS — supposerait de
 * lire une feuille de style compilée au démarrage. Deux déclarations dont le désaccord se voit
 * immédiatement à l'écran valent mieux qu'une indirection qui masquerait le lien.
 */
import { useEffect, useState } from "react";

/** Doit rester identique à la variante `duo:` de `index.css`. */
export const SEUIL_DUO = "(min-width: 48rem)";

/**
 * Vrai quand les deux panneaux tiennent côte à côte.
 *
 * Réévalué au redimensionnement, ce qui couvre la rotation d'une tablette autant qu'une fenêtre
 * qu'on rétrécit — le même événement, et il n'y a pas de raison de traiter l'un des deux comme
 * un cas particulier.
 */
export function useDuo(): boolean {
  const [duo, setDuo] = useState(() => globalThis.matchMedia?.(SEUIL_DUO).matches ?? true);

  useEffect(() => {
    const requete = globalThis.matchMedia?.(SEUIL_DUO);
    if (!requete) return;

    const reagir = () => setDuo(requete.matches);
    requete.addEventListener("change", reagir);
    // Relu à l'abonnement : entre le premier rendu et cet effet, la fenêtre a pu changer.
    reagir();
    return () => requete.removeEventListener("change", reagir);
  }, []);

  return duo;
}
