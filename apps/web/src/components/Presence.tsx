/**
 * Affichage de la présence.
 *
 * Isolé plutôt qu'inséré directement dans `page.tsx` : ce fichier dépasse déjà les huit cents
 * lignes, et la règle d'affichage — un point quand c'est frais, une heure sinon, rien quand on
 * ne sait pas — mérite d'être lisible d'un seul tenant.
 */
import type { Session } from "@/lib/session";
import { describePresence, isOnline } from "@/lib/presence";

/**
 * Pastille « en ligne », sans texte.
 *
 * Rien du tout quand le compte n'est pas frais : un point gris demanderait à l'œil de
 * distinguer deux nuances dans une liste, pour dire « hors ligne » alors qu'on ne le sait pas
 * toujours. L'absence de point est plus honnête et plus lisible.
 */
export function PresenceDot({ session, handle }: { session: Session; handle: string }) {
  if (!isOnline(session.presenceOf(handle), session.presenceClock)) return null;

  return (
    <span
      className="inline-block size-2 shrink-0 rounded-full bg-(--color-ok)"
      title="en ligne"
      aria-label="en ligne"
    />
  );
}

/**
 * Ligne « en ligne » / « vu à 14:02 ».
 *
 * Ne rend rien quand le serveur n'a rien à dire — compte jamais vu, ou qui a refusé de diffuser
 * sa présence. « Hors ligne » serait une affirmation, et on n'en a pas les moyens.
 */
export function PresenceLine({ session, handle }: { session: Session; handle: string }) {
  const texte = describePresence(session.presenceOf(handle), session.presenceClock);
  if (!texte) return null;

  return <span className="text-xs text-(--color-ink-muted)">{texte}</span>;
}
