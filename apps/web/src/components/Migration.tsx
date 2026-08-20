import { useState } from "react";
import type { MigrationProposee, Session } from "@/lib/session";

/**
 * Propose le passage au stockage natif, sans le faire.
 *
 * # Pourquoi une proposition et non une opération automatique
 *
 * Elle enregistre un appareil et **en révoque un autre**. Ce sont des gestes de compte, visibles
 * du serveur et des correspondants ; rien dans « ouvrir l'application » ne les demande. Et son
 * prix est réel : l'identité MLS change, donc les conversations sont rejointes à neuf et
 * l'historique relu depuis le coffre. C'est à l'utilisateur de choisir le moment.
 *
 * # Ce que le texte doit dire, et pourquoi il est long
 *
 * Le bénéfice — un stockage que le système n'évince pas — est invisible tant qu'il n'a pas
 * manqué. Le coût, lui, se voit tout de suite. Un bandeau qui promettrait « plus de sécurité »
 * sans dire ce qui change ferait accepter à l'aveugle, ou refuser par prudence, ce qui revient au
 * même : la décision ne serait pas éclairée.
 */
export function MigrationBanner({
  migration,
  onDone,
  onError,
}: {
  migration: MigrationProposee;
  onDone: (session: Session) => void;
  onError: (message: string) => void;
}) {
  const [etape, setEtape] = useState<string | null>(null);
  const [ecarte, setEcarte] = useState(false);

  if (ecarte) return null;

  const lancer = async () => {
    setEtape("Préparation…");
    try {
      onDone(await migration.executer(setEtape));
    } catch (error) {
      // Un échec ne casse rien : les deux appareils restent actifs, et la reprise repart de là
      // au prochain démarrage. Le dire évite que l'utilisateur ne s'inquiète de voir deux
      // appareils dans ses réglages.
      console.error("migration interrompue", error);
      onError(
        error instanceof Error
          ? error.message
          : "La migration n'a pas abouti. Elle reprendra au prochain démarrage.",
      );
      setEtape(null);
    }
  };

  return (
    <section className="border-t border-(--color-ink-muted)/30 bg-(--color-ink-muted)/10 px-4 py-3 text-sm">
      <h2 className="font-medium">
        {migration.reprise ? "Migration inachevée" : "Stockage de cet appareil"}
      </h2>

      <p className="mt-1 text-(--color-ink-muted)">
        {migration.reprise
          ? "Un second appareil a été enregistré mais l'ancien n'a pas encore été retiré. " +
            "Les deux fonctionnent ; reprendre termine le passage et retire l'ancien."
          : "Cette application peut ranger vos conversations hors du navigateur, là où le " +
            "système ne les efface pas. Le passage enregistre un nouvel appareil et retire " +
            "celui-ci : vos conversations sont rejointes à neuf et l'historique rechargé depuis " +
            "la sauvegarde. Vos correspondants verront un appareil changer."}
      </p>

      {etape ? (
        <p className="mt-2 text-(--color-ink-muted)" role="status">
          {etape}
        </p>
      ) : (
        <div className="mt-2 flex gap-4">
          <button type="button" onClick={() => void lancer()} className="underline">
            {migration.reprise ? "Reprendre" : "Passer au stockage de l'application"}
          </button>
          {/* Écarté pour cette session seulement : la proposition revient au démarrage suivant,
              parce qu'un refus d'aujourd'hui n'est pas un refus définitif — et parce que rien
              ne permet de distinguer les deux. */}
          <button
            type="button"
            onClick={() => setEcarte(true)}
            className="text-(--color-ink-muted) underline"
          >
            Plus tard
          </button>
        </div>
      )}
    </section>
  );
}
