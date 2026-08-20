"use client";

import { useState } from "react";
import type { ConversationView, Session } from "@/lib/session";

/**
 * Activation du coffre d'historique.
 *
 * Cet écran existe pour dire ce qu'on abandonne, pas pour vendre une fonctionnalité. Activer
 * le coffre retire à l'historique la protection de la forward secrecy : c'est un vrai
 * renoncement, il se décide en connaissance de cause, et l'enfouir dans un menu reviendrait à
 * le prendre à la place de l'utilisateur.
 */
export function VaultSettings({
  session,
  active,
  onDone,
}: {
  session: Session;
  active: ConversationView | null;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [compris, setCompris] = useState(false);
  const [restaures, setRestaures] = useState<number | null>(null);

  const basculer = async () => {
    setBusy(true);
    try {
      if (session.archiving) {
        await session.disableVault();
      } else {
        await session.enableVault();
      }
      onDone();
    } finally {
      setBusy(false);
    }
  };

  const restaurer = async () => {
    if (!active) return;
    setBusy(true);
    try {
      setRestaures(await session.restoreHistory(active));
    } finally {
      setBusy(false);
    }
  };

  if (session.archiving) {
    return (
      <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="font-medium">Sauvegarde de l&apos;historique</h2>
          <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
            Fermer
          </button>
        </div>

        <p className="mt-2 text-(--color-ink-muted)">
          Vos messages sont archivés, chiffrés par une clé dérivée de votre phrase de
          récupération. Le serveur ne peut pas les lire.
        </p>

        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={restaurer}
            disabled={busy || !active}
            className="rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white disabled:opacity-50"
          >
            {busy ? "…" : "Restaurer l'historique ici"}
          </button>
          <button
            type="button"
            onClick={basculer}
            disabled={busy}
            className="rounded-md border border-(--color-border-subtle) px-3 py-1.5 disabled:opacity-50"
          >
            Arrêter la sauvegarde
          </button>
        </div>

        {restaures !== null && (
          <p className="mt-2 text-(--color-ok)">
            {restaures === 0
              ? "Rien à restaurer pour cette conversation."
              : `${restaures} message(s) restauré(s).`}
          </p>
        )}

        <p className="mt-3 text-xs text-(--color-ink-muted)">
          Arrêter la sauvegarde n&apos;efface pas ce qui a déjà été archivé : le serveur
          conserve ces entrées, et la clé qui les ouvre reste dérivable de votre phrase.
          Promettre une suppression que nous ne contrôlons pas serait malhonnête.
        </p>
      </div>
    );
  }

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Sauvegarder l&apos;historique</h2>
        <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
          Fermer
        </button>
      </div>

      <p className="mt-2 text-(--color-ink-muted)">
        Sans sauvegarde, vos messages disparaissent à la fermeture de l&apos;application et un
        nouvel appareil repart d&apos;une conversation vide. Ce n&apos;est pas un oubli :
        c&apos;est la forward secrecy, qui rend le passé illisible même pour qui obtiendrait le
        serveur plus tard.
      </p>

      <div className="mt-3 rounded-md border border-(--color-danger) bg-(--color-danger)/10 p-3">
        <p className="font-medium text-(--color-danger)">Ce que vous abandonnez</p>
        <p className="mt-1 text-(--color-ink-muted)">
          L&apos;archive est chiffrée par une clé dérivée de votre phrase de récupération, donc
          <strong> la même pour toujours</strong>. Si cette phrase vous échappe un jour,
          l&apos;intégralité du passé sauvegardé devient lisible — rétroactivement. Sans
          sauvegarde, ce passé-là serait resté hors d&apos;atteinte.
        </p>
      </div>

      <p className="mt-3 text-xs text-(--color-ink-muted)">
        L&apos;archivage commence maintenant et ne remonte pas dans le temps : les messages
        déjà échangés ont vu leurs clés détruites, rien ne permet de les reconstituer.
      </p>

      <label className="mt-3 flex items-start gap-2">
        <input
          type="checkbox"
          checked={compris}
          onChange={(e) => setCompris(e.target.checked)}
          className="mt-1"
        />
        <span>
          Je comprends que mon historique ne sera plus protégé par la forward secrecy.
        </span>
      </label>

      <button
        type="button"
        onClick={basculer}
        disabled={busy || !compris}
        className="mt-3 rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white disabled:opacity-50"
      >
        {busy ? "…" : "Activer la sauvegarde"}
      </button>
    </div>
  );
}
