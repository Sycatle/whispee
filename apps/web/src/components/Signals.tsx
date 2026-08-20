"use client";

/**
 * Réglages de signalisation.
 *
 * # Pourquoi la réciprocité est écrite à l'écran
 *
 * Désactiver ses accusés de lecture cesse aussi de montrer ceux des autres. C'est le
 * comportement de WhatsApp et de Signal, et il surprend systématiquement quand il n'est pas
 * annoncé. L'enfouir dans une documentation reviendrait à faire découvrir la contrepartie
 * après coup, ce qui est exactement ce qu'un réglage de vie privée ne doit pas faire.
 *
 * # Pourquoi il n'y a pas de réglage de présence
 *
 * Parce qu'il n'y a pas de présence. Elle est la seule des trois fonctions demandées qui
 * oblige quelqu'un à tenir un registre transverse aux conversations — donc à connaître les
 * horaires de chacun. Aucune formulation chiffrée ne contourne cela.
 */
import { useState } from "react";

import type { Session } from "@/lib/session";

export function SignalSettings({
  session,
  onError,
}: {
  session: Session;
  onError: (message: string) => void;
}) {
  const [settings, setSettings] = useState(session.signalSettings());

  const basculer = (cle: "readReceipts" | "typingIndicator") => {
    const valeur = !settings[cle];
    setSettings({ ...settings, [cle]: valeur });
    session.setSignalSetting(cle, valeur).catch((e: unknown) => {
      onError(e instanceof Error ? e.message : String(e));
    });
  };

  return (
    <section className="space-y-3 text-sm">
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={settings.readReceipts}
          onChange={() => basculer("readReceipts")}
          className="mt-1"
        />
        <span>
          Accusés de lecture
          <span className="block text-xs opacity-70">
            Les désactiver vous empêche aussi de voir ceux des autres. Les accusés de réception
            restent actifs : ils constatent qu’un appareil a relevé le message, pas qu’une
            personne l’a lu.
          </span>
        </span>
      </label>

      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={settings.typingIndicator}
          onChange={() => basculer("typingIndicator")}
          className="mt-1"
        />
        <span>
          Indicateur de frappe
          <span className="block text-xs opacity-70">
            Le contenu est chiffré et n’est jamais stocké, mais le serveur voit qu’un dépôt a
            lieu dans cette conversation. Le désactiver est la seule protection réelle.
          </span>
        </span>
      </label>

      <p className="text-xs opacity-60">
        Aucune présence n’est diffusée : personne, pas même le serveur, ne sait si vous êtes
        connecté.
      </p>
    </section>
  );
}
