"use client";

import { useEffect, useState } from "react";
import type { ResolvedAccount } from "@/lib/account";
import type { Session } from "@/lib/session";

/**
 * Appareils du compte : révocation, et rotation quand un appareil a été volé.
 *
 * # La distinction que ce panneau existe pour rendre lisible
 *
 * Perdre un appareil et se le faire voler n'appellent pas la même réponse, et l'interface est
 * le seul endroit où l'utilisateur peut apprendre pourquoi.
 *
 * Tous les appareils d'un compte détiennent la même graine — c'est ce qui leur donne à tous
 * les mêmes droits, sans appareil « principal ». La contrepartie est qu'un appareil **volé**
 * détient le compte entier : le révoquer ne l'empêche pas d'en attester un nouveau dans la
 * seconde. Seule la rotation de la clé du compte y met fin, en rendant invérifiables toutes
 * les attestations d'un coup.
 *
 * Présenter les deux boutons côte à côte sans cette explication conduirait tout droit au
 * mauvais choix, et l'utilisateur croirait s'être protégé.
 */
export function DeviceSettings({
  session,
  onError,
  onClose,
}: {
  session: Session;
  onError: (message: string) => void;
  onClose: () => void;
}) {
  const [account, setAccount] = useState<ResolvedAccount | null>(null);
  const [busy, setBusy] = useState(false);
  const [rotation, setRotation] = useState(false);
  const [phrase, setPhrase] = useState<string | null>(null);

  const recharger = () => {
    session
      .resolve(session.handle)
      .then(setAccount)
      .catch((e: unknown) => onError(e instanceof Error ? e.message : String(e)));
  };

  useEffect(recharger, [session, onError]);

  const revoquer = async (deviceId: string) => {
    setBusy(true);
    try {
      await session.revokeOwnDevice(deviceId);
      recharger();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const tourner = async () => {
    setBusy(true);
    try {
      setPhrase(await session.rotateAccount());
      recharger();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // Après rotation : la nouvelle phrase, une seule fois. L'ancienne ne vaut plus rien.
  if (phrase) {
    return (
      <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
        <h2 className="font-medium">Nouvelle phrase de récupération</h2>
        <p className="mt-2 text-(--color-ink-muted)">
          Notez-la maintenant. L&apos;ancienne ne donne plus accès à rien, et celle-ci ne sera
          pas réaffichée.
        </p>
        <p className="mt-3 rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-3 py-2 font-mono text-xs leading-relaxed">
          {phrase}
        </p>
        <p className="mt-3 text-xs text-(--color-ink-muted)">
          Vos autres appareils doivent être <strong>ré-appairés</strong> : ils détiennent
          l&apos;ancienne clé. Vos correspondants verront un avertissement de changement
          d&apos;empreinte — il est exact, la clé de votre compte a changé.
        </p>
        <button
          type="button"
          onClick={() => {
            setPhrase(null);
            onClose();
          }}
          className="mt-4 rounded-md bg-(--color-accent) px-3 py-1.5 text-sm font-medium text-white"
        >
          Je l&apos;ai notée
        </button>
      </div>
    );
  }

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Vos appareils</h2>
        <button type="button" onClick={onClose} className="text-(--color-ink-muted) underline">
          Fermer
        </button>
      </div>

      <p className="mt-2 text-xs text-(--color-ink-muted)">
        Tous vos appareils ont exactement le même accès, partout. Il n&apos;y a pas
        d&apos;appareil principal.
      </p>

      {account === null ? (
        <p className="mt-3 text-(--color-ink-muted)">Chargement…</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {account.devices.map((device) => (
            <li key={device.id} className="flex items-center justify-between gap-3">
              <span className="font-mono text-xs">
                {device.id}
                {device.id === session.deviceId && (
                  <span className="ml-2 font-sans text-(--color-ink-muted)">(celui-ci)</span>
                )}
              </span>
              {device.id !== session.deviceId && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => revoquer(device.id)}
                  className="shrink-0 text-xs underline text-(--color-ink-muted)"
                >
                  révoquer
                </button>
              )}
            </li>
          ))}

          {account.revoked.map((device) => (
            <li key={device.id} className="flex items-center justify-between gap-3">
              <span className="font-mono text-xs text-(--color-ink-muted) line-through">
                {device.id}
              </span>
              <span className="shrink-0 text-xs text-(--color-ink-muted)">révoqué</span>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-4 border-t border-(--color-border-subtle) pt-3">
        <p className="text-xs text-(--color-ink-muted)">
          <strong>Révoquer</strong> convient à un appareil perdu ou hors service : il cesse de
          recevoir, et ne déchiffre plus la suite des conversations.
        </p>

        {rotation ? (
          <div className="mt-3 space-y-2 rounded-md border border-(--color-danger) bg-(--color-danger)/10 p-3">
            <p className="font-medium text-(--color-danger)">
              Si un appareil vous a été volé, le révoquer ne suffit pas
            </p>
            <p className="text-xs text-(--color-ink-muted)">
              Il détient la clé de votre compte, comme tous vos appareils. Son porteur peut donc
              en déclarer un nouveau aussitôt. Changer la clé du compte est la seule mesure qui
              l&apos;en empêche.
            </p>
            <p className="text-xs text-(--color-ink-muted)">Ce que cela implique :</p>
            <ul className="list-disc space-y-1 pl-5 text-xs text-(--color-ink-muted)">
              <li>Une nouvelle phrase de récupération. L&apos;ancienne ne vaudra plus rien.</li>
              <li>Vos autres appareils devront être ré-appairés.</li>
              <li>
                Vos correspondants verront un avertissement de changement d&apos;identité, qui
                sera exact.
              </li>
              <li>
                <strong>Tout votre historique sauvegardé deviendra définitivement illisible</strong>
                : il est chiffré sous une clé dérivée de l&apos;ancienne phrase, et rien ne permet
                de le rechiffrer. La sauvegarde étant active par défaut, cela vous concerne même
                si vous ne l&apos;avez jamais réglée.
              </li>
              <li>
                Le voleur détient la même clé que vous et peut agir le premier. Faites-le
                maintenant.
              </li>
            </ul>
            <div className="flex gap-3 pt-1">
              <button
                type="button"
                disabled={busy}
                onClick={tourner}
                className="rounded-md bg-(--color-danger) px-3 py-1.5 text-xs font-medium text-white"
              >
                Changer la clé du compte
              </button>
              <button
                type="button"
                onClick={() => setRotation(false)}
                className="text-xs underline text-(--color-ink-muted)"
              >
                Annuler
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setRotation(true)}
            className="mt-2 text-xs underline text-(--color-danger)"
          >
            Un appareil m&apos;a été volé
          </button>
        )}
      </div>
    </div>
  );
}
