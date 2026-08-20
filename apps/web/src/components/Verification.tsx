import { useState } from "react";
import type { ResolvedAccount } from "@/lib/account";
import type { VerificationState } from "@/lib/session";
import { Fingerprint } from "./Fingerprint";

/**
 * Vérification d'identité : silencieuse en régime nominal, franche sur anomalie.
 *
 * # Pourquoi ne rien afficher tant que tout va bien
 *
 * Un avertissement permanent « identité non vérifiée » s'apprend à ignorer en quelques
 * jours. Le jour où il compte — l'empreinte a changé — il est déjà devenu invisible. Un
 * bandeau perpétuel n'est donc pas une précaution : c'est ce qui rend l'alerte utile
 * inaudible.
 *
 * Signal et WhatsApp ne disent rien en nominal et n'alertent que sur un changement. C'est
 * meilleur pour l'utilisateur *et* pour la sécurité, parce que ça préserve la valeur
 * d'attention de l'alerte.
 *
 * # Ce qui reste à faire pour supprimer le trou de confiance initial
 *
 * Le silence sur `unverified` fait un pari : que le premier KeyPackage servi était bien
 * celui du correspondant (trust on first use). Le combler demande de la **key transparency**
 * — un log Merkle auditable des clés publiques, que le client vérifie automatiquement.
 * C'est ce que déploient WhatsApp et Apple, et c'est ce qui permet de ne rien demander à
 * l'utilisateur sans pour autant faire confiance au serveur.
 *
 * # L'empreinte porte sur le compte, pas sur l'appareil
 *
 * Elle ne bouge donc pas quand le correspondant ajoute un téléphone. C'est délibéré : une
 * empreinte qui changerait à chaque appareil ajouté obligerait à revérifier après chaque
 * événement banal, et serait ignorée en quelques semaines. Les ajouts d'appareils sont
 * signalés à part, par [`DeviceAdded`].
 */
export function Verification({
  account,
  state,
}: {
  account: ResolvedAccount;
  state: VerificationState;
}) {
  // Le serveur a servi un appareil qu'il n'aurait pas pu produire. C'est plus grave qu'un
  // changement d'empreinte : il n'existe aucune explication bénigne.
  if (account.rejected.length > 0) {
    return (
      <div
        role="alert"
        className="border-b border-(--color-danger) bg-(--color-danger)/20 px-4 py-3 text-sm"
      >
        <p className="font-medium text-(--color-danger)">
          Appareil non attesté présenté pour @{account.handle}
        </p>
        <p className="mt-1 text-(--color-ink-muted)">
          Le serveur a annoncé {account.rejected.length} appareil(s) dont la signature ne
          correspond pas à ce compte. Un compte légitime ne peut pas produire cela : soit le
          serveur a été compromis, soit il tente de s&apos;insérer dans la conversation. Ces
          appareils ont été écartés et ne reçoivent rien.
        </p>
      </div>
    );
  }

  // Nominal : rien. Ni coche verte, ni bandeau, ni pastille.
  if (state.status !== "changed") return null;

  return (
    <div
      role="alert"
      className="border-b border-(--color-danger) bg-(--color-danger)/10 px-4 py-3 text-sm"
    >
      <p className="font-medium text-(--color-danger)">
        L&apos;empreinte de @{account.handle} a changé
      </p>
      <p className="mt-1 text-(--color-ink-muted)">
        Soit @{account.handle} a restauré son compte depuis sa phrase de récupération, soit
        quelqu&apos;un s&apos;est interposé. La première explication est rare, la seconde est
        une attaque — et rien dans le protocole ne permet de les distinguer. Vérifiez avant
        d&apos;envoyer quoi que ce soit de sensible.
      </p>
    </div>
  );
}

/**
 * Signale les appareils apparus chez un correspondant.
 *
 * C'est **cette notification, et non l'empreinte, qui détecte un appareil hostile**. Un
 * appareil ajouté par un compte compromis est dûment attesté, donc indiscernable d'un ajout
 * légitime : seul l'utilisateur peut dire s'il possède bien cet appareil. D'où l'affichage
 * plutôt qu'un verdict automatique.
 */
export function DeviceAdded({ handle, devices }: { handle: string; devices: string[] }) {
  if (devices.length === 0) return null;

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-2 text-xs text-(--color-ink-muted)">
      @{handle} a ajouté {devices.length === 1 ? "un appareil" : `${devices.length} appareils`} :{" "}
      {devices.join(", ")}. Si ce n&apos;est pas vous, ce compte est peut-être compromis.
    </div>
  );
}

/**
 * Comparaison manuelle des empreintes, à la demande.
 *
 * Reste accessible pour qui veut vraiment vérifier, sans imposer la démarche à tout le
 * monde. La suite naturelle est un QR code affiché et scanné : deux secondes et aucune
 * erreur de lecture, là où comparer des chiffres à l'œil est pénible et peu fiable — mais
 * cela suppose l'accès à la caméra, hors périmètre ici.
 */
export function VerificationPanel({
  account,
  state,
  myName,
  myFingerprint,
  onVerified,
  onClose,
}: {
  account: ResolvedAccount;
  state: VerificationState;
  myName: string;
  myFingerprint: string;
  onVerified: () => void;
  onClose: () => void;
}) {
  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Vérifier l&apos;identité de @{account.handle}</h2>
        <button type="button" onClick={onClose} className="text-(--color-ink-muted) underline">
          Fermer
        </button>
      </div>

      <p className="mt-2 text-(--color-ink-muted)">
        Comparez ces deux empreintes de vive voix ou par un autre canal. Si elles
        correspondent, personne ne s&apos;est interposé.
      </p>

      <p className="mt-1 text-xs text-(--color-ink-muted)">
        L&apos;empreinte porte sur le compte : elle reste la même quand @{account.handle}
        ajoute ou retire un appareil. Ce compte en déclare actuellement{" "}
        {account.devices.length}.
      </p>

      <div className="mt-4 space-y-3">
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-wide text-(--color-ink-muted)">
            @{account.handle}
          </p>
          <Fingerprint value={account.fingerprint} />
        </div>

        {state.status === "changed" && (
          <div className="space-y-1">
            <p className="text-xs uppercase tracking-wide text-(--color-danger)">
              Empreinte vérifiée précédemment
            </p>
            <Fingerprint value={state.previous} />
          </div>
        )}

        <div className="space-y-1">
          <p className="text-xs uppercase tracking-wide text-(--color-ink-muted)">
            {myName} (la vôtre)
          </p>
          <Fingerprint value={myFingerprint} />
        </div>
      </div>

      {state.status === "verified" ? (
        <p className="mt-4 text-(--color-ok)">✓ Vous avez déjà vérifié cette empreinte.</p>
      ) : (
        <button
          type="button"
          onClick={onVerified}
          className="mt-4 rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white"
        >
          Les empreintes correspondent
        </button>
      )}
    </div>
  );
}

/** Bouton discret d'accès à la vérification, dans l'en-tête de conversation. */
export function VerificationToggle({
  state,
  onClick,
}: {
  state: VerificationState;
  onClick: () => void;
}) {
  const [hover, setHover] = useState(false);
  return (
    <button
      type="button"
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      title="Vérifier l'identité"
      className={`text-xs ${state.status === "verified" ? "text-(--color-ok)" : "text-(--color-ink-muted)"} ${hover ? "underline" : ""}`}
    >
      {state.status === "verified" ? "✓ vérifié" : "vérifier l'identité"}
    </button>
  );
}
