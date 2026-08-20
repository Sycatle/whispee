import { useEffect, useState } from "react";
import { ShowPairingCode, usePairingOffer } from "@/components/Pairing";
import { Session } from "@/lib/session";
import { supportsEd25519 } from "@/lib/keys";

export function Onboarding({
  onReady,
  onError,
  error,
}: {
  onReady: (session: Session) => void;
  onError: (message: string) => void;
  error: string | null;
}) {
  const [handle, setHandle] = useState("");
  const [phrase, setPhrase] = useState("");
  const [mode, setMode] = useState<"create" | "restore" | "pair">("create");
  const [busy, setBusy] = useState(false);
  const [ed25519, setEd25519] = useState<boolean | null>(null);
  /** La phrase produite à la création. Affichée une fois, jamais réaffichable ensuite. */
  const [recovery, setRecovery] = useState<{ phrase: string; session: Session } | null>(null);

  useEffect(() => {
    void supportsEd25519().then(setEd25519);
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      if (mode === "create") {
        const [session, generated] = await Session.create(handle.trim());
        // On ne remet pas la session tout de suite : l'utilisateur doit d'abord voir sa
        // phrase. Passer directement à la conversation la lui ferait perdre définitivement.
        setRecovery({ phrase: generated, session });
      } else {
        onReady(await Session.restoreFromPhrase(handle.trim(), phrase));
      }
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (recovery) {
    return <RecoveryPhrase phrase={recovery.phrase} onAcknowledged={() => onReady(recovery.session)} />;
  }

  if (mode === "pair") {
    return <PairThisDevice onReady={onReady} onError={onError} onCancel={() => setMode("create")} />;
  }

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">
          {mode === "create" ? "Nouveau compte" : "Récupérer mon compte"}
        </h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          Votre pseudonyme est transporté en clair et visible du serveur comme de tous vos
          correspondants. N&apos;y mettez rien de sensible, et surtout pas de numéro de
          téléphone ni d&apos;adresse e-mail — ce système n&apos;en demande aucun.
        </p>
        <p className="mt-2 text-xs text-(--color-ink-muted)">
          Cet appareil sera nommé automatiquement d&apos;après son type. Rien de plus précis :
          un modèle exact distinguerait son porteur bien au-delà de ce qu&apos;exige
          l&apos;acheminement des messages.
        </p>
      </div>

      {ed25519 === false && (
        <p role="alert" className="rounded-md border border-(--color-danger) bg-(--color-danger)/10 p-3 text-sm text-(--color-danger)">
          Ce navigateur ne prend pas en charge Ed25519 dans WebCrypto. Plutôt que de replier
          sur une implémentation JavaScript — où la clé privée resterait exposée en mémoire du
          script — l&apos;application refuse de créer une identité. Utilisez un navigateur à jour.
        </p>
      )}

      <form onSubmit={submit} className="space-y-3">
        <input
          value={handle}
          onChange={(e) => setHandle(e.target.value)}
          placeholder="pseudonyme (alice)"
          required
          maxLength={64}
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2"
        />
        {mode === "restore" && (
          <textarea
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            placeholder="vos douze mots de récupération"
            required
            rows={3}
            className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2 text-sm"
          />
        )}

        <button
          type="submit"
          disabled={busy || !handle.trim() || ed25519 !== true}
          className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50"
        >
          {busy ? "En cours…" : mode === "create" ? "Créer le compte" : "Récupérer le compte"}
        </button>
      </form>

      <div className="flex flex-col gap-2 text-sm text-(--color-ink-muted)">
        {mode === "create" ? (
          <>
            <button type="button" onClick={() => setMode("pair")} className="underline">
              Ajouter cet appareil à un compte existant
            </button>
            <button type="button" onClick={() => setMode("restore")} className="underline">
              J&apos;ai perdu tous mes appareils — récupérer avec ma phrase
            </button>
          </>
        ) : (
          <button type="button" onClick={() => setMode("create")} className="underline">
            Créer un nouveau compte
          </button>
        )}
      </div>

      {mode === "restore" && (
        <p className="text-xs text-(--color-ink-muted)">
          À n&apos;utiliser que si vous avez perdu tous vos appareils. Pour en ajouter un
          nouveau alors que vous en avez encore un sous la main, faites-le depuis celui-ci :
          votre phrase n&apos;a alors aucune raison d&apos;être ressaisie, donc aucune raison
          d&apos;être exposée.
          <br />
          Vous retrouverez votre compte, mais pas vos conversations en cours : elles vivent
          dans des groupes chiffrés dont ce nouvel appareil n&apos;est pas membre. Votre
          historique sauvegardé, lui, existe toujours et votre phrase l&apos;ouvre — mais tant
          que quelqu&apos;un ne vous a pas réintégré à la conversation, cet appareil ignore
          jusqu&apos;à son existence et ne peut pas aller le chercher.
        </p>
      )}

      {error && (
        <p role="alert" className="text-sm text-(--color-danger)">
          {error}
        </p>
      )}
    </main>
  );
}

/**
 * Nouvel appareil en attente d'appairage.
 *
 * Il affiche son code et attend. Il n'a aucun secret à saisir : c'est tout l'intérêt du sens
 * choisi — le code étant photographiable, il ne doit rien contenir de sensible.
 */
function PairThisDevice({
  onReady,
  onError,
  onCancel,
}: {
  onReady: (session: Session) => void;
  onError: (message: string) => void;
  onCancel: () => void;
}) {
  const [handle, setHandle] = useState("");
  const [started, setStarted] = useState(false);
  const { code, seed, confirmation, error } = usePairingOffer(started);

  useEffect(() => {
    if (!seed) return;
    Session.fromSeed(handle.trim(), seed)
      .then(onReady)
      .catch((e: unknown) => onError(e instanceof Error ? e.message : String(e)));
  }, [seed, handle, onReady, onError]);

  useEffect(() => {
    if (error) onError(error);
  }, [error, onError]);

  if (started && code) {
    return <ShowPairingCode code={code} confirmation={confirmation} onCancel={onCancel} />;
  }

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">Ajouter cet appareil</h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          Indiquez le pseudonyme du compte, puis recopiez le code affiché ici sur un appareil
          où vous êtes déjà connecté.
        </p>
      </div>

      <input
        value={handle}
        onChange={(e) => setHandle(e.target.value)}
        placeholder="pseudonyme du compte"
        maxLength={64}
        className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2"
      />

      <button
        type="button"
        disabled={!handle.trim()}
        onClick={() => setStarted(true)}
        className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50"
      >
        Afficher le code d&apos;appairage
      </button>

      <button type="button" onClick={onCancel} className="text-sm text-(--color-ink-muted) underline">
        Retour
      </button>
    </main>
  );
}

/**
 * Affichage unique de la phrase de récupération.
 *
 * Elle n'est pas conservée et ne pourra pas être réaffichée. C'est délibéré : une phrase que
 * l'application sait remontrer est une phrase que quiconque tient l'appareil déverrouillé
 * peut remontrer aussi. L'écran force donc une confirmation explicite.
 */
function RecoveryPhrase({
  phrase,
  onAcknowledged,
}: {
  phrase: string;
  onAcknowledged: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">Votre phrase de récupération</h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          Ces douze mots sont le <strong>seul</strong> moyen de retrouver votre compte si vous
          perdez tous vos appareils. Ils ne quittent jamais cet appareil : le serveur ne les
          connaît pas et ne peut pas vous les redonner.
        </p>
      </div>

      <ol className="grid grid-cols-3 gap-2 rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) p-4 font-mono text-sm">
        {phrase.split(/\s+/).map((word, index) => (
          <li key={word + String(index)} className="tabular-nums">
            <span className="text-(--color-ink-muted)">{index + 1}.</span> {word}
          </li>
        ))}
      </ol>

      <p className="text-sm text-(--color-danger)">
        Notez-les hors ligne. Cet écran ne pourra pas être réaffiché — pas par précaution
        excessive, mais parce que l&apos;application ne conserve pas la phrase.
      </p>

      {/*
        Dit ici, et pas dans un écran de réglage que personne n'ouvrira : c'est le moment où
        ces douze mots deviennent aussi la clé de l'historique. La sauvegarde est active par
        défaut, donc le compromis se prend maintenant, à l'endroit où la phrase est à l'écran.
      */}
      <p className="text-sm text-(--color-ink-muted)">
        Ces douze mots chiffrent aussi votre historique sauvegardé. Qui les obtient peut donc
        relire tout votre passé archivé, y compris rétroactivement. Vous pouvez couper cette
        sauvegarde dans les réglages.
      </p>

      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          className="mt-1"
        />
        <span>J&apos;ai noté ces douze mots et je comprends qu&apos;ils sont irrécupérables.</span>
      </label>

      <button
        type="button"
        disabled={!confirmed}
        onClick={onAcknowledged}
        className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50"
      >
        Continuer
      </button>
    </main>
  );
}
