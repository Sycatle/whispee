import { useState } from "react";
import { MIN_LENGTH, bitsApproximatifs, verifier } from "@/lib/password";
import type { Session } from "@/lib/session";

/** Saisie du mot de passe au démarrage, quand un verrou est posé. */
export function Unlock({
  onUnlocked,
  onError,
}: {
  onUnlocked: (session: Session) => void;
  onError: (message: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [refus, setRefus] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setRefus(false);
    try {
      const { Session } = await import("@/lib/session");
      const session = await Session.restore(password);
      if (session) onUnlocked(session);
    } catch {
      // Toute erreur est présentée comme un mot de passe incorrect : distinguer « mauvais mot
      // de passe » de « données corrompues » apprendrait à un attaquant quand il approche.
      setRefus(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">Déverrouiller</h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          Vos conversations sont chiffrées sur cet appareil. Le mot de passe les déverrouille
          ici, et nulle part ailleurs : il n&apos;est jamais transmis au serveur.
        </p>
      </div>

      <form onSubmit={submit} className="space-y-3">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="mot de passe"
          required
          autoFocus
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2"
        />
        <button
          type="submit"
          disabled={busy || !password}
          className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Déverrouillage…" : "Déverrouiller"}
        </button>
      </form>

      {busy && (
        <p className="text-xs text-(--color-ink-muted)">
          La dérivation prend environ une seconde et 64 Mio de mémoire. Cette lenteur est
          délibérée : elle coûte le même prix à chaque essai de quelqu&apos;un qui aurait
          récupéré vos données.
        </p>
      )}

      {refus && (
        <p role="alert" className="text-sm text-(--color-danger)">
          Mot de passe incorrect.
        </p>
      )}

      <button
        type="button"
        onClick={() => {
          void import("@/lib/session").then(({ Session }) =>
            Session.forget().then(() => window.location.reload()),
          );
        }}
        className="text-sm text-(--color-ink-muted) underline"
      >
        J&apos;ai oublié ce mot de passe
      </button>

      <p className="text-xs text-(--color-ink-muted)">
        L&apos;oublier ne fait rien perdre définitivement : effacez cet appareil, puis
        récupérez le compte avec votre phrase de douze mots. Les conversations en cours, elles,
        ne suivront pas — un appareil déjà en place devra vous y réintégrer.
      </p>
    </main>
  );
}

/** Réglage du verrou depuis l'application. */
export function LockSettings({ session, onDone }: { session: Session; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const verdict = verifier(password);
  const bits = bitsApproximatifs(password);
  const concordent = password === confirmation;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (session.locked) {
        await session.disableLock(password);
      } else {
        await session.enableLock(password);
      }
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (session.locked) {
    return (
      <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="font-medium">Retirer le verrou</h2>
          <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
            Fermer
          </button>
        </div>
        <p className="mt-2 text-(--color-ink-muted)">
          Sans verrou, vos conversations restent chiffrées sur le disque, mais quiconque ouvre
          ce navigateur peut les lire.
        </p>
        <form onSubmit={submit} className="mt-3 flex gap-2">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="mot de passe actuel"
            required
            className="flex-1 rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1.5"
          />
          <button
            type="submit"
            disabled={busy || !password}
            className="rounded-md bg-(--color-danger) px-3 py-1.5 font-medium text-white disabled:opacity-50"
          >
            {busy ? "…" : "Retirer"}
          </button>
        </form>
        {error && (
          <p role="alert" className="mt-2 text-(--color-danger)">
            Mot de passe incorrect.
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Verrouiller cet appareil</h2>
        <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
          Fermer
        </button>
      </div>

      <p className="mt-2 text-(--color-ink-muted)">
        Vos conversations seront chiffrées par ce mot de passe, qui ne quitte jamais cet
        appareil. Ce n&apos;est pas un moyen de récupération : l&apos;oublier ne fait rien
        perdre, votre phrase de douze mots reste le seul chemin de restauration.
      </p>

      <form onSubmit={submit} className="mt-3 space-y-2">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={`mot de passe (${MIN_LENGTH} caractères minimum)`}
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1.5"
        />
        <input
          type="password"
          value={confirmation}
          onChange={(e) => setConfirmation(e.target.value)}
          placeholder="confirmation"
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1.5"
        />

        {password && !verdict.ok && (
          <p className="text-(--color-danger)">{verdict.raison}</p>
        )}
        {password && verdict.ok && (
          <p className="text-xs text-(--color-ink-muted)">
            Environ {bits} bits, en supposant des caractères tirés au hasard — ce qu&apos;un
            humain ne fait jamais. Prenez cette valeur pour un plafond, pas pour une garantie.
          </p>
        )}
        {confirmation && !concordent && (
          <p className="text-(--color-danger)">Les deux saisies diffèrent.</p>
        )}

        <button
          type="submit"
          disabled={busy || !verdict.ok || !concordent}
          className="rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Chiffrement…" : "Activer le verrou"}
        </button>
      </form>

      {error && (
        <p role="alert" className="mt-2 text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}
