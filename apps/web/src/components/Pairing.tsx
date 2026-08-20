"use client";

import { useEffect, useRef, useState } from "react";
import type { Session } from "@/lib/session";

/**
 * Ajout d'un appareil, côté appareil **déjà authentifié**.
 *
 * C'est ici que doit se passer l'ajout, et non sur l'écran d'accueil : tant qu'on tient un
 * appareil en main, il n'y a aucune raison de ressaisir la phrase de récupération — donc
 * aucune raison de l'exposer une seconde fois.
 */
export function PairDevice({ session, onDone }: { session: Session; onDone: () => void }) {
  const [code, setCode] = useState("");
  const [confirmation, setConfirmation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setConfirmation(await session.pairDevice(code.trim()));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (confirmation) {
    return (
      <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
        <h2 className="font-medium">Code de confirmation</h2>
        <p className="mt-2 text-(--color-ink-muted)">
          Ce code doit être identique sur les deux écrans. S&apos;il diffère, interrompez :
          vous n&apos;êtes pas en train d&apos;appairer l&apos;appareil que vous croyez.
        </p>
        <p className="mt-3 font-mono text-2xl tracking-widest">{confirmation}</p>
        <p className="mt-3 text-xs text-(--color-ink-muted)">
          Le nouvel appareil rejoint vos conversations en cours dans les secondes qui suivent.
        </p>
        <button
          type="button"
          onClick={onDone}
          className="mt-4 rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white"
        >
          Terminé
        </button>
      </div>
    );
  }

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Ajouter un appareil</h2>
        <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
          Fermer
        </button>
      </div>

      <p className="mt-2 text-(--color-ink-muted)">
        Sur le nouvel appareil, choisissez « Ajouter cet appareil à un compte » et recopiez ici
        le code affiché. Ce code ne contient aucun secret : il n&apos;est qu&apos;une clé
        publique éphémère, inutilisable par qui l&apos;intercepte.
      </p>

      <form onSubmit={submit} className="mt-3 space-y-2">
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="code affiché par le nouvel appareil"
          rows={2}
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1.5 font-mono text-xs"
        />
        <button
          type="submit"
          disabled={busy || !code.trim()}
          className="rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Envoi…" : "Appairer"}
        </button>
      </form>

      {error && (
        <p role="alert" className="mt-3 text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}

/**
 * Écran du **nouvel** appareil : il affiche, il n'entre rien.
 *
 * Ce sens est obligatoire. Un code affiché est photographiable ; il ne doit donc contenir
 * aucun secret. C'est l'appareil d'origine qui scelle et envoie, dans ce sens-là uniquement.
 */
export function ShowPairingCode({
  code,
  confirmation,
  onCancel,
}: {
  code: string;
  confirmation: string | null;
  onCancel: () => void;
}) {
  const [copied, setCopied] = useState(false);

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">Ajouter cet appareil</h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          Sur un appareil où vous êtes déjà connecté, ouvrez « Ajouter un appareil » et
          recopiez-y ce code. Il ne contient aucun secret : votre phrase de récupération reste
          là où elle est, et n&apos;a pas à être ressaisie.
        </p>
      </div>

      <div className="space-y-2">
        <p className="break-all rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) p-4 font-mono text-xs">
          {code}
        </p>
        <button
          type="button"
          onClick={() => {
            void navigator.clipboard.writeText(code).then(() => setCopied(true));
          }}
          className="text-sm text-(--color-ink-muted) underline"
        >
          {copied ? "Copié" : "Copier le code"}
        </button>
      </div>

      {confirmation ? (
        <div>
          <p className="text-sm">Code de confirmation :</p>
          <p className="mt-1 font-mono text-2xl tracking-widest">{confirmation}</p>
          <p className="mt-2 text-xs text-(--color-ink-muted)">
            Il doit être identique sur les deux écrans.
          </p>
        </div>
      ) : (
        <p className="text-sm text-(--color-ink-muted)">En attente de l&apos;autre appareil…</p>
      )}

      <button type="button" onClick={onCancel} className="text-sm text-(--color-ink-muted) underline">
        Annuler
      </button>
    </main>
  );
}

/** Génère l'offre et attend le paquet. Isolé en hook : la boucle doit s'arrêter au démontage. */
export function usePairingOffer(enabled: boolean) {
  const [code, setCode] = useState<string | null>(null);
  const [seed, setSeed] = useState<Uint8Array | null>(null);
  const [confirmation, setConfirmation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const cancel = useRef({ cancelled: false });

  useEffect(() => {
    if (!enabled) return;
    const signal = { cancelled: false };
    cancel.current = signal;

    void (async () => {
      const { loadCrypto } = await import("@/lib/wasm");
      const { encodePairingCode, awaitPairing } = await import("@/lib/pairing");
      const crypto = await loadCrypto();

      const offer = new crypto.Pairing();
      const id = offer.id();
      setCode(encodePairingCode({ id, publicKey: offer.publicKey() }));

      try {
        const sealed = await awaitPairing(id, signal);
        if (!sealed || signal.cancelled) return;

        const opened = offer.open(sealed) as { plaintext: Uint8Array; confirmation: string };
        setConfirmation(opened.confirmation);
        setSeed(opened.plaintext);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();

    return () => {
      signal.cancelled = true;
    };
  }, [enabled]);

  return { code, seed, confirmation, error };
}
