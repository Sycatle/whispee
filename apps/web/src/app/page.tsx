"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Attachment } from "@/components/Attachment";
import { DeviceSettings } from "@/components/Devices";
import { GroupPanel, GroupToggle } from "@/components/Group";
import { LockSettings, Unlock } from "@/components/Lock";
import { PairDevice, ShowPairingCode, usePairingOffer } from "@/components/Pairing";
import { VaultSettings } from "@/components/Vault";
import { Messages } from "@/components/Messages";
import { SignalSettings } from "@/components/Signals";
import { Verification, VerificationPanel, VerificationToggle } from "@/components/Verification";
import { type ConversationView, Session } from "@/lib/session";
import { supportsEd25519 } from "@/lib/keys";

/**
 * Intervalle de relève, désormais un filet plutôt qu'un moteur.
 *
 * Le flux temps réel apporte les nouveautés en moins d'une seconde ; ce qui reste ici est
 * l'entretien qui n'a pas d'événement déclencheur — réapprovisionnement des clés d'accueil,
 * découverte de nouvelles conversations, propagation vers nos autres appareils, éviction des
 * appareils révoqués.
 *
 * Le raccourcir ne rendrait rien plus rapide : cela ne ferait que redonner au serveur le
 * journal d'activité à la seconde près que le flux vient de lui retirer.
 */
const POLL_MS = 30_000;

export default function Page() {
  const [session, setSession] = useState<Session | null>(null);
  const [active, setActive] = useState<ConversationView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [locked, setLocked] = useState(false);
  const [, forceRender] = useState(0);
  const refresh = useCallback(() => forceRender((n) => n + 1), []);

  useEffect(() => {
    // Le verrou se détecte avant toute tentative de restauration : sans mot de passe, l'état
    // est illisible, et traiter cela comme une erreur de déchiffrement effacerait la
    // distinction entre « verrouillé » et « corrompu ».
    Session.isLocked()
      .then((verrouillee) => {
        if (verrouillee) {
          setLocked(true);
          return null;
        }
        return Session.restore();
      })
      .then(setSession)
      .catch((e) => {
        // Un état illisible ne doit pas bloquer l'écran de démarrage : mieux vaut proposer
        // de repartir d'une identité neuve que de laisser un « Chargement… » éternel.
        console.error("restauration de session impossible", e);
        setError(
          "Impossible de restaurer la session précédente. Effacez l'identité pour repartir de zéro.",
        );
      })
      .finally(() => setBusy(false));
  }, []);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;

    const tick = async () => {
      try {
        await session.poll();
        if (cancelled) return;

        // Ouvre la première conversation tant qu'aucune n'est sélectionnée.
        //
        // Un appareil fraîchement appairé découvre ses conversations pendant la relève : sans
        // cela il affiche une liste à gauche et un vide à droite, et les messages semblent ne
        // pas arriver alors qu'ils sont déjà déchiffrés.
        setActive((current) => current ?? session.conversations.values().next().value ?? null);

        // Une relève réussie efface l'erreur précédente.
        //
        // Sans cela, un incident passager — réseau coupé, serveur redémarré — laisse un
        // bandeau rouge indéfiniment à l'écran, alors que tout refonctionne. Une alerte qui
        // survit à sa cause s'apprend à ignorer, et le jour où elle compte, elle est déjà
        // devenue invisible.
        setError(null);
        refresh();
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    };

    void tick();
    const id = setInterval(tick, POLL_MS);

    // Le flux n'est pas une dépendance de la relève : il la déclenche plus tôt, rien de plus.
    // S'il ne se connecte jamais, l'intervalle ci-dessus suffit à tout faire fonctionner.
    session.startStream(() => {
      if (!cancelled) refresh();
    });

    return () => {
      cancelled = true;
      clearInterval(id);
      session.stopStream();
    };
  }, [session, refresh]);

  if (busy) return <Centered>Chargement…</Centered>;

  if (locked && !session) {
    return (
      <Unlock
        onUnlocked={(s) => {
          setSession(s);
          setLocked(false);
        }}
        onError={setError}
      />
    );
  }

  if (!session) {
    return <Onboarding onReady={setSession} onError={setError} error={error} />;
  }

  const conversations = [...session.conversations.values()];
  const current = active && session.conversations.get(active.key) ? active : conversations[0] ?? null;

  return (
    <div className="mx-auto flex h-dvh max-w-5xl flex-col">
      <Header session={session} onForget={() => session.forget().then(() => location.reload())} />

      {/*
        Les anomalies du journal de clés sont affichées au niveau de l'application, pas d'une
        conversation : elles portent sur l'identité des comptes, donc sur toutes les
        conversations à la fois.
      */}
      {session.logAlerts.length > 0 && (
        <div role="alert" className="border-b border-(--color-danger) bg-(--color-danger)/20 px-4 py-3 text-sm">
          <p className="font-medium text-(--color-danger)">Journal de clés incohérent</p>
          {session.logAlerts.map((alerte) => (
            <p key={alerte} className="mt-1 text-(--color-ink-muted)">
              {alerte}
            </p>
          ))}
          <p className="mt-2 text-xs text-(--color-ink-muted)">
            Le serveur a échoué à prouver ce qu&apos;il affirme sur les clés des comptes. Ce
            n&apos;est pas une panne réseau : c&apos;est exactement ce que ce contrôle existe
            pour détecter.
          </p>
        </div>
      )}

      <div className="flex min-h-0 flex-1">
        <Sidebar
          session={session}
          conversations={conversations}
          current={current}
          onSelect={setActive}
          onError={setError}
          onChanged={refresh}
        />
        {current ? (
          <Conversation session={session} view={current} onChanged={refresh} onError={setError} />
        ) : (
          <Centered>Aucune conversation. Ouvrez-en une avec le pseudonyme d&apos;un correspondant.</Centered>
        )}
      </div>

      {error && (
        <p
          role="alert"
          className="flex items-baseline justify-between gap-4 border-t border-(--color-danger) bg-(--color-danger)/10 px-4 py-2 text-sm text-(--color-danger)"
        >
          <span>{error}</span>
          {/* Toujours refermable : une erreur qu'on ne peut pas écarter finit par faire
              partie du décor. */}
          <button type="button" onClick={() => setError(null)} className="shrink-0 underline">
            Fermer
          </button>
        </p>
      )}
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-1 items-center justify-center p-8 text-center text-sm text-(--color-ink-muted)">
      {children}
    </div>
  );
}

function Header({ session, onForget }: { session: Session; onForget: () => void }) {
  return (
    <header className="border-b border-(--color-border-subtle) px-4 py-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        {/*
          L'empreinte de l'utilisateur n'est plus affichée en permanence : elle ne lui sert
          à rien au quotidien. Elle vit désormais dans le panneau de vérification, avec
          celle du correspondant — c'est-à-dire au seul endroit où on en a besoin.
        */}
        <h1 className="font-medium">
          @{session.handle}{" "}
          <span className="font-normal text-(--color-ink-muted)">
            · {session.deviceId.slice(session.handle.length + 1)}
          </span>
        </h1>
        <button type="button" onClick={onForget} className="text-sm text-(--color-ink-muted) underline">
          Effacer cette identité
        </button>
      </div>
      {/*
        Cet avertissement reste, lui, parce qu'il ne concerne pas une conversation mais
        l'outil entier : c'est une limite que l'utilisateur doit connaître pour décider quoi
        lui confier.
      */}
      <p className="mt-2 text-xs text-(--color-ink-muted)">
        Client web : le serveur livre ce code à chaque chargement et pourrait en livrer une
        version qui exfiltre vos clés. Aucune API navigateur ne corrige cela. Projet
        d&apos;apprentissage, non audité — pour des échanges réellement sensibles, utilisez Signal.
      </p>
    </header>
  );
}

function Onboarding({
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

function Sidebar({
  session,
  conversations,
  current,
  onSelect,
  onError,
  onChanged,
}: {
  session: Session;
  conversations: ConversationView[];
  current: ConversationView | null;
  onSelect: (view: ConversationView) => void;
  onError: (message: string) => void;
  onChanged: () => void;
}) {
  const [peer, setPeer] = useState("");
  const [pairing, setPairing] = useState(false);
  const [lockPanel, setLockPanel] = useState(false);
  const [vaultPanel, setVaultPanel] = useState(false);
  const [devicePanel, setDevicePanel] = useState(false);
  const [signalPanel, setSignalPanel] = useState(false);

  const start = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      // Plusieurs pseudonymes séparés par des virgules ouvrent un groupe. Au-delà d'un
      // correspondant, le créateur en devient le premier administrateur.
      const handles = peer
        .split(",")
        .map((handle) => handle.trim().replace(/^@/, ""))
        .filter((handle) => handle.length > 0);

      onSelect(await session.startConversation(handles));
      setPeer("");
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-(--color-border-subtle)">
      <form onSubmit={start} className="space-y-2 border-b border-(--color-border-subtle) p-3">
        <input
          value={peer}
          onChange={(e) => setPeer(e.target.value)}
          placeholder="bob, ou bob, carol"
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-2 py-1.5 text-sm"
        />
        <button type="submit" className="w-full rounded-md bg-(--color-accent) px-2 py-1.5 text-sm text-white">
          Ouvrir une conversation
        </button>
      </form>

      {pairing && <PairDevice session={session} onDone={() => setPairing(false)} />}
      {lockPanel && (
        <LockSettings
          session={session}
          onDone={() => {
            setLockPanel(false);
            onChanged();
          }}
        />
      )}

      {vaultPanel && (
        <VaultSettings
          session={session}
          active={current}
          onDone={() => {
            setVaultPanel(false);
            onChanged();
          }}
        />
      )}

      {signalPanel && (
        <div className="border-b border-(--color-border-subtle) p-3">
          <SignalSettings session={session} onError={onError} />
          <button
            type="button"
            onClick={() => setSignalPanel(false)}
            className="mt-3 text-xs underline opacity-70"
          >
            Fermer
          </button>
        </div>
      )}

      {devicePanel && (
        <DeviceSettings
          session={session}
          onError={onError}
          onClose={() => {
            setDevicePanel(false);
            onChanged();
          }}
        />
      )}

      {!pairing && !lockPanel && !vaultPanel && !devicePanel && !signalPanel && (
        <div className="flex flex-col gap-1 border-b border-(--color-border-subtle) px-3 py-2 text-left text-xs text-(--color-ink-muted)">
          <button type="button" onClick={() => setPairing(true)} className="text-left underline">
            Ajouter un appareil
          </button>
          <button type="button" onClick={() => setDevicePanel(true)} className="text-left underline">
            Vos appareils
          </button>
          <button type="button" onClick={() => setLockPanel(true)} className="text-left underline">
            {session.locked ? "Retirer le verrou" : "Verrouiller cet appareil"}
          </button>
          <button type="button" onClick={() => setVaultPanel(true)} className="text-left underline">
            {/* L'état coupé se lit comme une anomalie choisie, pas comme une invitation. */}
            {session.archiving ? "Sauvegarde de l'historique" : "Sauvegarde désactivée"}
          </button>
          <button type="button" onClick={() => setSignalPanel(true)} className="text-left underline">
            Accusés et indicateurs
          </button>
        </div>
      )}

      {/*
        Ni epoch, ni stock de clés d'accueil. L'epoch est un détail de débogage, et le stock
        se reconstitue tout seul à chaque relève — l'exposer transformerait de l'entretien
        automatique en inquiétude pour l'utilisateur.
      */}
      <ul className="min-h-0 flex-1 overflow-y-auto">
        {conversations.map((view) => (
          <li key={view.key}>
            <button
              type="button"
              onClick={() => onSelect(view)}
              className={`w-full px-3 py-2 text-left text-sm ${
                current?.key === view.key ? "bg-(--color-surface-raised) font-medium" : ""
              }`}
            >
              {view.accounts.map((a) => `@${a.handle}`).join(", ") ||
                [...new Set(view.peers.map((p) => p.name))].map((n) => `@${n}`).join(", ") ||
                "conversation vide"}
            </button>
          </li>
        ))}
      </ul>
    </aside>
  );
}

function Conversation({
  session,
  view,
  onChanged,
  onError,
}: {
  session: Session;
  view: ConversationView;
  onChanged: () => void;
  onError: (message: string) => void;
}) {
  const [text, setText] = useState("");
  const [verifying, setVerifying] = useState<string | null>(null);
  const [group, setGroup] = useState(false);
  const [sending, setSending] = useState(false);
  const [replyTo, setReplyTo] = useState<number | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  // Rapatriement de l'historique archivé, à l'ouverture de la conversation.
  //
  // Paresseux et non bloquant : la conversation s'affiche tout de suite, le passé se remplit
  // derrière. `hydrate` ne fait le travail qu'une fois par session — l'effet peut donc se
  // rejouer sans conséquence quand la vue change d'identité.
  useEffect(() => {
    session
      .hydrate(view)
      .then((restaures) => {
        if (restaures > 0) onChanged();
      })
      .catch((e: unknown) => onError(e instanceof Error ? e.message : String(e)));
  }, [session, view, onChanged, onError]);

  const send = async (event: React.FormEvent) => {
    event.preventDefault();
    const body = text.trim();
    if (!body) return;
    setText("");
    const cite = replyTo;
    setReplyTo(null);
    try {
      if (cite !== null) await session.replyTo(view, cite, body);
      else await session.send(view, body);
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  /**
   * Signale la frappe à chaque touche — le débounce est dans `Session`.
   *
   * Le placer ici obligerait chaque appelant à le refaire, et c'est le genre de garde qu'on
   * oublie : un dépôt réseau par touche enfoncée.
   */
  const typing = (valeur: string) => {
    setText(valeur);
    if (valeur) void session.notifyTyping(view).catch(() => {});
  };

  const attach = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    // Le champ est réinitialisé tout de suite : sans cela, renvoyer deux fois le même
    // fichier ne déclencherait pas de second `change`.
    event.target.value = "";
    if (!file) return;

    setSending(true);
    try {
      await session.sendAttachment(view, file);
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
  };

  const title =
    view.accounts.map((a) => `@${a.handle}`).join(", ") ||
    [...new Set(view.peers.map((p) => p.name))].map((n) => `@${n}`).join(", ") ||
    "conversation vide";

  return (
    <section className="flex min-w-0 flex-1 flex-col">
      <header className="flex items-baseline justify-between gap-4 border-b border-(--color-border-subtle) px-4 py-2">
        {/*
          L'epoch n'est pas affichée — c'est un détail de protocole qui n'apprend rien à
          l'utilisateur. Elle est exposée en attribut parce que deux membres à des epochs
          différentes ne peuvent plus se lire du tout : c'est la première chose à regarder
          quand un message n'arrive pas, et la chercher autrement demande d'instrumenter le
          module WebAssembly.
        */}
        <h2 className="truncate text-sm font-medium" data-epoch={String(view.epoch)}>
          {title}
        </h2>
        <div className="flex shrink-0 gap-3">
          {view.accounts.length > 1 && (
            <GroupToggle count={view.accounts.length} onClick={() => setGroup(!group)} />
          )}
          {view.accounts.map((account) => (
            <VerificationToggle
              key={account.handle}
              state={session.verificationOf(account)}
              onClick={() => setVerifying(verifying === account.handle ? null : account.handle)}
            />
          ))}
        </div>
      </header>

      {group && (
        <GroupPanel
          session={session}
          view={view}
          onError={onError}
          onChanged={onChanged}
          onClose={() => setGroup(false)}
        />
      )}

      {/*
        Alerte uniquement sur changement d'empreinte. En nominal, ce composant ne rend rien :
        un avertissement permanent s'apprend à ignorer, et rendrait celui-ci inaudible le
        jour où il compte.
      */}
      {view.accounts.map((account) => (
        <Verification
          key={account.handle}
          account={account}
          state={session.verificationOf(account)}
        />
      ))}

      {view.accounts
        .filter((account) => account.handle === verifying)
        .map((account) => (
          <VerificationPanel
            key={account.handle}
            account={account}
            state={session.verificationOf(account)}
            myName={`@${session.handle}`}
            myFingerprint={session.accountFingerprint()}
            onVerified={() => void session.markVerified(account).then(onChanged)}
            onClose={() => setVerifying(null)}
          />
        ))}

      <Messages
        session={session}
        view={view}
        onChanged={onChanged}
        onError={onError}
        onReplyTo={setReplyTo}
      />


      {replyTo !== null && (
        <div className="flex items-center justify-between gap-2 border-t border-(--color-border-subtle) px-4 py-1 text-xs opacity-70">
          <span className="truncate">Réponse au message {replyTo}</span>
          <button type="button" onClick={() => setReplyTo(null)} className="shrink-0">
            annuler
          </button>
        </div>
      )}

      <form onSubmit={send} className="flex items-center gap-2 border-t border-(--color-border-subtle) p-3">
        <input ref={fileInput} type="file" onChange={attach} className="hidden" />
        <button
          type="button"
          onClick={() => fileInput.current?.click()}
          disabled={sending}
          title="Joindre un fichier"
          className="rounded-md border border-(--color-border-subtle) px-3 py-2 text-sm disabled:opacity-50"
        >
          {sending ? "…" : "📎"}
        </button>
        <input
          value={text}
          onChange={(e) => typing(e.target.value)}
          placeholder={replyTo === null ? "Message" : "Réponse"}
          className="min-w-0 flex-1 rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2"
        />
        <button type="submit" className="rounded-md bg-(--color-accent) px-4 py-2 text-sm font-medium text-white">
          Envoyer
        </button>
      </form>
    </section>
  );
}
