import { useCallback, useEffect, useState } from "react";
import { Unlock } from "@/components/Lock";
import { Conversation } from "@/components/Conversation";
import { ConversationList } from "@/components/ConversationList";
import { Onboarding } from "@/components/Onboarding";
import { MigrationBanner } from "@/components/Migration";
import { type ConversationView, type MigrationProposee, Session, demarrer } from "@/lib/session";

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

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [active, setActive] = useState<ConversationView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  /** Pourquoi la migration est impossible, s'il y a lieu. Informatif : rien n'est cassé. */
  const [repli, setRepli] = useState<string | null>(null);
  /**
   * Migration proposée, tant que l'utilisateur ne l'a ni lancée ni écartée.
   *
   * Proposée et non exécutée : elle enregistre un appareil et en révoque un autre, ce que rien
   * dans « ouvrir l'application » ne demande.
   */
  const [migration, setMigration] = useState<MigrationProposee | null>(null);
  const [locked, setLocked] = useState(false);
  const [, forceRender] = useState(0);
  const refresh = useCallback(() => forceRender((n) => n + 1), []);

  useEffect(() => {
    // Le verrou se détecte avant toute tentative de restauration : sans mot de passe, l'état
    // est illisible, et traiter cela comme une erreur de déchiffrement effacerait la
    // distinction entre « verrouillé » et « corrompu ».
    Session.isLocked()
      .then(async (verrouillee) => {
        if (verrouillee) {
          setLocked(true);
          return null;
        }

        // `demarrer` et non `restore` : sous Tauri, une installation existante peut avoir une
        // migration à faire, ce qui suppose de tenir l'ancienne session ouverte.
        const { session, migration: proposee, repli: refuse } = await demarrer();
        if (refuse) setRepli(refuse);
        if (proposee) setMigration(proposee);
        return session;
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
        onUnlocked={(s, proposee) => {
          setSession(s);
          if (proposee) setMigration(proposee);
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
        <ConversationList
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

      {migration && (
        <MigrationBanner
          migration={migration}
          onDone={(nouvelle) => {
            setMigration(null);
            setActive(null);
            setSession(nouvelle);
          }}
          onError={setError}
        />
      )}

      {repli && (
        <p className="flex items-baseline justify-between gap-4 border-t border-(--color-ink-muted)/30 bg-(--color-ink-muted)/10 px-4 py-2 text-sm text-(--color-ink-muted)">
          <span>{repli}</span>
          <button type="button" onClick={() => setRepli(null)} className="shrink-0 underline">
            Fermer
          </button>
        </p>
      )}

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
