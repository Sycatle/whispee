import { useCallback, useEffect, useRef, useState } from "react";
import { Unlock } from "@/components/Lock";
import { Conversation } from "@/components/Conversation";
import { ConversationList } from "@/components/ConversationList";
import { Onboarding } from "@/components/Onboarding";
import { MigrationBanner } from "@/components/Migration";
import { type ConversationView, type MigrationProposee, Session, demarrer } from "@/lib/session";
import { useDuo } from "@/lib/duo";
import { REVERROUILLAGE_MS, observerCycle, reseauDeclare } from "@/lib/lifecycle";

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
  /**
   * Le système déclare-t-il une connexion ?
   *
   * Affiché parce que `false` est une information sûre et qu'elle explique tous les échecs à
   * venir. L'inverse ne prouve rien — un portail captif se déclare en ligne — donc rien n'est
   * empêché sur la foi de cette valeur.
   */
  const [horsLigne, setHorsLigne] = useState(false);
  const [locked, setLocked] = useState(false);
  const [, forceRender] = useState(0);
  const duo = useDuo();
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

  /**
   * Reprise après un passage en arrière-plan.
   *
   * Le système gèle les minuteurs et coupe les connexions sans prévenir. Au retour, l'intervalle
   * qui repart ne suffit pas : il faut relever tout de suite et **rouvrir le flux** sans
   * chercher à savoir s'il a survécu. La question n'a pas de réponse fiable — un socket coupé
   * par le système reste `OPEN` jusqu'à la première écriture — et reconnecter à tort coûte moins
   * cher que de rester silencieusement muet.
   */
  useEffect(() => {
    if (!session) return;

    const arret = observerCycle((transition) => {
      if (transition.quoi === "veille") return;

      if (transition.quoi === "reseau") setHorsLigne(false);

      // Une absence prolongée referme un appareil verrouillé.
      //
      // Sans cela le verrou n'agit qu'au démarrage à froid : il protège un appareil éteint, et
      // pas celui qu'on pose sur une table. Écarter la session de l'écran suffit à exiger le
      // mot de passe — l'état sur le disque est chiffré sous une clé qui n'existait qu'en
      // mémoire.
      //
      // Ce que cela ne fait pas : effacer cette clé de la mémoire du processus. Le module
      // WebAssembly garde son état, et rien dans un navigateur ne permet de l'exiger. La
      // protection vise qui prend l'appareil en main, pas qui inspecte sa mémoire.
      if (transition.quoi === "reprise" && session.locked && transition.absenceMs > REVERROUILLAGE_MS) {
        setSession(null);
        setActive(null);
        setLocked(true);
        return;
      }

      session.startStream(refresh);
      void session
        .poll()
        .then(() => {
          setError(null);
          refresh();
        })
        .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
    });

    const perdu = () => setHorsLigne(true);
    addEventListener("offline", perdu);
    setHorsLigne(!reseauDeclare());

    return () => {
      arret();
      removeEventListener("offline", perdu);
    };
  }, [session, refresh]);

  /**
   * Le retour du système ferme la conversation, au lieu de quitter l'application.
   *
   * # Pourquoi passer par l'historique
   *
   * Sur Android comme dans un navigateur mobile, le geste de retour agit sur l'historique. Une
   * application à un seul panneau qui n'y touche pas se fait quitter au premier retour, alors
   * que l'utilisateur voulait revenir à sa liste — le réflexe le plus courant sur mobile, et
   * celui dont l'échec ressemble le plus à un plantage.
   *
   * # Le garde-fou
   *
   * L'entrée poussée doit être retirée si la conversation se ferme autrement — par le bouton
   * retour de l'en-tête, ou parce que l'écran s'est élargi. Le drapeau distingue les deux : sans
   * lui, un `history.back()` de trop consommerait une entrée qui ne nous appartient pas, et sur
   * Android cela ferme l'application.
   */
  const entreePoussee = useRef(false);

  useEffect(() => {
    // `active` et non la conversation retenue : celle-ci n'est calculée qu'après les écrans de
    // démarrage, donc après les hooks. Les deux coïncident à un panneau, où la sélection ne se
    // replie sur rien.
    if (duo || !active) return;

    history.pushState({ wac: "conversation" }, "");
    entreePoussee.current = true;

    const revenir = () => {
      // Consommée par le système : il n'y a plus rien à retirer.
      entreePoussee.current = false;
      setActive(null);
    };

    addEventListener("popstate", revenir);
    return () => {
      removeEventListener("popstate", revenir);
      if (entreePoussee.current) {
        entreePoussee.current = false;
        history.back();
      }
    };
  }, [duo, active]);

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

  // À deux panneaux, une conversation est toujours ouverte : un panneau droit vide serait du
  // vide permanent. À un seul, l'absence de sélection **est** l'écran de liste — retomber sur la
  // première conversation rendrait la liste inatteignable.
  const retenue = active && session.conversations.get(active.key) ? active : null;
  const current = duo ? retenue ?? conversations[0] ?? null : retenue;

  return (
    <div
      // `h-dvh` et non `h-screen` : sur mobile, `100vh` compte la hauteur barres déployées, si
      // bien qu'une centaine de pixels passent sous l'écran — précisément le champ de saisie et
      // le dernier message.
      className="safe-cotes safe-haut mx-auto flex h-dvh max-w-5xl flex-col"
    >
      {/* À un panneau, l'en-tête ne s'affiche que sur la liste. Dans la conversation il coûtait
          un sixième de la hauteur pour répéter une identité que l'utilisateur connaît, alors
          que l'écran porte déjà son propre en-tête — celui du correspondant, qui lui est
          utile. L'avertissement reste lisible : la liste est l'écran d'accueil. */}
      {(duo || !current) && (
        <Header session={session} onForget={() => session.forget().then(() => location.reload())} />
      )}

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
        {/* À un panneau, un seul des deux est monté — et non masqué : une conversation cachée
            continuerait de relever, de défiler et de réclamer le focus au clavier. */}
        {(duo || !current) && (
          <ConversationList
            session={session}
            conversations={conversations}
            current={current}
            onSelect={setActive}
            onError={setError}
            onChanged={refresh}
          />
        )}
        {current ? (
          <Conversation
            session={session}
            view={current}
            onChanged={refresh}
            onError={setError}
            onBack={duo ? undefined : () => setActive(null)}
          />
        ) : (
          duo && (
            <Centered>
              Aucune conversation. Ouvrez-en une avec le pseudonyme d&apos;un correspondant.
            </Centered>
          )
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

      {horsLigne && (
        <p
          role="status"
          className="border-t border-(--color-warn) bg-(--color-warn)/10 px-4 py-2 text-sm text-(--color-warn)"
        >
          Hors ligne. Les messages écrits maintenant ne partiront pas ; ce qui a été reçu reste
          lisible.
        </p>
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
