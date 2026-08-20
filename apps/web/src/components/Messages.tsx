"use client";

/**
 * Fil de messages : bulles, réactions repliées, citations, état de lecture.
 *
 * Extrait de `page.tsx` quand les réactions ont transformé une liste plate en arbre : une
 * réaction n'est pas une bulle, c'est une annotation d'une autre bulle, et la même chose vaut
 * pour la citation d'une réponse. Garder cette logique dans le rendu de la page mêlait la
 * mise en page de l'application à la structure de la conversation.
 */
import { useEffect, useRef, useState } from "react";

import { Attachment } from "@/components/Attachment";
import type { ConversationView, Session } from "@/lib/session";
import { nextExpiry } from "@/lib/signals";

/** Palette proposée au survol. Volontairement courte : un sélecteur complet est un autre sujet. */
const EMOJIS = ["👍", "❤️", "😂", "😮", "🙏"];

export function Messages({
  session,
  view,
  onChanged,
  onError,
  onReplyTo,
}: {
  session: Session;
  view: ConversationView;
  onChanged: () => void;
  onError: (message: string) => void;
  onReplyTo: (seq: number) => void;
}) {
  const bottom = useRef<HTMLDivElement>(null);

  const messages = view.messages.slice().sort((a, b) => a.seq - b.seq);

  // Les réactions sont retirées du fil et rattachées à leur cible. Un emoji vide retire la
  // réaction de son auteur : c'est le dernier état qui compte, pas l'accumulation.
  const reactions = new Map<number, Map<string, string>>();
  for (const message of messages) {
    if (message.content.kind !== "reaction") continue;
    const auteur = message.mine ? session.handle : (message.sender ?? "inconnu");
    const cible = reactions.get(message.content.target) ?? new Map<string, string>();
    if (message.content.emoji) cible.set(auteur, message.content.emoji);
    else cible.delete(auteur);
    reactions.set(message.content.target, cible);
  }

  const texteDe = (seq: number): string => {
    const cible = messages.find((message) => message.seq === seq);
    if (!cible) return "message indisponible";
    if (cible.content.kind === "text") return cible.content.text;
    if (cible.content.kind === "reply") return cible.content.text;
    if (cible.content.kind === "attachment") return cible.content.ref.name;
    return "…";
  };

  const visibles = messages.filter((message) => message.content.kind !== "reaction");

  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth" });
  }, [visibles.length]);

  // « Lu » veut dire **affiché à quelqu'un**. C'est donc ici, dans le composant qui rend le fil,
  // que cela se décide — pas dans la relève, qui tourne même fenêtre fermée.
  //
  // La visibilité de l'onglet en fait partie : un fil rendu dans un onglet d'arrière-plan a été
  // reçu, pas lu. Le navigateur ralentit déjà les onglets cachés, ce qui produit à peu près le
  // bon comportement — mais s'appuyer sur cet effet de bord reviendrait à laisser une règle de
  // vie privée dépendre d'une heuristique d'économie de batterie.
  useEffect(() => {
    const marquer = () => {
      if (document.visibilityState === "visible") {
        session.markRead(view);
        onChanged();
      }
    };

    marquer();
    document.addEventListener("visibilitychange", marquer);
    return () => document.removeEventListener("visibilitychange", marquer);
  }, [session, view, view.contentCursor, onChanged]);

  const react = (seq: number, emoji: string) => {
    session.reactTo(view, seq, emoji).then(onChanged).catch((e: unknown) => {
      onError(e instanceof Error ? e.message : String(e));
    });
  };

  const enTrainDEcrire = session.typingIn(view);

  // Réveil à l'expiration.
  //
  // `typingIn` filtre les indicateurs périmés, mais il ne s'exécute qu'au rendu — et quand le
  // correspondant cesse d'écrire, plus rien ne provoque de rendu : aucun signal n'arrive, et la
  // relève périodique ne repasse que trente secondes plus tard. L'indicateur restait donc peint
  // à l'écran bien après avoir cessé d'être vrai.
  //
  // Ce minuteur n'ajoute aucune donnée : il ne fait que redemander un rendu à l'instant où le
  // filtre changera d'avis. `tick` n'est jamais lu, seul son changement compte.
  const [, setTick] = useState(0);
  useEffect(() => {
    const delai = nextExpiry(view.typing, Date.now());
    if (delai === undefined) return;

    const minuteur = setTimeout(() => setTick((n) => n + 1), delai);
    return () => clearTimeout(minuteur);
  });

  return (
    <>
      <ol className="min-h-0 flex-1 space-y-2 overflow-y-auto p-4">
        {visibles.map((message) => {
          // Extrait avant le JSX : le rétrécissement de type se perd à l'intérieur d'une
          // closure, et le contourner dans l'expression rendait le rendu illisible.
          const attachment = message.content.kind === "attachment" ? message.content.ref : null;
          const cite = message.content.kind === "reply" ? message.content.target : null;
          const emojis = [...(reactions.get(message.seq)?.values() ?? [])];

          return (
            <li key={message.seq} className={`group ${message.mine ? "text-right" : ""}`}>
              <div
                className={`inline-block max-w-[75%] wrap-anywhere rounded-lg px-3 py-2 text-left text-sm ${
                  message.mine
                    ? "bg-(--color-accent) text-white"
                    : "bg-(--color-surface-raised) border border-(--color-border-subtle)"
                }`}
              >
                {!message.mine && view.peers.length > 1 && (
                  <span className="block text-xs opacity-70">{message.sender ?? "inconnu"}</span>
                )}

                {cite !== null && (
                  <span className="mb-1 block border-l-2 border-current/40 pl-2 text-xs opacity-70">
                    {texteDe(cite)}
                  </span>
                )}

                {attachment ? (
                  <Attachment
                    attachment={attachment}
                    onOpen={() => session.openAttachment(view, attachment)}
                  />
                ) : message.content.kind === "text" ? (
                  message.content.text
                ) : message.content.kind === "reply" ? (
                  message.content.text
                ) : null}

                {message.mine && <Status state={session.statusOf(view, message.seq)} />}
              </div>

              {emojis.length > 0 && (
                <div className="mt-0.5 text-xs" aria-label="réactions">
                  {emojis.join(" ")}
                </div>
              )}

              <div className="mt-0.5 hidden gap-1 text-xs group-hover:flex" data-actions>
                {EMOJIS.map((emoji) => (
                  <button
                    key={emoji}
                    type="button"
                    onClick={() => react(message.seq, emoji)}
                    className="rounded px-1 hover:bg-(--color-surface-raised)"
                    title={`Réagir ${emoji}`}
                  >
                    {emoji}
                  </button>
                ))}
                <button
                  type="button"
                  onClick={() => onReplyTo(message.seq)}
                  className="rounded px-1 opacity-70 hover:bg-(--color-surface-raised)"
                >
                  Répondre
                </button>
              </div>
            </li>
          );
        })}
        <div ref={bottom} />
      </ol>

      {/*
        Ligne d'activité. Elle s'éteint de deux façons, aucune ne dépendant d'un signal « a cessé
        d'écrire » — un tel signal peut se perdre et laisserait l'indicateur allumé pour toujours.

        À l'arrivée d'un message de l'auteur, immédiatement : l'envoi prouve qu'il a fini, et
        cette preuve ne peut pas s'égarer puisqu'on ne l'attend pas. Sinon, par expiration locale,
        réveillée par le minuteur ci-dessus.
      */}
      {enTrainDEcrire.length > 0 && (
        <p className="px-4 pb-1 text-xs opacity-60" aria-live="polite">
          {enTrainDEcrire.map((handle) => `@${handle}`).join(", ")}{" "}
          {enTrainDEcrire.length > 1 ? "écrivent" : "écrit"}…
        </p>
      )}
    </>
  );
}

/**
 * État d'un message qu'on a envoyé.
 *
 * Trois états et pas deux : « envoyé » signifie que le serveur l'a accepté, « reçu » qu'un
 * appareil l'a relevé, « lu » qu'une personne l'a eu à l'écran. Les confondre ferait passer
 * un téléphone allumé pour une attention humaine.
 */
function Status({ state }: { state: "sent" | "delivered" | "read" }) {
  const libelle = { sent: "envoyé", delivered: "reçu", read: "lu" }[state];
  const marque = { sent: "✓", delivered: "✓✓", read: "✓✓" }[state];

  return (
    <span
      className={`ml-2 align-bottom text-xs ${state === "read" ? "opacity-100" : "opacity-60"}`}
      title={libelle}
      aria-label={libelle}
      data-receipt={state}
    >
      {marque}
    </span>
  );
}
