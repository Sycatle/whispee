import { useEffect, useRef, useState } from "react";
import { useOcclusion } from "@/lib/viewport";
import { GroupPanel, GroupToggle } from "@/components/Group";
import { Messages } from "@/components/Messages";
import { PresenceLine } from "@/components/Presence";
import { Verification, VerificationPanel, VerificationToggle } from "@/components/Verification";
import { type ConversationView, Session } from "@/lib/session";

export function Conversation({
  session,
  view,
  onChanged,
  onError,
  onBack,
}: {
  session: Session;
  view: ConversationView;
  onChanged: () => void;
  onError: (message: string) => void;
  /**
   * Retour à la liste, quand elle n'est pas affichée à côté.
   *
   * Absent à deux panneaux : un bouton retour y désignerait un écran déjà visible. Sa présence
   * est donc ce qui dit à ce composant qu'il occupe l'écran entier.
   */
  onBack?: () => void;
}) {
  const [text, setText] = useState("");
  const [verifying, setVerifying] = useState<string | null>(null);
  const [group, setGroup] = useState(false);
  const [sending, setSending] = useState(false);
  const [replyTo, setReplyTo] = useState<number | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const occlusion = useOcclusion();

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

  const enTrainDEcrire = session.typingIn(view);

  const title =
    view.accounts.map((a) => `@${a.handle}`).join(", ") ||
    [...new Set(view.peers.map((p) => p.name))].map((n) => `@${n}`).join(", ") ||
    "conversation vide";

  return (
    <section className="flex min-w-0 flex-1 flex-col">
      <header className="flex items-baseline justify-between gap-4 border-b border-(--color-border-subtle) px-4 py-2">
        {onBack && (
          <button
            type="button"
            onClick={onBack}
            aria-label="Revenir aux conversations"
            className="-ml-2 shrink-0 self-center px-2 py-1 text-xl leading-none text-(--color-ink-muted) tactile:min-h-11"
          >
            ‹
          </button>
        )}
        {/*
          L'epoch n'est pas affichée — c'est un détail de protocole qui n'apprend rien à
          l'utilisateur. Elle est exposée en attribut parce que deux membres à des epochs
          différentes ne peuvent plus se lire du tout : c'est la première chose à regarder
          quand un message n'arrive pas, et la chercher autrement demande d'instrumenter le
          module WebAssembly.
        */}
        <div className="min-w-0">
          <h2 className="truncate text-sm font-medium" data-epoch={String(view.epoch)}>
            {title}
          </h2>
          {/*
            « écrit… » prend le pas sur la présence : écrire implique être en ligne, et afficher
            les deux ajoute du bruit sans ajouter d'information. En tête-à-tête seulement — sur
            un groupe, « en ligne » ne dirait pas de qui il s'agit.
          */}
          {enTrainDEcrire.length > 0 ? (
            <span className="text-xs text-(--color-ink-muted)">
              {enTrainDEcrire.map((handle) => `@${handle}`).join(", ")}{" "}
              {enTrainDEcrire.length > 1 ? "écrivent" : "écrit"}…
            </span>
          ) : (
            view.accounts.length === 1 && (
              <PresenceLine session={session} handle={view.accounts[0].handle} />
            )
          )}
        </div>
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

      <form
        onSubmit={send}
        // Le clavier logiciel ne redimensionne pas la fenêtre sur iOS : il glisse la page
        // dessous, sans qu'aucune requête média ne se déclenche. Sans ce retrait, le champ qui
        // vient de recevoir le focus se retrouve caché par le clavier qui l'a ouvert.
        //
        // `safe-bas` en plus : les deux ne se recouvrent pas — la barre de geste est là quand le
        // clavier est fermé, et le clavier la remplace quand il s'ouvre.
        style={{ paddingBottom: occlusion || undefined }}
        className="safe-bas flex items-center gap-2 border-t border-(--color-border-subtle) p-3"
      >
        <input ref={fileInput} type="file" onChange={attach} className="hidden" />
        <button
          type="button"
          onClick={() => fileInput.current?.click()}
          disabled={sending}
          title="Joindre un fichier"
          className="rounded-md border border-(--color-border-subtle) px-3 py-2 text-sm tactile:min-h-11 tactile:min-w-11 disabled:opacity-50"
        >
          {sending ? "…" : "📎"}
        </button>
        <input
          value={text}
          onChange={(e) => typing(e.target.value)}
          placeholder={replyTo === null ? "Message" : "Réponse"}
          // `text-base` explicitement : en dessous de 16 pixels, iOS zoome sur le champ au
          // focus et ne dézoome pas en sortant. Le corriger en interdisant le zoom priverait de
          // recours ceux qui en ont besoin ; le corriger par la taille ne coûte rien.
          className="min-w-0 flex-1 rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2 text-base tactile:min-h-11"
        />
        <button
          type="submit"
          className="rounded-md bg-(--color-accent) px-4 py-2 text-sm font-medium text-white tactile:min-h-11"
        >
          Envoyer
        </button>
      </form>
    </section>
  );
}
