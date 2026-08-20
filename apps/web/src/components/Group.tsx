import { useState } from "react";
import type { ConversationView, Session } from "@/lib/session";

/**
 * Administration d'un groupe : membres, rôles, sortie.
 *
 * # Ce que ce panneau doit dire, et que l'utilisateur ne peut pas deviner
 *
 * Deux comportements paraîtraient des bugs si on ne les expliquait pas :
 *
 * 1. **Quitter un groupe ne prend pas effet tout de suite.** La RFC 9420 interdit de se
 *    retirer soi-même dans un commit qu'on génère ; il faut qu'un autre membre le reprenne.
 *    Faire disparaître la conversation de l'écran laisserait croire à quelqu'un qu'il est
 *    sorti alors qu'il continue d'être lu.
 *
 * 2. **Retirer quelqu'un le retire avec tous ses appareils.** L'unité est le compte, jamais
 *    l'appareil : tous les appareils d'un compte ont exactement le même accès, partout.
 *
 * # La hiérarchie
 *
 * Un **admin** unique, des **modérateurs** sous lui. Les modérateurs entretiennent le groupe —
 * ajouter, retirer des membres ordinaires — mais ne touchent pas aux rôles : s'ils le
 * pouvaient, l'un d'eux se promouvrait admin et il n'y aurait plus d'autorité, seulement une
 * course. Un seul bouton distribue le pouvoir, et il n'appartient qu'à l'admin.
 */
export function GroupPanel({
  session,
  view,
  onError,
  onChanged,
  onClose,
}: {
  session: Session;
  view: ConversationView;
  onError: (message: string) => void;
  onChanged: () => void;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [leaving, setLeaving] = useState(false);

  const roles = session.roles(view);
  const jeSuisAdmin = roles === null || roles.admin === session.handle;
  const jeModere = roles === null || roles.admin === session.handle
    || roles.moderators.includes(session.handle);

  // Qui héritera si nous partons. Calculé comme le fait `Session.requestLeave` : le rang
  // immédiatement en dessous — un modérateur — sinon le membre le plus ancien au sens de
  // l'arbre MLS. Annoncé avant le départ plutôt que constaté après : léguer un groupe sans
  // savoir à qui serait la pire façon de le quitter.
  const heritier = (() => {
    if (roles === null || roles.admin !== session.handle) return null;
    const membres = view.peers
      .map((peer) => peer.name)
      .filter((name) => name !== session.handle);
    return membres.find((name) => roles.moderators.includes(name)) ?? membres[0] ?? null;
  })();

  const action = async (run: () => Promise<void>) => {
    setBusy(true);
    try {
      await run();
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const role = (handle: string) => {
    if (roles === null) return null;
    if (roles.admin === handle) return "admin";
    if (roles.moderators.includes(handle)) return "modérateur";
    return null;
  };

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Membres</h2>
        <button type="button" onClick={onClose} className="text-(--color-ink-muted) underline">
          Fermer
        </button>
      </div>

      {roles === null && (
        <p className="mt-2 text-xs text-(--color-ink-muted)">
          Conversation à deux : pas de rôles. Une hiérarchie n&apos;y aurait aucun sens.
        </p>
      )}

      <ul className="mt-3 space-y-2">
        <li className="flex items-center justify-between gap-3">
          <span>
            @{session.handle} <span className="text-(--color-ink-muted)">(vous)</span>
            {role(session.handle) && (
              <span className="ml-2 text-xs text-(--color-accent)">{role(session.handle)}</span>
            )}
          </span>
        </li>

        {view.accounts.map((account) => {
          const estModerateur = roles?.moderators.includes(account.handle) ?? false;
          const estAdmin = roles?.admin === account.handle;

          return (
            <li key={account.handle} className="flex items-center justify-between gap-3">
              <span>
                @{account.handle}
                {role(account.handle) && (
                  <span className="ml-2 text-xs text-(--color-accent)">
                    {role(account.handle)}
                  </span>
                )}
                <span className="ml-2 text-xs text-(--color-ink-muted)">
                  {account.devices.length} appareil{account.devices.length > 1 ? "s" : ""}
                </span>
              </span>

              {roles !== null && !estAdmin && (
                <span className="flex shrink-0 gap-3 text-xs">
                  {/* Seul l'admin distribue les rôles : un modérateur qui le pourrait se
                      promouvrait admin, et il n'y aurait plus d'autorité. */}
                  {jeSuisAdmin && (
                    <>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          action(() =>
                            session.setModerator(view, account.handle, !estModerateur),
                          )
                        }
                        className="underline text-(--color-ink-muted)"
                      >
                        {estModerateur ? "retirer modérateur" : "passer modérateur"}
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          action(async () => {
                            await session.setRoles(view, account.handle, roles.moderators);
                          })
                        }
                        className="underline text-(--color-ink-muted)"
                        title="Transmet définitivement le groupe : vous ne pourrez pas le reprendre."
                      >
                        transmettre
                      </button>
                    </>
                  )}
                  {/* Un modérateur retire les membres ordinaires, pas ses pairs. */}
                  {jeModere && (!estModerateur || jeSuisAdmin) && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => action(() => session.removeAccount(view, account.handle))}
                      className="underline text-(--color-danger)"
                    >
                      retirer
                    </button>
                  )}
                </span>
              )}
            </li>
          );
        })}
      </ul>

      {roles !== null && jeModere && (
        <p className="mt-3 text-xs text-(--color-ink-muted)">
          Retirer quelqu&apos;un le retire avec <strong>tous ses appareils</strong> : l&apos;unité
          est le compte. À partir du commit, il ne déchiffre plus rien de ce qui suit.
        </p>
      )}

      {roles !== null && (
        <div className="mt-4 border-t border-(--color-border-subtle) pt-3">
          {leaving ? (
            <div className="space-y-2">
              <p className="text-xs text-(--color-ink-muted)">
                Votre départ est une <strong>demande</strong> : le protocole interdit de se
                retirer soi-même, un autre membre doit la reprendre. Jusque-là vous restez dans
                le groupe et continuez d&apos;en recevoir les messages.
              </p>
              {heritier !== null && (
                <p className="text-xs text-(--color-ink-muted)">
                  Vous administrez ce groupe : <strong>@{heritier}</strong> vous succédera
                  {roles.moderators.includes(heritier)
                    ? " (modérateur, le rang en dessous)"
                    : " (membre le plus ancien)"}
                  . Un groupe sans administrateur serait définitivement figé.
                </p>
              )}
              {roles.admin === session.handle && heritier === null && (
                <p className="text-xs text-(--color-danger)">
                  Vous êtes le dernier membre : quitter revient à supprimer la conversation.
                </p>
              )}
              <div className="flex gap-3">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    action(async () => {
                      await session.requestLeave(view);
                      setLeaving(false);
                    })
                  }
                  className="rounded-md bg-(--color-danger) px-3 py-1.5 text-xs font-medium text-white"
                >
                  {heritier !== null ? `Transmettre à @${heritier} et quitter` : "Demander à quitter"}
                </button>
                <button
                  type="button"
                  onClick={() => setLeaving(false)}
                  className="text-xs underline text-(--color-ink-muted)"
                >
                  Annuler
                </button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setLeaving(true)}
              className="text-xs underline text-(--color-ink-muted)"
            >
              Quitter le groupe
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/** Bouton discret d'accès au panneau, dans l'en-tête de conversation. */
export function GroupToggle({ count, onClick }: { count: number; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title="Membres du groupe"
      className="text-xs text-(--color-ink-muted) hover:underline"
    >
      {count + 1} membres
    </button>
  );
}
