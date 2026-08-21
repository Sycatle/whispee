import { useState } from "react";
import type { ConversationView } from "@/lib/session";
import { Button } from "@/ui/Button";
import { Dialog } from "@/ui/Dialog";
import { useBump, useSession } from "@/state/SessionProvider";
import { useReport } from "@/state/report";

/**
 * Group administration: members, roles, leaving.
 *
 * # What this panel has to say, and the user cannot guess
 *
 * Two behaviours would look like bugs if left unexplained:
 *
 * 1. **Leaving a group does not take effect right away.** RFC 9420 forbids removing yourself
 *    in a commit you generate; another member has to pick it up. Making the conversation
 *    vanish from the screen would let someone believe they were out while they are still
 *    being read.
 *
 * 2. **Removing someone removes all of their devices.** The unit is the account, never the
 *    device: every device on an account has exactly the same access, everywhere.
 *
 * # The hierarchy
 *
 * A single **admin**, with **moderators** under them. Moderators keep the group in order —
 * adding and removing ordinary members — but do not touch roles: if they could, one of them
 * would promote themselves to admin and there would be no authority left, only a race. One
 * button hands out power, and it belongs to the admin alone.
 *
 * # Why the irreversible actions are behind a dialog now
 *
 * Removing a member, handing the group over and leaving are all commits: they reach the other
 * members, and nothing in the protocol undoes them. They used to be underlined words in a row of
 * underlined words, one pointer-width from "make moderator". A `Dialog tone="danger"` costs a
 * deliberate second click and — the part that matters more — gives the consequence somewhere to
 * be written at the moment it is about to happen, instead of in a `title` attribute a touch user
 * never sees.
 *
 * What it does not solve: a confirmed mistake is still a mistake. There is no undo here, because
 * there is no undo in MLS; re-adding somebody is a new join, and they decrypt nothing from the
 * window they were out of.
 *
 * # Why it takes no `session`
 *
 * It reads the session through `useSession`, so it re-renders when the roster or the roles move
 * under it. See the rule at the top of `state/SessionProvider.tsx`: a session arriving by prop is
 * fresh exactly once.
 */
export function GroupPanel({
  view,
  onClose,
}: {
  view: ConversationView;
  /**
   * Closes the detail column. Called once the leave request is in: there is nothing further to
   * administer in a group one is on the way out of. It does **not** mean the conversation is
   * gone — see the note on leaving above.
   */
  onClose: () => void;
}) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();

  const [busy, setBusy] = useState(false);
  const [leaving, setLeaving] = useState(false);
  /** The member a confirmation is currently open about, and what it would do to them. */
  const [pending, setPending] = useState<{ kind: "remove" | "handover"; handle: string } | null>(
    null,
  );

  const roles = session.roles(view);
  const iAmAdmin = roles === null || roles.admin === session.handle;
  const iModerate = roles === null || roles.admin === session.handle
    || roles.moderators.includes(session.handle);

  // Who inherits if we leave. Computed the way `Session.requestLeave` does it: the rank just
  // below — a moderator — otherwise the longest-standing member in MLS tree order. Announced
  // before leaving rather than discovered after: bequeathing a group without knowing to whom
  // would be the worst way to leave it.
  const heir = (() => {
    if (roles === null || roles.admin !== session.handle) return null;
    const members = view.peers
      .map((peer) => peer.name)
      .filter((name) => name !== session.handle);
    return members.find((name) => roles.moderators.includes(name)) ?? members[0] ?? null;
  })();

  const action = async (run: () => Promise<void>) => {
    setBusy(true);
    try {
      await run();
      bump();
    } catch (e) {
      report.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const role = (handle: string) => {
    if (roles === null) return null;
    if (roles.admin === handle) return "admin";
    if (roles.moderators.includes(handle)) return "moderator";
    return null;
  };

  const Role = ({ handle }: { handle: string }) => {
    const named = role(handle);
    if (named === null) return null;
    return <span className="text-caption text-(--color-accent)">{named}</span>;
  };

  return (
    <div className="space-y-snug">
      {roles === null && (
        <p className="text-caption text-(--color-ink-muted)">
          One-to-one conversation: no roles. A hierarchy would make no sense here.
        </p>
      )}

      <ul className="space-y-tight">
        <li className="flex flex-wrap items-baseline gap-x-snug gap-y-tight text-body">
          <span>@{session.handle}</span>
          <span className="text-caption text-(--color-ink-muted)">(you)</span>
          <Role handle={session.handle} />
        </li>

        {view.accounts.map((account) => {
          const isModerator = roles?.moderators.includes(account.handle) ?? false;
          const isAdmin = roles?.admin === account.handle;

          return (
            <li key={account.handle} className="flex flex-wrap items-baseline gap-x-snug gap-y-tight text-body">
              <span>@{account.handle}</span>
              <Role handle={account.handle} />
              <span className="text-caption text-(--color-ink-muted)">
                {account.devices.length} device{account.devices.length > 1 ? "s" : ""}
              </span>

              {roles !== null && !isAdmin && (
                <span className="flex flex-wrap gap-tight">
                  {/* Only the admin hands out roles: a moderator who could would promote
                      themselves to admin, and there would be no authority left. */}
                  {iAmAdmin && (
                    <>
                      {/* Reversible in one click, so it is not behind a confirmation. */}
                      <Button
                        variant="quiet"
                        size="sm"
                        disabled={busy}
                        onClick={() =>
                          void action(() =>
                            session.setModerator(view, account.handle, !isModerator),
                          )
                        }
                      >
                        {isModerator ? "Remove moderator" : "Make moderator"}
                      </Button>
                      <Button
                        variant="quiet"
                        size="sm"
                        disabled={busy}
                        onClick={() => setPending({ kind: "handover", handle: account.handle })}
                      >
                        Hand over
                      </Button>
                    </>
                  )}
                  {/* A moderator removes ordinary members, not their peers. */}
                  {iModerate && (!isModerator || iAmAdmin) && (
                    <Button
                      variant="quiet"
                      size="sm"
                      disabled={busy}
                      onClick={() => setPending({ kind: "remove", handle: account.handle })}
                      className="text-(--color-danger)"
                    >
                      Remove
                    </Button>
                  )}
                </span>
              )}
            </li>
          );
        })}
      </ul>

      {roles !== null && iModerate && (
        <p className="text-caption text-(--color-ink-muted)">
          Removing someone removes <strong>all of their devices</strong>: the unit is the
          account. From the commit onward, they decrypt nothing that follows.
        </p>
      )}

      {roles !== null && (
        <div className="border-t border-(--color-border-subtle) pt-snug">
          <Button variant="quiet" size="sm" onClick={() => setLeaving(true)}>
            Leave the group
          </Button>
        </div>
      )}

      <Dialog
        open={pending?.kind === "remove"}
        onOpenChange={(open) => !open && setPending(null)}
        tone="danger"
        title={pending === null ? "Remove member" : `Remove @${pending.handle}?`}
        description="Removing someone removes all of their devices: the unit is the account, never the device. From the commit onward they decrypt nothing that follows, and re-adding them later does not give the window back."
        actions={
          <>
            <Button variant="secondary" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              busy={busy}
              onClick={() => {
                const handle = pending?.handle;
                if (handle === undefined) return;
                void action(async () => {
                  await session.removeAccount(view, handle);
                  setPending(null);
                  report.done(`Removed @${handle} from the group.`);
                });
              }}
            >
              Remove
            </Button>
          </>
        }
      />

      <Dialog
        open={pending?.kind === "handover"}
        onOpenChange={(open) => !open && setPending(null)}
        tone="danger"
        title={pending === null ? "Hand the group over" : `Hand the group over to @${pending.handle}?`}
        description="They become the administrator and you do not. There is no way to take it back from this side: only the new administrator can hand it to anybody, including back to you."
        actions={
          <>
            <Button variant="secondary" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              busy={busy}
              onClick={() => {
                const handle = pending?.handle;
                if (handle === undefined || roles === null) return;
                void action(async () => {
                  await session.setRoles(view, handle, roles.moderators);
                  setPending(null);
                  report.done(`@${handle} now administers this group.`);
                });
              }}
            >
              Hand over
            </Button>
          </>
        }
      />

      <Dialog
        open={leaving}
        onOpenChange={setLeaving}
        tone="danger"
        title="Leave the group?"
        actions={
          <>
            <Button variant="secondary" onClick={() => setLeaving(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              busy={busy}
              onClick={() =>
                void action(async () => {
                  await session.requestLeave(view);
                  setLeaving(false);
                  report.done("Leave request sent. You are out once another member commits it.");
                  onClose();
                })
              }
            >
              {heir !== null ? `Hand over to @${heir} and leave` : "Request to leave"}
            </Button>
          </>
        }
      >
        <div className="space-y-snug text-(--color-ink-muted)">
          <p>
            Leaving is a <strong>request</strong>: the protocol forbids removing yourself, so
            another member has to pick it up. Until then you stay in the group and keep receiving
            its messages.
          </p>
          {heir !== null && (
            <p>
              You administer this group: <strong>@{heir}</strong> will succeed you
              {roles !== null && roles.moderators.includes(heir)
                ? " (moderator, the rank below)"
                : " (longest-standing member)"}
              . A group with no administrator would be frozen for good.
            </p>
          )}
          {roles?.admin === session.handle && heir === null && (
            <p className="text-(--color-danger)">
              You are the last member: leaving amounts to deleting the conversation.
            </p>
          )}
        </div>
      </Dialog>
    </div>
  );
}
