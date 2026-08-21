import { useState } from "react";
import { formatHandle } from "@/lib/naming";
import type { ConversationView } from "@/lib/session";
import { Button } from "@/ui/Button";
import { ContextMenu } from "@/ui/ContextMenu";
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
export function useGroupAdmin({
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

  /**
   * A member's two lines, for the roster and nowhere else in this file.
   *
   * The roster is a reference list read at leisure, so it has room for both strings and shows
   * both. The confirmations further down deliberately do not — see the comment above the first
   * of them.
   */
  const menuFor = (handle: string) => {
    const isModerator = roles?.moderators.includes(handle) ?? false;
    const isAdmin = roles?.admin === handle;

    // Ourselves: the group has nothing to do *to* us, but leaving is ours to do, so the menu
    // says that rather than "no actions". Excluding our own row would make one name in every
    // group behave unlike the others for a reason the reader cannot see.
    if (handle === session.handle) {
      return roles === null ? (
        <ContextMenu.Item disabled onSelect={() => undefined}>
          No actions
        </ContextMenu.Item>
      ) : (
        <ContextMenu.Item icon="revoke" tone="danger" onSelect={() => setLeaving(true)}>
          Leave the group
        </ContextMenu.Item>
      );
    }

    if (roles === null || isAdmin) {
      // No roles at all is a one-to-one wearing a group's clothes, and the admin has no rank
      // above them to be given or taken.
      return (
        <ContextMenu.Item disabled onSelect={() => undefined}>
          No actions
        </ContextMenu.Item>
      );
    }

    return (
      <>
        {iAmAdmin && (
          <>
            {/* Reversible in one click, so it is not behind a confirmation. */}
            <ContextMenu.Item
              disabled={busy}
              onSelect={() => void action(() => session.setModerator(view, handle, !isModerator))}
            >
              {isModerator ? "Remove moderator" : "Make moderator"}
            </ContextMenu.Item>
            <ContextMenu.Item
              disabled={busy}
              onSelect={() => setPending({ kind: "handover", handle })}
            >
              Hand over
            </ContextMenu.Item>
          </>
        )}
        {/* A moderator removes ordinary members, not their peers. */}
        {iModerate && (!isModerator || iAmAdmin) && (
          <ContextMenu.Item
            icon="revoke"
            tone="danger"
            disabled={busy}
            onSelect={() => setPending({ kind: "remove", handle })}
          >
            Remove from group
          </ContextMenu.Item>
        )}
      </>
    );
  };

  const footer = (
    <div className="space-y-snug">
      {roles !== null && iModerate && (
        <p className="text-caption text-(--color-ink-muted)">
          Removing someone removes <strong>all of their devices</strong>: the unit is the
          account. From the commit onward, they decrypt nothing that follows.
        </p>
      )}

      {roles !== null && (
        // Leaving is not another row of the roster, so it does not sit at roster distance: the
        // extra `pt-gutter` on top of the list's `space-y-snug` is what says the subject changed.
        // It stays a word rather than a glyph, by the rule at the top of `ui/IconButton.tsx` —
        // rare, and undone only by somebody else's commit.
        <div className="pt-gutter">
          <Button variant="quiet" size="sm" onClick={() => setLeaving(true)}>
            Leave the group
          </Button>
        </div>
      )}

      {/*
        Every confirmation below names people by handle, and none of them by display name. This
        is the deliberate exception to the rule the roster above follows.

        A confirmation asks somebody to commit to an irreversible act against a specific account,
        so the string it names has to be the one that account cannot choose. "Remove Charlie?"
        asks for a signature on a label its own subject types in and can change tomorrow; "Remove
        @charlie8295?" asks for one on the anchor. It is the same argument that keeps the bare
        handle in `Verification.tsx`, and it applies to the reports these actions leave behind
        too — a report of what happened has to be checkable against what was confirmed.

        What it does not solve: somebody who only ever sees a display name in the roster may not
        recognise the handle here. That is the cost, and it is the right way round — hesitating
        over an unfamiliar handle is a better failure than confidently removing the wrong person.
      */}
      <Dialog
        open={pending?.kind === "remove"}
        onOpenChange={(open) => !open && setPending(null)}
        tone="danger"
        title={pending === null ? "Remove member" : `Remove ${formatHandle(pending.handle)}?`}
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
                  report.done(`Removed ${formatHandle(handle)} from the group.`);
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
        title={
          pending === null
            ? "Hand the group over"
            : `Hand the group over to ${formatHandle(pending.handle)}?`
        }
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
                  report.done(`${formatHandle(handle)} now administers this group.`);
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
              {heir !== null
                ? `Hand over to ${formatHandle(heir)} and leave`
                : "Request to leave"}
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
              You administer this group: <strong>{formatHandle(heir)}</strong> will succeed you
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

  return { menuFor, footer, role };
}
