import { useState } from "react";
import { handleOf } from "@/lib/naming";
import type { ConversationView } from "@/lib/session";
import { Button } from "@/ui/Button";
import { ContextMenu } from "@/ui/ContextMenu";
import { Dialog } from "@/ui/Dialog";
import { useNames } from "@/state/names";
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
}: {
  view: ConversationView;
}) {
  const session = useSession();
  const names = useNames();
  const bump = useBump();
  const report = useReport();

  const [busy, setBusy] = useState(false);
  /** The member a confirmation is currently open about, and what it would do to them. */
  const [pending, setPending] = useState<{ kind: "remove" | "handover"; handle: string } | null>(
    null,
  );

  const roles = session.roles(view);
  const iAmAdmin = roles === null || roles.admin === session.accountId;
  const iModerate = roles === null || roles.admin === session.accountId
    || roles.moderators.includes(session.accountId);

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
    if (handle === session.accountId) {
      // Nothing the group does *to* us. Leaving is ours to do and lives on the conversation's own
      // menu, where the decision is actually made.
      return (
        <ContextMenu.Item disabled onSelect={() => undefined}>
          No actions
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

  /**
   * The confirmations, and nothing visible until one is asked for.
   *
   * The warning about removal and the "Leave the group" button used to be rendered here, under
   * the member list. Both moved: the warning is in the removal dialog, where it is read at the
   * moment it changes a decision rather than standing permanently over a list nobody is removing
   * anybody from; leaving is on the conversation's own context menu, which is where you are when
   * you decide to leave one.
   *
   * What remains is a node the caller must render *outside* any menu. A dialog mounted inside a
   * context menu is unmounted with it the instant an item is chosen, so the confirmation would
   * flash and vanish — which is exactly the failure a confirmation exists to prevent.
   */
  const dialogs = (
    <>
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
        title={pending === null ? "Remove member" : `Remove ${handleOf(pending.handle, names)}?`}
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
                  report.done(`Removed ${handleOf(handle, names)} from the group.`);
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
            : `Hand the group over to ${handleOf(pending.handle, names)}?`
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
                  report.done(`${handleOf(handle, names)} now administers this group.`);
                });
              }}
            >
              Hand over
            </Button>
          </>
        }
      />

    </>
  );

  return { menuFor, dialogs, role };
}

/**
 * Leaving a group, asked about the group.
 *
 * Its own component rather than part of `useGroupAdmin`, because the two callers need it in
 * different places: the detail column has the hook already, and the rail opens this from a
 * context menu that unmounts the moment an item is chosen. A confirmation rendered inside that
 * menu would flash and vanish, which is the one thing a confirmation must not do.
 */
export function LeaveGroupDialog({
  view,
  open,
  onOpenChange,
  onLeft,
}: {
  view: ConversationView;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called once the request is in. The rail closes its own state; the column also closes. */
  onLeft?: () => void;
}) {
  const session = useSession();
  const names = useNames();
  const bump = useBump();
  const report = useReport();
  const [busy, setBusy] = useState(false);

  const roles = session.roles(view);

  // Who inherits if we leave. Computed the way `Session.requestLeave` does it: the rank just
  // below — a moderator — otherwise the longest-standing member in MLS tree order. Announced
  // before leaving rather than discovered after: bequeathing a group without knowing to whom
  // would be the worst way to leave it.
  const heir = (() => {
    if (roles === null || roles.admin !== session.accountId) return null;
    const members = view.peers.map((peer) => peer.name).filter((name) => name !== session.accountId);
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

  return (
    <Dialog
    open={open}
    onOpenChange={onOpenChange}
      tone="danger"
      title="Leave the group?"
      actions={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            busy={busy}
            onClick={() =>
              void action(async () => {
                await session.requestLeave(view);
                onOpenChange(false);
                report.done("Leave request sent. You are out once another member commits it.");
                onLeft?.();
              })
            }
          >
            {heir !== null
              ? `Hand over to ${handleOf(heir, names)} and leave`
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
            You administer this group: <strong>{handleOf(heir, names)}</strong> will succeed you
            {roles !== null && roles.moderators.includes(heir)
              ? " (moderator, the rank below)"
              : " (longest-standing member)"}
            . A group with no administrator would be frozen for good.
          </p>
        )}
        {roles?.admin === session.accountId && heir === null && (
          <p className="text-(--color-danger)">
            You are the last member: leaving amounts to deleting the conversation.
          </p>
        )}
      </div>
    </Dialog>
  );
}
