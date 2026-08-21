import { useState } from "react";
import type { ConversationView, Session } from "@/lib/session";

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
    if (roles.moderators.includes(handle)) return "moderator";
    return null;
  };

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Members</h2>
        <button type="button" onClick={onClose} className="text-(--color-ink-muted) underline">
          Close
        </button>
      </div>

      {roles === null && (
        <p className="mt-2 text-xs text-(--color-ink-muted)">
          One-to-one conversation: no roles. A hierarchy would make no sense here.
        </p>
      )}

      <ul className="mt-3 space-y-2">
        <li className="flex items-center justify-between gap-3">
          <span>
            @{session.handle} <span className="text-(--color-ink-muted)">(you)</span>
            {role(session.handle) && (
              <span className="ml-2 text-xs text-(--color-accent)">{role(session.handle)}</span>
            )}
          </span>
        </li>

        {view.accounts.map((account) => {
          const isModerator = roles?.moderators.includes(account.handle) ?? false;
          const isAdmin = roles?.admin === account.handle;

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
                  {account.devices.length} device{account.devices.length > 1 ? "s" : ""}
                </span>
              </span>

              {roles !== null && !isAdmin && (
                <span className="flex shrink-0 gap-3 text-xs">
                  {/* Only the admin hands out roles: a moderator who could would promote
                      themselves to admin, and there would be no authority left. */}
                  {iAmAdmin && (
                    <>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          action(() =>
                            session.setModerator(view, account.handle, !isModerator),
                          )
                        }
                        className="underline text-(--color-ink-muted)"
                      >
                        {isModerator ? "remove moderator" : "make moderator"}
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
                        title="Hands the group over for good: you will not be able to take it back."
                      >
                        hand over
                      </button>
                    </>
                  )}
                  {/* A moderator removes ordinary members, not their peers. */}
                  {iModerate && (!isModerator || iAmAdmin) && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => action(() => session.removeAccount(view, account.handle))}
                      className="underline text-(--color-danger)"
                    >
                      remove
                    </button>
                  )}
                </span>
              )}
            </li>
          );
        })}
      </ul>

      {roles !== null && iModerate && (
        <p className="mt-3 text-xs text-(--color-ink-muted)">
          Removing someone removes <strong>all of their devices</strong>: the unit is the
          account. From the commit onward, they decrypt nothing that follows.
        </p>
      )}

      {roles !== null && (
        <div className="mt-4 border-t border-(--color-border-subtle) pt-3">
          {leaving ? (
            <div className="space-y-2">
              <p className="text-xs text-(--color-ink-muted)">
                Leaving is a <strong>request</strong>: the protocol forbids removing yourself,
                so another member has to pick it up. Until then you stay in the group and keep
                receiving its messages.
              </p>
              {heir !== null && (
                <p className="text-xs text-(--color-ink-muted)">
                  You administer this group: <strong>@{heir}</strong> will succeed you
                  {roles.moderators.includes(heir)
                    ? " (moderator, the rank below)"
                    : " (longest-standing member)"}
                  . A group with no administrator would be frozen for good.
                </p>
              )}
              {roles.admin === session.handle && heir === null && (
                <p className="text-xs text-(--color-danger)">
                  You are the last member: leaving amounts to deleting the conversation.
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
                  {heir !== null ? `Hand over to @${heir} and leave` : "Request to leave"}
                </button>
                <button
                  type="button"
                  onClick={() => setLeaving(false)}
                  className="text-xs underline text-(--color-ink-muted)"
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setLeaving(true)}
              className="text-xs underline text-(--color-ink-muted)"
            >
              Leave the group
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/** Discreet entry point to the panel, in the conversation header. */
export function GroupToggle({ count, onClick }: { count: number; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title="Group members"
      className="text-xs text-(--color-ink-muted) hover:underline"
    >
      {count + 1} members
    </button>
  );
}
