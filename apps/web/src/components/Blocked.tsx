/**
 * The accounts this person has declined to read, and the way back.
 *
 * # Why a list exists at all, when the decision is made elsewhere
 *
 * Blocking happens on somebody's card, in front of the face it is about. Undoing it cannot only
 * happen there: a conversation that has gone quiet drops down the list, a group one has left is
 * gone entirely, and the card is reached *through* those. Without this screen, an account blocked
 * in a thread that later went silent is blocked with no way back — a state the interface can
 * produce and not undo, which is the one kind of state it must never produce.
 *
 * # Why the names are resolved here and not stored
 *
 * `blocked` holds account ids, because that is what the credential authenticates and what every
 * comparison in the protocol uses. A handle or a display name would have been kinder to read and
 * wrong to store: both are claims, both change, and a list keyed on a claim would let somebody
 * escape a block by renaming themselves.
 *
 * So the display resolves through `naming.ts` at render time, exactly as the thread does, and
 * falls back to the id in its grouped form when nothing is known — which is the honest answer for
 * an account whose profile was never seen, and it stays copy-pastable.
 *
 * # What this screen deliberately does not offer
 *
 * A way to block somebody from here. That would be a field to paste an account id into, and an
 * account id pasted from somewhere is not a person anybody recognises. Blocking belongs where the
 * person is.
 */
import { compactNameOf, handleOf } from "@/lib/naming";
import { useNames } from "@/state/names";
import { useBump, useRevision, useSession } from "@/state/SessionProvider";
import { useReport } from "@/state/report";
import { Button } from "@/ui/Button";
import { Panel } from "@/ui/Panel";

export function BlockedAccounts() {
  const session = useSession();
  const names = useNames();
  const report = useReport();
  const bump = useBump();
  // The list moves when another of this account's devices decides something — the block travels
  // now — so this reads the revision rather than a snapshot taken on mount.
  useRevision();

  const blocked = [...session.blocked];

  const unblock = (account: string, shown: string) => {
    session
      .setBlocked(account, false)
      .then(() => {
        bump();
        report.done(`Unblocked. What ${shown} says will appear again.`);
      })
      .catch((failure: unknown) => {
        report.error(failure instanceof Error ? failure.message : String(failure));
      });
  };

  return (
    <Panel
      title="Blocked"
      description="Blocking hides what someone says, on every device you are signed in on. It does not stop them sending: their messages are still delivered and stored, and they are never told."
    >
      {blocked.length === 0 ? (
        <p className="text-body text-(--color-ink-muted)">
          Nobody is blocked. You can block someone from their profile, in a conversation you share.
        </p>
      ) : (
        <ul className="space-y-snug">
          {blocked.map((account) => {
            // `among` is the rest of the list: two blocked accounts claiming one name must both
            // fall back to their handle here, for the reason `compactNameOf` gives — otherwise the
            // unblock button names one of two people and the reader cannot tell which.
            const shown = compactNameOf(account, names, blocked);

            return (
              <li key={account} className="flex items-center justify-between gap-snug">
                <span className="min-w-0">
                  <span className="block truncate text-body">{shown}</span>
                  {/* The handle under the name, always: this is a list of people one has decided
                      something about, and a name alone is a claim. */}
                  <span className="block truncate font-evidence text-caption text-(--color-ink-muted)">
                    {handleOf(account, names)}
                  </span>
                </span>
                <Button variant="secondary" size="sm" onClick={() => unblock(account, shown)}>
                  Unblock
                </Button>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
