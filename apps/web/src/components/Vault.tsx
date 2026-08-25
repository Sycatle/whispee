import { useState } from "react";

import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Checkbox } from "@/ui/Checkbox";
import { Panel } from "@/ui/Panel";

/**
 * History vault settings, **on by default**.
 *
 * This screen does not exist to get a trade-off accepted: it has already been made, in
 * `Session.attach`. It exists to **restate** it and to let the user back out — which is not
 * the same thing as staying quiet about it.
 *
 * Hence the shape: the warning stays on screen, in the present tense, while archiving is on,
 * rather than only on an activation screen nobody will ever see again. A trade-off that
 * becomes the default is exactly the one you stop saying out loud unless you take care to.
 *
 * # What turning it off is about to start costing
 *
 * The stated counterpart used to be that the server does not keep your message bodies. Retention
 * is being built on the server side, and once envelopes past a window are discarded the sentence
 * becomes stronger and harder: nobody keeps them. A message old enough to have been collected
 * then exists nowhere — not on the server, not on a device that only holds the thread in memory.
 * The copy in both branches says so now, in the present of the decision and without a date,
 * because a date we do not control is the kind of promise this screen exists not to make.
 *
 * What that does not solve: nothing here deletes anything. Saying the future is lossier is not
 * the same as offering the erasure of what is already archived, which this screen still cannot
 * do and still says it cannot.
 *
 * # Why one busy value and not one flag per button
 *
 * Three actions share this screen and at most one of them runs at a time. A single boolean would
 * put a spinner in every button whenever any of them was working, which is a false statement
 * about two of the three; naming the running action instead lets the button that is waiting say
 * so and the others merely go inert.
 */
type Running = "restore" | "switch" | null;

export function VaultSettings() {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const [running, setRunning] = useState<Running>(null);
  const [understood, setUnderstood] = useState(false);

  const toggle = async () => {
    setRunning("switch");
    try {
      if (session.archiving) {
        await session.disableVault();
        report.done("Backup is off. Messages from now on will not be archived.");
      } else {
        await session.enableVault();
        report.done("Backup is on. Messages from now on will be archived.");
      }
      bump();
    } catch (e: unknown) {
      report.error(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(null);
    }
  };

  /**
   * Pulls every conversation's archive back in.
   *
   * It used to take the conversation the list had open, as a prop. This screen is reached from
   * the settings route, where there is no open conversation to take — a button that could only
   * ever be disabled here would be worse than no button, and the vault is an account-wide thing
   * anyway. So it sweeps `session.conversations`, which is the same operation applied to each.
   *
   * Sequentially, not `Promise.all`: each restore is a round trip that decrypts entry by entry,
   * and firing one per conversation at once turns a settings click into a burst the server has
   * no reason to absorb.
   *
   * What this does not solve: a failure part way through keeps whatever was already merged and
   * reports only the error, so the count of what did come back is lost. Restoring is idempotent
   * — `vault.merge` drops what the thread already holds — so pressing it again is the recovery,
   * and that is cheaper than a per-conversation result list nobody would read.
   */
  const restore = async () => {
    setRunning("restore");
    try {
      let added = 0;
      for (const view of session.conversations.values()) {
        added += await session.restoreHistory(view);
      }
      bump();
      report.done(
        added === 0
          ? "Nothing left to restore: your conversations already hold everything the vault has."
          : `${added} message${added === 1 ? "" : "s"} restored.`,
      );
    } catch (e: unknown) {
      report.error(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(null);
    }
  };

  if (session.archiving) {
    return (
      <Panel
        title="History backup"
        description="Your messages are archived, encrypted under a key derived from your recovery phrase. The server cannot read them, and your history comes back on its own when you open a conversation."
        actions={
          <>
            <Button
              variant="primary"
              onClick={restore}
              busy={running === "restore"}
              disabled={running !== null}
            >
              Reload from the vault
            </Button>
            <Button onClick={toggle} busy={running === "switch"} disabled={running !== null}>
              Stop backing up
            </Button>
          </>
        }
      >
        <div className="space-y-pane">
          {session.vaultFull && (
            <Banner tone="warn" title="This account is out of room on this server">
              Messages from now on are <strong>not</strong> being archived. Nothing already
              archived has been deleted, and turning the backup off would free nothing — ask
              whoever runs this server for more room.
            </Banner>
          )}

          <Banner tone="danger" title="What you gave up">
            The archive is encrypted under a key derived from your recovery phrase, so
            <strong> the same key forever</strong>. If that phrase ever gets away from you, the
            whole of your backed-up past becomes readable — retroactively. Without the backup, that
            past would have stayed out of reach: that is forward secrecy, and it is real
            protection.
          </Banner>

          <p className="text-caption text-(--color-ink-muted)">
            Stopping the backup does not erase what has already been archived: the server keeps
            those entries, and the key that opens them stays derivable from your phrase. Promising
            a deletion we do not control would be dishonest. Nor does it give back the forward
            secrecy the already-archived past has lost — while the messages that follow will be
            unrecoverable on a new device. Retention is being built on the server side, and once it
            lands the counterpart is no longer only that the server forgets your message bodies:
            nobody keeps them, and a message old enough to have been collected exists nowhere at
            all. We are not promising a date for that.
          </p>
        </div>
      </Panel>
    );
  }

  return (
    <Panel
      title="Backup off"
      description="You turned the backup off. Your messages therefore disappear when the application closes, and a new device starts from an empty conversation. This is not a failure: it is forward secrecy, which keeps the past unreadable even to someone who gets hold of the server later on."
      actions={
        <Button
          variant="primary"
          onClick={toggle}
          busy={running === "switch"}
          disabled={running !== null || !understood}
        >
          Turn the backup back on
        </Button>
      }
    >
      <div className="space-y-pane">
        <Banner tone="danger" title="What you would give up">
          The archive is encrypted under a key derived from your recovery phrase, so
          <strong> the same key forever</strong>. If that phrase ever gets away from you, the whole
          of your backed-up past becomes readable — retroactively. Without the backup, that past
          would have stayed out of reach.
        </Banner>

        <p className="text-caption text-(--color-ink-muted)">
          Archiving would resume from now on and does not reach back in time: the messages
          exchanged while it was off had their keys destroyed, and nothing can reconstruct them.
          Retention is being built on the server side, and once it lands those messages are gone
          from the server too: with the backup off, one old enough to have been collected exists
          nowhere at all, here included. We are not promising a date for that.
        </p>

        {/*
          A checkbox and not a switch: this states an understanding that the button below acts on,
          and it changes nothing by itself. A switch would promise that flipping it already did
          something. `Switch.tsx` draws the same line from the other side.
        */}
        <Checkbox
          label="I understand that my history will no longer be protected by forward secrecy."
          checked={understood}
          onChange={(e) => setUnderstood(e.target.checked)}
        />
      </div>
    </Panel>
  );
}
