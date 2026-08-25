/**
 * The settings of one conversation.
 *
 * # Why these five exist here and not in the settings screen
 *
 * Because each of them is a decision about *this* thread, and the settings screen is where
 * decisions about the account live. Muting one group has nothing to say about the others, and a
 * screen that listed every conversation to offer a switch per row would be a worse version of the
 * conversation list itself.
 *
 * # The rule this screen exists to satisfy
 *
 * `ui/ContextMenu.tsx` states it: a context menu that is the only way to reach something is a
 * feature hidden behind a gesture — untrue on touch, unknown to anybody who has not tried
 * right-clicking, invisible to a screen reader reading in order. Pinning and muting want to be on
 * the right-click of a row, and they may be, **because** they are here first. This panel is what
 * the shortcut is a shortcut to.
 *
 * # What each control has to say before it is offered
 *
 * The same rule the vault and signalling screens follow: state the cost in the present tense, next
 * to the control, not in a footnote. Two of these are easy to misread and are therefore spelled
 * out:
 *
 *  * **Archiving is a display decision.** An archived conversation keeps polling and keeps
 *    advancing its cursor, because not reading it would leave the ratchet behind and a thread left
 *    archived long enough would come back unreadable. It has to say "hidden", never "paused".
 *  * **Turning off the backup for a conversation does not remove what is already in it.** The
 *    entries stay on the server under a key derived from a phrase that does not rotate. Saying
 *    "stops archiving" is true; letting somebody read it as "erases" is not.
 *  * **Nothing enforces a lifetime on the other side.** The room agrees on it — it is in the MLS
 *    group context, authenticated — and every client that honours it drops the message. A client
 *    that does not, keeps it, and screenshots exist. The sentence sits *above* the control, not
 *    under it: somebody has to read what it does not do before choosing it, not after.
 *
 * # Why the lifetime control is disabled rather than hidden
 *
 * Somebody who cannot change it should learn that a rank is required, not that the feature does
 * not exist. A hidden control teaches the second, and the reader has no way to find out they were
 * wrong.
 */
import { useState } from "react";

import { spokenLifetime } from "@/lib/datetime";
import type { ConversationView } from "@/lib/session-types";
import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { Button } from "@/ui/Button";
import { Dialog } from "@/ui/Dialog";
import { Field } from "@/ui/Field";
import { Panel } from "@/ui/Panel";
import { Switch } from "@/ui/Switch";

/**
 * How long a mute lasts, and why there is no "forever".
 *
 * A permanent mute is the option people reach for and then forget they chose; months later the
 * conversation is silent and its owner believes it is quiet. Offering an end date makes the
 * silence something that lapses on its own, which is what most mutes actually mean.
 *
 * Eight hours is a working day or a night, and a week covers a holiday. Between them they are the
 * two answers "not now" usually has.
 */
const DURATIONS: { label: string; ms: number }[] = [
  { label: "8 hours", ms: 8 * 60 * 60 * 1000 },
  { label: "1 week", ms: 7 * 24 * 60 * 60 * 1000 },
];

/**
 * The lifetimes on offer, and why they are a list rather than a number somebody types.
 *
 * The value travels in the group context and every member reads it: a room where one person
 * chose 86399 seconds is a room whose setting reads as a typo. Four answers cover what people
 * actually mean — off, a day, a week, a month — and each is a round number the notice in the
 * thread can say without rounding.
 */
const LIFETIMES: number[] = [0, 24 * 60 * 60, 7 * 24 * 60 * 60, 30 * 24 * 60 * 60];

export function ConversationSettings({ view }: { view: ConversationView }) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();

  const flags = session.flagsIn(view);
  const muted = session.mutedIn(view);

  // What the finger just did, until the write settles. The same arrangement `Signals.tsx` uses,
  // and for the same reason: these settings now travel between an account's devices, so the
  // truth can move without this screen having touched anything.
  const [pending, setPending] = useState<Record<string, boolean>>({});

  const apply = (key: string, change: () => Promise<void>) => {
    change()
      .then(bump)
      .catch((error: unknown) => {
        report.error(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        setPending(({ [key]: _settled, ...rest }) => rest);
      });
  };

  const set = (key: string, next: Parameters<typeof session.setConversationFlags>[1]) => {
    apply(key, () => session.setConversationFlags(view.key, next));
  };

  const shown = (key: string, value: boolean) => pending[key] ?? value;

  const lifetime = session.lifetimeSeconds(view);

  // A flat conversation — a one-to-one — has no roster and therefore no rank to hold: the rule
  // that applies there is that anybody may change it, which is what `crypto-core` enforces too.
  const roles = session.roles(view);
  const iModerate =
    roles === null ||
    roles.admin === session.accountId ||
    roles.moderators.includes(session.accountId);

  // The choice waiting on a confirmation. Only turning a lifetime *on* asks one, because only
  // that destroys something: it drops this account's archive of the conversation.
  const [confirming, setConfirming] = useState<number | null>(null);
  const [dropping, setDropping] = useState(false);

  const chooseLifetime = (seconds: number) => {
    setDropping(true);
    session
      .setLifetime(view, seconds)
      .then(() => {
        setConfirming(null);
        report.done(
          seconds === 0
            ? "Messages sent here are kept again."
            : `Messages sent here now disappear after ${spokenLifetime(seconds)}.`,
        );
      })
      .then(bump)
      .catch((error: unknown) => {
        report.error(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        setDropping(false);
      });
  };

  return (
    <Panel
      title="This conversation"
      description="Choices about this thread alone. They apply on every device you are signed in on."
    >
      <div className="space-y-pane">
        <Field label="Pin to the top" hint="Kept above the rest of the list, whatever was said last.">
          {(control) => (
            <Switch
              id={control.id}
              aria-describedby={control.describedBy}
              label="Pin to the top"
              checked={shown("pinned", flags.pinned === true)}
              onCheckedChange={(value) => {
                setPending((current) => ({ ...current, pinned: value }));
                set("pinned", { ...flags, pinned: value || undefined });
              }}
            />
          )}
        </Field>

        <Field
          label="Hide from the list"
          hint="Out of the list until something is said here again. It keeps receiving: a conversation that stopped syncing would come back unreadable once the server had collected its messages, so hiding is all this does."
        >
          {(control) => (
            <Switch
              id={control.id}
              aria-describedby={control.describedBy}
              label="Hide from the list"
              checked={shown("archived", flags.archived === true)}
              onCheckedChange={(value) => {
                setPending((current) => ({ ...current, archived: value }));
                set("archived", { ...flags, archived: value || undefined });
              }}
            />
          )}
        </Field>

        <Field
          label="Mute notifications"
          hint={
            muted
              ? `Silent until ${new Date(flags.mutedUntil ?? 0).toLocaleString()}. Unread messages are still counted — muting decides whether you are interrupted, not whether you are told.`
              : "Silences notifications for a while. Unread messages are still counted, and being mentioned does not override it: anyone could otherwise ring a phone its owner silenced by typing one handle."
          }
        >
          {(control) => (
            <div className="flex flex-wrap gap-tight" id={control.id} aria-describedby={control.describedBy}>
              {muted ? (
                <button
                  type="button"
                  className="text-body underline underline-offset-2"
                  onClick={() => set("mutedUntil", { ...flags, mutedUntil: undefined })}
                >
                  Unmute
                </button>
              ) : (
                DURATIONS.map((duration) => (
                  <button
                    key={duration.label}
                    type="button"
                    className="text-body underline underline-offset-2"
                    onClick={() =>
                      set("mutedUntil", { ...flags, mutedUntil: Date.now() + duration.ms })
                    }
                  >
                    Mute for {duration.label}
                  </button>
                ))
              )}
            </div>
          )}
        </Field>

        <Field
          label="Name this conversation in notifications"
          hint="Overrides the account-wide choice for this thread alone. A notification is the one place encryption cannot reach: whoever picks the device up reads what is on the lock screen."
        >
          {(control) => (
            <Switch
              id={control.id}
              aria-describedby={control.describedBy}
              label="Name this conversation in notifications"
              checked={shown("discloseName", session.disclosesNameIn(view))}
              onCheckedChange={(value) => {
                setPending((current) => ({ ...current, discloseName: value }));
                // Written explicitly rather than cleared back to "follow the account": somebody
                // who answered this question about this thread has answered it, and an account
                // setting changed later must not silently reverse them.
                set("discloseName", { ...flags, discloseName: value });
              }}
            />
          )}
        </Field>

        <Field
          label="Make messages disappear"
          hint={
            iModerate
              ? "Messages sent from now on disappear for everybody after this delay. Nothing enforces it on the other side: a modified client keeps what it likes, and screenshots exist. What it does guarantee is that they are not archived on this server."
              : "Messages sent from now on disappear for everybody after this delay. Changing it needs a role in this group — an admin or a moderator — so it is shown here and not offered."
          }
        >
          {(control) => (
            <div
              className="flex flex-wrap gap-tight"
              id={control.id}
              aria-describedby={control.describedBy}
            >
              {LIFETIMES.map((seconds) => (
                <Button
                  key={seconds}
                  type="button"
                  // Not `primary`: the variant table reserves that for the one action a screen
                  // exists for, and a row of choices has none. The current one is raised, the
                  // rest read as text, and `aria-pressed` carries the same fact to a reader who
                  // sees neither.
                  variant={seconds === lifetime ? "secondary" : "quiet"}
                  disabled={!iModerate || dropping}
                  aria-pressed={seconds === lifetime}
                  onClick={() => {
                    // Turning it off destroys nothing and asks nothing. Turning it on drops this
                    // account's archive of the conversation, which is irreversible, so it goes
                    // through the dialog below.
                    if (seconds === 0) chooseLifetime(0);
                    else setConfirming(seconds);
                  }}
                >
                  {seconds === 0 ? "Off" : spokenLifetime(seconds)}
                </Button>
              ))}
            </div>
          )}
        </Field>

        <Field
          label="Keep a backup of this conversation"
          hint={
            lifetime > 0
              ? "This conversation is not backed up. If you lose every device, it does not come back — including what was written today. That is what making messages disappear costs, and it is not separable from it."
              : "Turning it off stops future messages from being deposited. It does not remove what is already there: those entries stay on the server, under a key derived from your recovery phrase."
          }
        >
          {(control) => (
            <Switch
              id={control.id}
              aria-describedby={control.describedBy}
              label="Keep a backup of this conversation"
              checked={shown("archiveToVault", flags.archiveToVault !== false)}
              onCheckedChange={(value) => {
                setPending((current) => ({ ...current, archiveToVault: value }));
                // `false` is the only value worth storing: absent means "follow the account", and
                // writing `true` would pin this thread against an account-wide backup somebody
                // turns off later.
                set("archiveToVault", { ...flags, archiveToVault: value ? undefined : false });
              }}
            />
          )}
        </Field>
      </div>

      {/*
        Turning a lifetime on offers the deletion it implies. `archiveToVault`'s own doc comment
        states the rule this follows: the screen that offers it has to offer the deletion too, or
        it is claiming something it has not done. So the confirmation names exactly what goes —
        this account's archive of this conversation, on the server — and says it does not come
        back.
      */}
      <Dialog
        open={confirming !== null}
        onOpenChange={(open) => !open && setConfirming(null)}
        tone="danger"
        title={
          confirming === null
            ? "Make messages disappear"
            : `Make messages disappear after ${spokenLifetime(confirming)}?`
        }
        description="Your backup of this conversation is deleted from the server, permanently, and no new messages are deposited while this is on. Messages already on anybody's screen stay there — this changes what happens from now on, and what this server keeps."
        actions={
          <>
            <Button variant="secondary" onClick={() => setConfirming(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              busy={dropping}
              onClick={() => {
                if (confirming !== null) chooseLifetime(confirming);
              }}
            >
              Delete the backup and turn it on
            </Button>
          </>
        }
      />
    </Panel>
  );
}
