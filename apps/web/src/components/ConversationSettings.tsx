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
 *
 */
import { useState } from "react";

import type { ConversationView } from "@/lib/session-types";
import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
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
          label="Keep a backup of this conversation"
          hint="Turning it off stops future messages from being deposited. It does not remove what is already there: those entries stay on the server, under a key derived from your recovery phrase."
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
    </Panel>
  );
}
