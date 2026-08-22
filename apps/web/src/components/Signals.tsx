/**
 * Signalling settings.
 *
 * # Why the reciprocity is spelled out on screen
 *
 * Turning off your read receipts also stops showing you other people's. This is how WhatsApp and
 * Signal behave, and it surprises everyone when it is not announced. Burying it in documentation
 * would mean discovering the trade-off after the fact, which is exactly what a privacy setting
 * must not do.
 *
 * # Presence follows the same rule, and goes further
 *
 * It is the only feature shown here that forces the server to keep a record spanning all
 * conversations — and therefore to know when each person is awake. No amount of encryption gets
 * around that: which is why turning it off does not merely hide the display, it tells the server
 * to **stop recording** and to erase what it already noted. A setting that only filtered on read
 * would fix nothing.
 *
 * # The settings belong to the account, not to this device
 *
 * They used to belong to the device, and the panel still says "this device" about what it
 * discloses, which is true of the disclosure and was true of the setting. It is no longer: a
 * refusal one laptop honoured while a phone kept emitting was a refusal in name only. They now
 * travel between an account's own devices, sealed so that the room carrying them cannot read
 * them — `lib/signal-sync.ts` says why that seal is not optional.
 *
 * Which is also why this reads its state back rather than trusting what it wrote: another device
 * can move a switch here, and it arrives on the poll that carries everything else.
 *
 * # Why the switch sends the value it shows
 *
 * `presence` is optional in storage and absent means enabled, so the row is checked when it is
 * anything other than `false`. The old handler wrote `!settings.presence` instead, which on a
 * fresh account — where the field is absent — read `undefined`, negated it to `true`, and wrote
 * back the value that was already in effect: the first press of the switch did nothing at all.
 * Sending the value the control reports makes the displayed state and the written state the same
 * thing by construction.
 *
 * # Why a failed write puts the switch back
 *
 * The row still moves before the server has answered — waiting would make every toggle feel
 * broken on a slow link. What changed is the ending: the optimistic value is dropped when the
 * call settles, success or failure, and what is drawn afterwards is whatever the session actually
 * holds. A failed write therefore leaves the switch where the setting really is.
 *
 * The objection to that was the control jumping under the finger. It does, and it should: the
 * alternative is a privacy setting displaying a state it failed to record, which is the one lie
 * this panel must not tell. It happens only when the write failed, and the error is reported in
 * the same breath.
 */
import { useMemo, useState } from "react";

import { CALLS_CONFIGURED } from "@/lib/call";
import { useReport } from "@/state/report";
import { useBump, useRevision, useSession } from "@/state/SessionProvider";
import { Field } from "@/ui/Field";
import { Panel } from "@/ui/Panel";
import { Switch } from "@/ui/Switch";

export function SignalSettings() {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const revision = useRevision();

  // Recomputed whenever anything mutates the session, which is how a change made on another
  // device lands here: it arrives during a poll, and the poll bumps the revision.
  const stored = useMemo(() => session.signalSettings(), [session, revision]);

  // What the finger just did, until the write settles. Dropped either way afterwards — see the
  // header — so that what is drawn is the setting that was really recorded.
  const [pending, setPending] = useState<Partial<typeof stored>>({});
  const settings = { ...stored, ...pending };

  const toggle = (key: "readReceipts" | "typingIndicator" | "presence" | "calls", value: boolean) => {
    setPending((current) => ({ ...current, [key]: value }));

    const settle = () => {
      setPending(({ [key]: _dropped, ...rest }) => rest);
    };

    session
      .setSignalSetting(key, value)
      .then(() => {
        settle();
        bump();
        // Only presence is confirmed out loud, and only when it goes off. The other two are
        // already confirmed by the switch itself: the thing they change is the thing that moved.
        // Erasing the server's record of your activity is the one effect here that happens
        // somewhere the user cannot see, so it is the one worth a sentence.
        if (key === "presence" && !value) {
          report.done("Presence is off, and the server has been asked to erase what it noted.");
        }
      })
      .catch((e: unknown) => {
        settle();
        report.error(e instanceof Error ? e.message : String(e));
      });
  };

  return (
    <Panel
      title="Signals"
      description="What you tell other people, on every device you are signed in on, and what the server can still see either way."
    >
      <div className="space-y-pane">
        <Field
          label="Read receipts"
          hint="Turning them off also stops you from seeing other people’s, and applies to every device you are signed in on — one that is offline follows the next time it connects. The server cannot see receipts at all, so it cannot enforce that exchange: this app is what holds up your side of it. Delivery receipts stay on either way, since they record that a device picked the message up, not that a person read it."
        >
          {(control) => (
            <Switch
              id={control.id}
              aria-describedby={control.describedBy}
              label="Read receipts"
              checked={settings.readReceipts}
              onCheckedChange={(value) => toggle("readReceipts", value)}
            />
          )}
        </Field>

        <Field
          label="Typing indicator"
          hint="Turning it off also stops you from seeing other people typing, and applies to every device you are signed in on. The content is encrypted and never stored, but the server can still see that something is being posted to this conversation — turning it off is the only real protection against that."
        >
          {(control) => (
            <Switch
              id={control.id}
              aria-describedby={control.describedBy}
              label="Typing indicator"
              checked={settings.typingIndicator}
              onCheckedChange={(value) => toggle("typingIndicator", value)}
            />
          )}
        </Field>

        <Field
          label="“Online” status"
          hint="Turning it off also stops you from seeing who is online, and asks the server to erase what it already noted about your activity. This one it enforces itself, for the whole account: it stops recording rather than stops showing. While it is on, the server keeps the time of your last connection, to the minute — the only one of these three features that requires it to keep a record."
        >
          {(control) => (
            <Switch
              id={control.id}
              aria-describedby={control.describedBy}
              label="“Online” status"
              checked={settings.presence !== false}
              onCheckedChange={(value) => toggle("presence", value)}
            />
          )}
        </Field>

        {/*
          Absent, not disabled, when this build knows of no media server: there is no setting to
          make about a feature that cannot happen. Same argument as the call button in the
          conversation bar, and the same constant.
        */}
        {CALLS_CONFIGURED ? (
          <Field
            label="Calls"
            hint="Turning them off also stops you from placing one, and applies to every device you are signed in on. A call leaks more than a message: the server sees that you joined one and towards which conversation, and the media server sees who was in the room with you and for how long. Neither can hear anything — the audio is encrypted under a key derived from the conversation itself, which never leaves your devices."
          >
            {(control) => (
              <Switch
                id={control.id}
                aria-describedby={control.describedBy}
                label="Calls"
                checked={settings.calls !== false}
                onCheckedChange={(value) => toggle("calls", value)}
              />
            )}
          </Field>
        ) : null}

        {/*
          `text-(--color-ink-muted)` rather than an opacity on the ink: the muted token is already
          the low-contrast end of the palette, and fading it further took this line under 3:1.
        */}
        <p className="text-caption text-(--color-ink-muted)">
          Your history is backed up by default, encrypted with your recovery phrase. You can change
          that under “History backup”.
        </p>
      </div>
    </Panel>
  );
}
