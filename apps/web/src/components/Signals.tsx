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
 * # Why the switch sends the value it shows
 *
 * `presence` is optional in storage and absent means enabled, so the row is checked when it is
 * anything other than `false`. The old handler wrote `!settings.presence` instead, which on a
 * fresh account — where the field is absent — read `undefined`, negated it to `true`, and wrote
 * back the value that was already in effect: the first press of the switch did nothing at all.
 * Sending the value the control reports makes the displayed state and the written state the same
 * thing by construction.
 *
 * What that does not solve: the write is still optimistic. The row moves before the server has
 * answered, and a failed write leaves it showing a setting that was not recorded — the error is
 * reported, but the switch is not put back. Reverting it would mean the control jumping under
 * the finger, and choosing between the two is a decision for whoever adds retries.
 */
import { useState } from "react";

import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { Field } from "@/ui/Field";
import { Panel } from "@/ui/Panel";
import { Switch } from "@/ui/Switch";

export function SignalSettings() {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const [settings, setSettings] = useState(session.signalSettings());

  const toggle = (key: "readReceipts" | "typingIndicator" | "presence", value: boolean) => {
    setSettings({ ...settings, [key]: value });
    session
      .setSignalSetting(key, value)
      .then(() => {
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
        report.error(e instanceof Error ? e.message : String(e));
      });
  };

  return (
    <Panel
      title="Signals"
      description="What this device tells other people, and what the server can still see either way."
    >
      <div className="space-y-pane">
        <Field
          label="Read receipts"
          hint="Turning them off also stops you from seeing other people’s. Delivery receipts stay on: they record that a device picked the message up, not that a person read it."
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
          hint="The content is encrypted and never stored, but the server can see that something is being posted to this conversation. Turning it off is the only real protection."
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
          hint="Turning it off also stops you from seeing who is online, and asks the server to erase what it already noted about your activity. While it is on, the server keeps the time of your last connection, to the minute — the only one of these three features that requires it to keep a record."
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
