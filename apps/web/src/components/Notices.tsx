/**
 * Notification settings.
 *
 * # Why permission is asked here and not on load
 *
 * A page that asks the moment it opens is denied once and permanently, and the browsers are
 * right about that: the question means nothing before the person has seen what the application
 * does. So it is asked behind a button, in the same screen as the other privacy switches, and
 * `notifications.ts` deliberately exposes the request without ever calling it.
 *
 * # What the copy has to say before the switch
 *
 * The same rule the vault and the signalling screens follow: state the disclosure in the present
 * tense, next to the control, not in a footnote. A notification is the one part of an encrypted
 * messenger that appears on a locked screen, which is precisely the surface encryption cannot
 * cover.
 *
 * The sentence itself is imported from `notifications.ts` rather than written here. That module
 * owns the behaviour the sentence describes, and a copy of the words next to a copy of nothing
 * is how a settings screen ends up promising something the code stopped doing.
 *
 * # The order on screen, and what it is not
 *
 * Permission first, disclosure second: the second choice is inert until the first is granted.
 * What that does not solve is the switch staying live while permission is denied — it is still
 * a recorded preference, and hiding it would lose the setting rather than explain it.
 */
import { useState } from "react";

import {
  DISCLOSE_NAME_COPY,
  notificationPermission,
  requestNotificationPermission,
} from "@/lib/notifications";
import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { Button } from "@/ui/Button";
import { Field } from "@/ui/Field";
import { Panel } from "@/ui/Panel";
import { Switch } from "@/ui/Switch";

export function NoticeSettings() {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const [permission, setPermission] = useState(notificationPermission());
  const [named, setNamed] = useState(session.discloseConversationName);

  // Called from a click and from nowhere else. Nothing in this component runs it on mount, and
  // that is the whole reason the request lives behind a button rather than in an effect.
  const ask = () => {
    void requestNotificationPermission().then((next) => {
      setPermission(next);
      // A refusal is already explained by the paragraph that replaces the button; a grant leaves
      // the screen looking almost unchanged, which is the case that needs saying out loud.
      if (next === "granted") report.done("Notifications are on.");
    });
  };

  const toggle = (value: boolean) => {
    setNamed(value);
    session
      .setDiscloseConversationName(value)
      .then(bump)
      .catch((e: unknown) => {
        report.error(e instanceof Error ? e.message : String(e));
      });
  };

  return (
    <Panel
      title="Notifications"
      description="A notification tells you a message arrived. It never carries the message, and never the name of who sent it — the lock screen is the one place encryption cannot reach."
    >
      <div className="space-y-pane">
        {permission === "unsupported" ? (
          <p className="text-caption text-(--color-ink-muted)">
            This browser offers no notifications. The unread count in the tab title still works.
          </p>
        ) : permission === "granted" ? (
          <p className="text-caption text-(--color-ink-muted)">
            Notifications are on. They appear only while the application is running: a closed tab
            produces nothing, and nothing on this side changes that.
          </p>
        ) : permission === "denied" ? (
          <p className="text-caption text-(--color-ink-muted)">
            Notifications are blocked for this site. Only the browser can undo that, in its own
            site settings — the page is not allowed to ask twice.
          </p>
        ) : (
          <Button onClick={ask}>Allow notifications</Button>
        )}

        <Field label="Show which conversation" hint={DISCLOSE_NAME_COPY}>
          {(control) => (
            <Switch
              id={control.id}
              aria-describedby={control.describedBy}
              label="Show which conversation"
              checked={named}
              onCheckedChange={toggle}
            />
          )}
        </Field>
      </div>
    </Panel>
  );
}
