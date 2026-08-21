/**
 * Notification settings.
 *
 * # Why permission is asked here and not on load
 *
 * A page that asks the moment it opens is denied once and permanently, and the browsers are
 * right about that: the question means nothing before the person has seen what the application
 * does. So it is asked behind a button, in the same drawer as the other privacy switches, and
 * `notifications.ts` deliberately exposes the request without ever calling it.
 *
 * # What the copy has to say before the switch
 *
 * The same rule the vault and the signalling screens follow: state the disclosure in the present
 * tense, next to the control, not in a footnote. A notification is the one part of an encrypted
 * messenger that appears on a locked screen, which is precisely the surface encryption cannot
 * cover.
 */
import { useState } from "react";

import {
  DISCLOSE_NAME_COPY,
  notificationPermission,
  requestNotificationPermission,
} from "@/lib/notifications";
import type { Session } from "@/lib/session";

export function NoticeSettings({
  session,
  onError,
  onClose,
}: {
  session: Session;
  onError: (message: string) => void;
  onClose: () => void;
}) {
  const [permission, setPermission] = useState(notificationPermission());
  const [named, setNamed] = useState(session.discloseConversationName);

  const ask = () => {
    void requestNotificationPermission().then(setPermission);
  };

  const toggle = () => {
    const value = !named;
    setNamed(value);
    session.setDiscloseConversationName(value).catch((e: unknown) => {
      onError(e instanceof Error ? e.message : String(e));
    });
  };

  return (
    <section className="space-y-3 border-b border-(--color-border-subtle) p-3 text-sm">
      <p className="text-xs opacity-70">
        A notification tells you a message arrived. It never carries the message, and never the
        name of who sent it — the lock screen is the one place encryption cannot reach.
      </p>

      {permission === "unsupported" ? (
        <p className="text-xs opacity-70">
          This browser offers no notifications. The unread count in the tab title still works.
        </p>
      ) : permission === "granted" ? (
        <p className="text-xs opacity-70">
          Notifications are on. They appear only while the application is running: a closed tab
          produces nothing, and nothing on this side changes that.
        </p>
      ) : permission === "denied" ? (
        <p className="text-xs opacity-70">
          Notifications are blocked for this site. Only the browser can undo that, in its own site
          settings — the page is not allowed to ask twice.
        </p>
      ) : (
        <button
          type="button"
          onClick={ask}
          className="rounded-md border border-(--color-border-subtle) px-3 py-1.5 text-sm"
        >
          Allow notifications
        </button>
      )}

      <label className="flex items-start gap-2">
        <input type="checkbox" checked={named} onChange={toggle} className="mt-1" />
        <span>
          Show which conversation
          <span className="block text-xs opacity-70">{DISCLOSE_NAME_COPY}</span>
        </span>
      </label>

      <button type="button" onClick={onClose} className="text-xs underline opacity-70">
        Close
      </button>
    </section>
  );
}
