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
 */
import { useState } from "react";

import type { Session } from "@/lib/session";

export function SignalSettings({
  session,
  onError,
}: {
  session: Session;
  onError: (message: string) => void;
}) {
  const [settings, setSettings] = useState(session.signalSettings());

  const toggle = (key: "readReceipts" | "typingIndicator" | "presence") => {
    const value = !settings[key];
    setSettings({ ...settings, [key]: value });
    session.setSignalSetting(key, value).catch((e: unknown) => {
      onError(e instanceof Error ? e.message : String(e));
    });
  };

  return (
    <section className="space-y-3 text-sm">
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={settings.readReceipts}
          onChange={() => toggle("readReceipts")}
          className="mt-1"
        />
        <span>
          Read receipts
          <span className="block text-xs opacity-70">
            Turning them off also stops you from seeing other people’s. Delivery receipts stay
            on: they record that a device picked the message up, not that a person read it.
          </span>
        </span>
      </label>

      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={settings.typingIndicator}
          onChange={() => toggle("typingIndicator")}
          className="mt-1"
        />
        <span>
          Typing indicator
          <span className="block text-xs opacity-70">
            The content is encrypted and never stored, but the server can see that something is
            being posted to this conversation. Turning it off is the only real protection.
          </span>
        </span>
      </label>

      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={settings.presence !== false}
          onChange={() => toggle("presence")}
          className="mt-1"
        />
        <span>
          “Online” status
          <span className="block text-xs opacity-70">
            Turning it off also stops you from seeing who is online, and asks the server to erase
            what it already noted about your activity. While it is on, the server keeps the time
            of your last connection, to the minute — the only one of these three features that
            requires it to keep a record.
          </span>
        </span>
      </label>

      <p className="text-xs opacity-60">
        Your history is backed up by default, encrypted with your recovery phrase. You can
        change that under “History backup”.
      </p>
    </section>
  );
}
