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
import { useEffect, useRef, useState } from "react";

import {
  DISCLOSE_NAME_COPY,
  notificationPermission,
  requestNotificationPermission,
} from "@/lib/notifications";
import { PUSH_DISCLOSURE_COPY, pushEnabled, pushSupported } from "@/lib/push";
import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { Banner } from "@/ui/Banner";
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
  // Read from the browser rather than from the session, the way `Recovery.tsx` re-reads its
  // factors from the server: the subscription is the state, and nothing of ours records it. It
  // can also have gone away without this application being told — a browser drops a subscription
  // when site data is cleared.
  const [waking, setWaking] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void pushEnabled().then(setWaking);
  }, []);

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

  // Async, unlike the switch above it, because both directions talk to the browser and to the
  // server. `busy` rather than an optimistic flip: a subscription that failed to register would
  // otherwise leave a switch saying the phone will wake when it will not.
  /**
   * The tail of the chain of toggles, so that only one is ever in flight.
   *
   * `busy` disables the switch while one runs, and that is not enough on its own: subscribing and
   * unsubscribing both reach the browser's push service, and two of them started a second apart
   * finish in an order nobody chose. Observed, both ways round — a switch left saying this browser
   * would be woken with nothing subscribed, and the reverse. Chaining makes the order the one the
   * clicks were in, which is the only order a person can reason about.
   */
  const chain = useRef<Promise<unknown>>(Promise.resolve());

  const toggleWaking = (value: boolean) => {
    setBusy(true);

    const change = chain.current
      // A failed toggle must not stop the next one: the chain is about ordering, not about
      // carrying an error forward. The `.catch` below still reports this one.
      .catch(() => undefined)
      .then(() => (value ? session.enableWaking() : session.disableWaking().then(() => true)));

    chain.current = change;

    change
      .then(async (done) => {
        if (value && !done) {
          // Not a failure: `Api.vapidPublicKey` answers null on a 503, which is this deployment
          // saying it does not do push. Saying so is better than a switch that flips back with no
          // explanation.
          report.error("This server does not send wake-ups.");
        }

        // **Read back rather than trust the call.** Turning it off and on again inside a second
        // leaves the browser's own unsubscribe still running while the new subscription is being
        // made, and the second can lose to the first: the switch then says this browser will be
        // woken while nothing is subscribed. Asking the browser what is true costs one call and
        // makes that class of lie impossible — the subscription is the state, so it is the only
        // thing worth displaying.
        const actual = await pushEnabled();
        setWaking(actual);

        // Only claimed when it is true. A report that says "this browser will be woken" while the
        // read-back disagrees would be the same lie one line further down.
        if (actual === value) {
          report.done(value ? "This browser will be woken." : "This browser will not be woken.");
        }
      })
      .catch((e: unknown) => {
        report.error(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        setBusy(false);
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

        {/*
          * Below the permission cascade, because a wake-up that cannot show a notification is a
          * wake-up for nothing — and above the disclosure switch, because that one refines what a
          * notification says while this one decides whether there is one at all.
          *
          * The banner comes before the control, as on the recovery and vault screens: what this
          * gives up is stated in the present tense, where somebody deciding will read it, and not
          * in a hint under a switch they have already flipped.
          */}
        {pushSupported() ? (
          <>
            <Banner tone="danger" title="What this gives up">
              {PUSH_DISCLOSURE_COPY}
            </Banner>

            <Field
              label="Wake this browser when a message arrives"
              hint="Without this, notifications only appear while Whispee is open in a tab. With it, a closed tab still wakes — and this browser stays subscribed until you turn it off here."
            >
              {(control) => (
                <Switch
                  id={control.id}
                  aria-describedby={control.describedBy}
                  label="Wake this browser when a message arrives"
                  checked={waking}
                  disabled={busy || permission !== "granted"}
                  onCheckedChange={toggleWaking}
                />
              )}
            </Field>
          </>
        ) : null}

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
