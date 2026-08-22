import { SESSION_LOCK, claim } from "@/lib/singleton";
import { StoredSessionTooOld } from "@/lib/session-types";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Shell } from "@/app/Shell";
import { ShortcutsProvider } from "@/app/Shortcuts";
import { Unlock } from "@/components/Lock";
import { preload } from "@/lib/emoji-sprite";
import { MigrationBanner } from "@/components/Migration";
import { Onboarding } from "@/components/Onboarding";
import { RELOCK_MS, networkReported, observeIdle, observeLifecycle } from "@/lib/lifecycle";
import { compactNameOf } from "@/lib/naming";
import { addressedIn } from "@/lib/mention";
import { countUnreadInTitle, createNotifier } from "@/lib/notifications";
import { type ProposedMigration, Session, start } from "@/lib/session";
import { RouterProvider, useNavigate } from "@/routes/Router";
import { DetailProvider } from "@/state/detail";
import { useNames } from "@/state/names";
import { ReportProvider, useReport, useReported } from "@/state/report";
import { Revision } from "@/state/revision";
import { SessionProvider, useBump, useSession, type SessionStore } from "@/state/SessionProvider";
import { Banner } from "@/ui/Banner";
import { OverlayProvider } from "@/ui/Overlays";
import { Toasts } from "@/ui/Toast";
import { TooltipProvider } from "@/ui/Tooltip";

/**
 * Gates, providers, and the lifecycle nobody else can own.
 *
 * # What is left here, and what left
 *
 * Everything this file used to draw is gone: the header, the conversation list, the settings
 * buttons, the layout. What remains is what genuinely has nowhere else to live.
 *
 * **Three gates.** `busy`, `locked && !session` and `!session` are not routes and must not
 * become ones. They are states in which navigation is moot: the absence of a session is not a
 * place one goes to. `routes/route.ts` says so at length, and one consequence is free — a
 * re-lock on `#/c/abc` leaves the URL alone, so the password drops the user back into their
 * conversation.
 *
 * **Five providers**, in this order, because each one needs the ones outside it: the report
 * channel wraps the gates so that a failed restore can speak; the session, then the router, then
 * the overlay container, then tooltips.
 *
 * **The lifecycle effects**, unchanged in substance. The stream, the poll, the two lock paths,
 * the notifications, the unread count in the title, the outbox flush. Their inputs and outputs
 * were rewired — `onChanged` became `useBump()`, `onError` became `useReport()`, selecting a
 * conversation became a navigation — and nothing about *when* they run was touched.
 *
 * # What was deleted outright
 *
 * The hand-written Android back gesture (`App.tsx:196-221` before this batch). It pushed a
 * synthetic history entry and carried a flag so the cleanup would not pop one too many. Two
 * things cannot share one history stack: both would answer the same `popstate`, and the URL and
 * the React state would drift apart within a single gesture. Every guarantee that block made is
 * now a property of the hash router, mapped one by one in the doc comment of `routes/Router.tsx`.
 */

/**
 * Polling interval, now a safety net rather than an engine.
 *
 * The realtime stream brings news in under a second; what is left here is the upkeep that has no
 * triggering event — replenishing welcome keys, discovering new conversations, propagating to our
 * other devices, evicting revoked devices.
 *
 * Shortening it would make nothing faster: it would only hand the server back the second-by-second
 * activity log the stream just took away from it.
 */
const POLL_MS = 30_000;

export function App() {
  return (
    <ReportProvider>
      <Boot />
    </ReportProvider>
  );
}

/**
 * Restoring, unlocking, onboarding — and then handing over.
 *
 * It is a component of its own rather than the body of `App` for one reason: the gates need to
 * report a failed restore, and `useReport()` only exists below `ReportProvider`.
 */
function Boot() {
  const [session, setSession] = useState<Session | null>(null);
  const [busy, setBusy] = useState(true);
  /** Why migration is impossible, if it is. Informational: nothing is broken. */
  const [fallback, setFallback] = useState<string | null>(null);
  /**
   * Proposed migration, until the user either runs it or dismisses it.
   *
   * Proposed and not executed: it registers one device and revokes another, and nothing about
   * "open the app" asks for that.
   */
  const [migration, setMigration] = useState<ProposedMigration | null>(null);
  const [locked, setLocked] = useState(false);
  const report = useReport();
  const reported = useReported();

  /**
   * One counter for the whole session, created once and never replaced.
   *
   * A new `Revision` per render would hand `useSyncExternalStore` a new `subscribe` every time
   * and resubscribe the entire tree on every keystroke. It is paired with the session in a store
   * object for the same reason: the provider takes one value, and remaking it would re-render
   * every consumer of the context for nothing.
   */
  const revision = useMemo(() => new Revision(), []);
  const store = useMemo<SessionStore | null>(
    () => (session ? { session, revision } : null),
    [session, revision],
  );

  /**
   * Closing a locked session again.
   *
   * Dropping the session is what re-locks: the state on disk is encrypted under a key that only
   * ever existed in memory, so forgetting the object is enough to make the password necessary
   * again. Two paths lead here — coming back after a long absence, and sitting untouched — and
   * they must do exactly the same thing, hence one function.
   *
   * What it does not do: erase that key from the process memory. The WebAssembly module keeps its
   * state, and nothing in a browser lets us demand otherwise. The protection targets whoever picks
   * the device up, not whoever inspects its memory.
   */
  const relock = useCallback(() => {
    setSession(null);
    setLocked(true);
  }, []);

  /**
   * Whether this tab is the one allowed to run a session.
   *
   * `undefined` until the claim settles, so the startup screen does not flash before the answer.
   */
  const [alone, setAlone] = useState<boolean | undefined>(undefined);

  useEffect(() => {
    /*
      Claimed before anything is read, and held for as long as this tab lives.

      Two tabs of one account do not merely duplicate a screen: each holds its own copy of the MLS
      ratchet and persists over the other, and decrypting a message *consumes* the key for its
      generation. So the tab that loses the race asks for a secret the other has already spent,
      OpenMLS answers that it was deleted to preserve forward secrecy, and the message is gone for
      good. See `lib/singleton.ts`, and the `crypto-core` test that pins the underlying rule.

      Never released explicitly: the browser drops it when the tab does, which is the property that
      made this mechanism the right one.
    */
    void claim(SESSION_LOCK).then((held) => setAlone(held.held));
  }, []);

  useEffect(() => {
    // The lock is detected before any restore attempt: without a password the state is
    // unreadable, and treating that as a decryption error would erase the distinction between
    // "locked" and "corrupted".
    Session.isLocked()
      .then(async (isLocked) => {
        if (isLocked) {
          setLocked(true);
          return null;
        }

        // `start` and not `restore`: under Tauri, an existing install may have a migration to
        // perform, which requires keeping the old session open.
        const { session, migration: proposed, fallback: refused } = await start();
        if (refused) setFallback(refused);
        if (proposed) setMigration(proposed);
        return session;
      })
      .then(setSession)
      .catch((e) => {
        // Unreadable state must not block the startup screen: better to offer a fresh identity
        // than to leave an eternal "Loading…".
        console.error("could not restore session", e);

        /*
          A state that is merely unreadable and a state that is *out of date* are different
          things to be told.

          The generic sentence is right for a corrupted or wrongly-keyed blob: nobody can say what
          was in it. `StoredSessionTooOld` can — the accounts were rekeyed, and what did not
          survive is the nicknames and the verifications. Somebody whose verifications are gone
          has to know it, or they will go on believing they have checked a key they have not, and
          that is the one misunderstanding this application cannot afford to leave standing.
        */
        report.error(
          e instanceof StoredSessionTooOld
            ? e.message
            : "Could not restore the previous session. Erase the identity to start over.",
        );
      })
      .finally(() => setBusy(false));
  }, [report]);

  if (busy || alone === undefined) return <Centered>Loading…</Centered>;

  /*
    The second tab is stopped here rather than allowed to read anything.

    It is not a warning that can be dismissed. A tab that carried on would consume message keys
    the other tab needs, and the loss is silent and permanent — there is no state in which showing
    this screen and letting the session run underneath it would be honest.
  */
  if (!alone) {
    return (
      <Centered>
        <div className="flex max-w-prose flex-col gap-snug text-center">
          <p className="text-title">Whispee is already open</p>
          <p className="text-body text-(--color-ink-muted)">
            Another tab of this browser is running your account. Only one may: two would read the
            same messages against two copies of the same encryption state, and a message read twice
            cannot be read again — that is what forward secrecy costs.
          </p>
          <p className="text-body text-(--color-ink-muted)">
            Close the other tab, then reload this one.
          </p>
        </div>
      </Centered>
    );
  }


  if (locked && !store) {
    return (
      <Unlock
        onUnlocked={(s, proposed) => {
          setSession(s);
          if (proposed) setMigration(proposed);
          setLocked(false);
        }}
      />
    );
  }

  if (!store) {
    return <Onboarding onReady={setSession} onError={report.error} error={reported.error} />;
  }

  return (
    <SessionProvider value={store}>
      <RouterProvider>
        <ShortcutsProvider>
          <OverlayProvider>
            <TooltipProvider>
              <Frame
                relock={relock}
                migration={migration}
                onMigrated={(fresh) => {
                  setMigration(null);
                  setSession(fresh);
                }}
                fallback={fallback}
                onDismissFallback={() => setFallback(null)}
              />
            </TooltipProvider>
          </OverlayProvider>
        </ShortcutsProvider>
      </RouterProvider>
    </SessionProvider>
  );
}

/**
 * The running application: the lifecycle effects, the shell, and the strips nobody navigates to.
 *
 * Inside every provider on purpose. These effects report errors, announce mutations and open
 * conversations, which are three hooks that do not exist above.
 */
function Frame({
  relock,
  migration,
  onMigrated,
  fallback,
  onDismissFallback,
}: {
  relock: () => void;
  migration: ProposedMigration | null;
  onMigrated: (session: Session) => void;
  fallback: string | null;
  onDismissFallback: () => void;
}) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const reported = useReported();
  const names = useNames();
  const navigate = useNavigate();
  // Stable by construction, so the poll below can depend on it without restarting its interval
  // every time a banner or a toast changes.
  const { dismissError } = reported;

  /**
   * Does the system report a connection?
   *
   * Shown because `false` is trustworthy information and explains every failure that follows. The
   * opposite proves nothing — a captive portal reports itself online — so nothing is prevented on
   * the strength of this value.
   */
  const [offline, setOffline] = useState(false);

  /**
   * Notices for messages that arrived while the user was elsewhere.
   *
   * Built once and kept in a ref: it holds the standing notices, so rebuilding it on a render
   * would lose the handles and stop a conversation being able to retract its own notice when it
   * is opened.
   */
  const notifier = useRef<ReturnType<typeof createNotifier>>(undefined);
  const title = useRef<ReturnType<typeof countUnreadInTitle>>(undefined);
  /**
   * The content cursor of each conversation at the previous render.
   *
   * An arrival is a cursor that moved, which is the one signal available here that does not
   * depend on guessing what the poll did. Only messages move it — receipts do not, by design —
   * so a quiet exchange of acknowledgements raises nothing.
   */
  const seen = useRef(new Map<string, number>());

  /**
   * Resuming after a spell in the background.
   *
   * The system freezes timers and cuts connections without warning. On return, restarting the
   * interval is not enough: we must poll immediately and **reopen the stream** without trying to
   * find out whether it survived. That question has no reliable answer — a socket cut by the
   * system stays `OPEN` until the first write — and reconnecting needlessly costs less than
   * staying silently mute.
   */
  useEffect(() => {
    const stop = observeLifecycle((transition) => {
      if (transition.kind === "hidden") return;

      if (transition.kind === "network") setOffline(false);

      // A long absence closes a locked device again. Without this the lock would only act on a
      // cold start: it would protect a powered-off device, not one put down mid-conversation.
      if (transition.kind === "resume" && session.locked && transition.awayMs > RELOCK_MS) {
        relock();
        return;
      }

      session.startStream(bump);
      void session
        .poll()
        .then(bump)
        .catch((e: unknown) => report.error(e instanceof Error ? e.message : String(e)));

      // Anything written while the network was gone goes out now. On a transition, not on a
      // timer: retrying on a schedule keeps hammering a server that is down, and the two moments
      // that actually change the answer — a reconnection, a resume — are reported right here.
      void session.flushOutbox().then(bump);
    });

    const lost = () => setOffline(true);
    addEventListener("offline", lost);
    setOffline(!networkReported());

    return () => {
      stop();
      removeEventListener("offline", lost);
    };
  }, [session, bump, report, relock]);

  /**
   * The emoji artwork, once, after the first paint.
   *
   * One request for the whole untoned set. It is not on the critical path — nothing on screen
   * needs it to lay out, and `ui/Emoji.tsx` draws an empty box of the right size until it lands —
   * so it waits for an idle moment rather than competing with the session opening its socket.
   *
   * It happens here and not in the picker because a *received* message needs it too, and the
   * first one usually arrives before anybody opens a picker.
   *
   * `requestIdleCallback` is absent from Safari before 17 and therefore from some of the WebKit
   * builds we ship into; the timeout is the fallback rather than a second chance, hence the
   * either-or.
   */
  useEffect(() => {
    if (typeof requestIdleCallback === "function") {
      const id = requestIdleCallback(preload, { timeout: 2_000 });
      return () => cancelIdleCallback(id);
    }

    const id = setTimeout(preload, 500);
    return () => clearTimeout(id);
  }, []);

  /**
   * The same lock, for a device nobody has taken away.
   *
   * The resume path above only fires on a device that left the foreground — a phone pocketed, a
   * tab switched. A desktop session left open on screen never triggers it, and until now stayed
   * readable until the tab closed: exactly the machine most likely to be shared, and the one
   * `docs/THREAT-MODEL.md` admitted was uncovered.
   *
   * Nothing is watched while the session carries no lock: without a password to come back with,
   * dropping the session would only mean a reload with no gain.
   */
  useEffect(() => {
    if (!session.locked) return;
    return observeIdle(relock, document);
  }, [session, relock]);

  useEffect(() => {
    let cancelled = false;

    const tick = async () => {
      try {
        await session.poll();
        if (cancelled) return;

        // A successful poll clears the previous error.
        //
        // Without this a passing incident — network cut, server restarted — leaves a red banner on
        // screen indefinitely while everything works again. An alert that outlives its cause
        // teaches people to ignore it, and the day it matters it has already become invisible.
        dismissError();
        bump();
      } catch (e) {
        if (!cancelled) report.error(e instanceof Error ? e.message : String(e));
      }
    };

    void tick();
    const id = setInterval(tick, POLL_MS);

    // The stream is not a dependency of the poll: it triggers it earlier, nothing more. If it
    // never connects, the interval above is enough to keep everything working.
    session.startStream(() => {
      if (!cancelled) bump();
    });

    return () => {
      cancelled = true;
      clearInterval(id);
      session.stopStream();
    };
    // `duo` is deliberately absent, where it used to be listed: the poll no longer selects a
    // conversation, so a resize no longer has any business restarting the interval and reopening
    // the stream. Filling the empty right-hand panel is the shell's job now, and a layout change
    // is not a reason to talk to the server.
  }, [session, bump, report, dismissError]);

  useEffect(() => {
    notifier.current ??= createNotifier({
      // Opening the conversation is a navigation now, so a notice clicked from the system tray
      // leaves an entry the back gesture can undo — and the URL says where we are.
      select: (key: string) => navigate({ kind: "conversation", key }),
    });
    title.current ??= countUnreadInTitle();

    const notices = notifier.current;
    const counter = title.current;

    return () => {
      // Leaving the session — a re-lock, a migration, the tab closing — must not leave a notice
      // standing for a thread nobody can open any more, nor a counted title on a page that no
      // longer knows the count.
      notices.dismissAll();
      counter.restore();
    };
  }, [session, navigate]);

  useEffect(() => {
    let unread = 0;
    for (const [key, view] of session.conversations) {
      unread += session.unreadIn(view);

      const before = seen.current.get(key);
      seen.current.set(key, view.contentCursor);

      // `before === undefined` is the first sight of a conversation, not an arrival: a device
      // that has just paired discovers a hundred threads at once and would raise a hundred
      // notices for messages nobody is newly receiving.
      if (before !== undefined && view.contentCursor > before) {
        // The name only travels if the user asked for it: it is the one thing here that ends up
        // legible on a locked screen.
        /*
          The compact form, and the second of the two places it exists for. A notification is one
          line on a lock screen, read at a glance and with nowhere to put the handle underneath —
          so a self-asserted name that another member of the same thread could be mistaken for is
          not shown at all, and everybody involved falls back to their handle.

          The disclosure guard above it is unchanged on purpose. A display name is exactly as
          disclosing as a handle: both name a person to whoever is looking at the screen, and
          treating a human-readable one as the lesser leak would have it get past a setting the
          user turned off for the other.
        */
        const among = view.accounts.map((account) => account.handle);
        // Per conversation, falling back to the account setting. The three states are the point:
        // an absent flag follows the account, and only an explicit one overrides it in either
        // direction — see `Session.disclosesNameIn`.
        const name = session.disclosesNameIn(view)
          ? view.accounts.map((account) => compactNameOf(account.handle, names, among)).join(", ")
          : undefined;

        /*
          Whether any of what just landed was aimed at us, decided by the same module the thread
          renders mentions with. One rule, so a notification cannot fire for a mention the reader
          will not find highlighted when they arrive — nor stay silent for one they will.

          `before` is the cursor as it stood, so this asks about the arrival and not about the
          thread; `among` is this conversation's members, which is what makes an `@handle` naming
          somebody who is not here stay prose here too.
        */
        //
        // Our own handle is added to the set. `among` above is the *other* side — it exists to
        // decide whether a name is ambiguous, a question we are never the subject of — and a
        // mention scanner given that set would refuse to recognise the one handle it is looking
        // for. This is the bug that would have made the feature silently do nothing.
        const address = addressedIn(view.messages, before, session.accountId, [
          ...among,
          session.accountId,
        ]);

        /*
          Muting silences the notification and nothing else.

          The unread count still moves, the title still counts it, and the thread still shows the
          line as unread — because muting is a decision about being interrupted, not a decision to
          stop being told. A mute that also hid the count would be indistinguishable from having
          read the conversation, and the person who muted a busy group would lose the one signal
          that tells them to go back to it.

          Being addressed does not override it. It is tempting — a mention is the case people say
          they want to hear about — but it hands anybody in the group a way to ring a phone its
          owner explicitly silenced, by typing one handle. Silence has to mean silence, or it is a
          suggestion.
        */
        /*
          Nothing from somebody we have declined to read.

          Judged on the authors of what actually arrived, not on the membership of the room: in a
          group, a blocked member must not be able to raise a notice, and the other members must
          go on raising them. A conversation-level test would have made blocking one person in a
          busy group silence everybody, which is a different feature nobody asked for.

          Our own messages are skipped for the same reason `addressedIn` skips them — an arrival
          is what somebody else said. Without that, catching up on a thread we posted to would be
          judged on an author who cannot be blocked, and the notice would fire from a room where
          the only other speaker is blocked.
        */
        const arrivals = view.messages.filter((message) => message.seq > before && !message.mine);
        // `arrivals.length > 0` is not defensive noise: `every` on an empty list is `true`, and
        // without it a batch of nothing but our own messages would read as a batch of blocked
        // ones. A sender we could not attribute is likewise *not* blocked — sealed sender means
        // some arrivals have no author to decline, and declining what cannot be named would
        // silence the very messages nobody can account for.
        const silenced =
          arrivals.length > 0 &&
          arrivals.every((message) => message.sender !== null && session.isBlocked(message.sender));

        if (!silenced && !session.mutedIn(view)) {
          notifier.current?.arrived({
            conversation: key,
            ...(name ? { name } : {}),
            ...(address ? { address } : {}),
          });
        }
      }
    }

    // Opening a thread retracts its notice. `markRead` has already run by the time this render
    // happens, so an unread count of zero is the same fact seen from here.
    for (const [key, view] of session.conversations) {
      if (session.unreadIn(view) === 0) notifier.current?.dismiss(key);
    }

    title.current?.show(unread);
  });

  return (
    <div
      // `h-dvh` and not `h-screen`: on mobile, `100vh` counts the height with the bars expanded, so
      // a hundred pixels or so end up below the screen — precisely the input field and the last
      // message.
      //
      // No `max-w-5xl` any more: a three column shell takes the window. Centring it left two
      // grey margins on a wide monitor and pinched the thread to a third of the space it had.
      className="flex h-dvh flex-col bg-(--color-surface) text-(--color-ink)"
    >
      {/*
        Key log anomalies are shown at the app level, not inside a conversation: they concern
        account identities, hence every conversation at once.
      */}
      {session.logAlerts.length > 0 && (
        <Banner tone="danger" title="Inconsistent key log" className="rounded-none border-x-0 border-t-0">
          {session.logAlerts.map((alert) => (
            <p key={alert}>{alert}</p>
          ))}
          <p className="mt-tight text-caption">
            The server failed to prove what it claims about account keys. This is not a network
            outage: it is exactly what this check exists to catch.
          </p>
        </Banner>
      )}

      {/* Around the shell and no higher: the detail column belongs to a conversation, and
          nothing outside the shell — the lock screen, onboarding, the migration notice — has one
          to open. See `state/detail.tsx` for why it stopped being a route. */}
      <DetailProvider>
        <Shell
          onLock={relock}
          onForget={() => void session.forget().then(() => location.reload())}
        />
      </DetailProvider>

      {migration && (
        <MigrationBanner
          migration={migration}
          onDone={onMigrated}
          onError={report.error}
        />
      )}

      {offline && (
        <Banner tone="warn" className="rounded-none border-x-0 border-b-0">
          Offline. Messages written now will not go out; anything already received stays readable.
        </Banner>
      )}

      {fallback && (
        <Banner onDismiss={onDismissFallback} className="rounded-none border-x-0 border-b-0">
          {fallback}
        </Banner>
      )}

      {/* Always dismissible: an error you cannot wave away ends up part of the scenery. */}
      {reported.error && (
        <Banner
          tone="danger"
          onDismiss={reported.dismissError}
          className="rounded-none border-x-0 border-b-0"
        >
          {reported.error}
        </Banner>
      )}

      <Toasts />
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-dvh items-center justify-center p-8 text-center text-body text-(--color-ink-muted)">
      {children}
    </div>
  );
}
