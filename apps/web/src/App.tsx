import { useCallback, useEffect, useRef, useState } from "react";
import { Unlock } from "@/components/Lock";
import { Conversation } from "@/components/Conversation";
import { ConversationList } from "@/components/ConversationList";
import { Onboarding } from "@/components/Onboarding";
import { MigrationBanner } from "@/components/Migration";
import { type ConversationView, type ProposedMigration, Session, start } from "@/lib/session";
import { useDuo } from "@/lib/duo";
import { RELOCK_MS, observeIdle, observeLifecycle, networkReported } from "@/lib/lifecycle";
import { countUnreadInTitle, createNotifier } from "@/lib/notifications";

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
  const [session, setSession] = useState<Session | null>(null);
  const [active, setActive] = useState<ConversationView | null>(null);
  const [error, setError] = useState<string | null>(null);
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
  /**
   * Does the system report a connection?
   *
   * Shown because `false` is trustworthy information and explains every failure that follows. The
   * opposite proves nothing — a captive portal reports itself online — so nothing is prevented on
   * the strength of this value.
   */
  const [offline, setOffline] = useState(false);
  const [locked, setLocked] = useState(false);
  const [, forceRender] = useState(0);
  const duo = useDuo();
  const refresh = useCallback(() => forceRender((n) => n + 1), []);

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
    setActive(null);
    setLocked(true);
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
        setError("Could not restore the previous session. Erase the identity to start over.");
      })
      .finally(() => setBusy(false));
  }, []);

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
    if (!session) return;

    const stop = observeLifecycle((transition) => {
      if (transition.kind === "hidden") return;

      if (transition.kind === "network") setOffline(false);

      // A long absence closes a locked device again. Without this the lock would only act on a
      // cold start: it would protect a powered-off device, not one put down mid-conversation.
      if (transition.kind === "resume" && session.locked && transition.awayMs > RELOCK_MS) {
        relock();
        return;
      }

      session.startStream(refresh);
      void session
        .poll()
        .then(() => {
          setError(null);
          refresh();
        })
        .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));

      // Anything written while the network was gone goes out now. On a transition, not on a
      // timer: retrying on a schedule keeps hammering a server that is down, and the two moments
      // that actually change the answer — a reconnection, a resume — are reported right here.
      void session.flushOutbox().then(refresh);
    });

    const lost = () => setOffline(true);
    addEventListener("offline", lost);
    setOffline(!networkReported());

    return () => {
      stop();
      removeEventListener("offline", lost);
    };
  }, [session, refresh, relock]);

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
    if (!session?.locked) return;
    return observeIdle(relock, document);
  }, [session, relock]);

  /**
   * The system back gesture closes the conversation instead of quitting the app.
   *
   * # Why go through history
   *
   * On Android as in a mobile browser, the back gesture acts on history. A single-panel app that
   * leaves history alone gets quit on the first back, when the user only wanted to return to their
   * list — the most common reflex on mobile, and the one whose failure looks most like a crash.
   *
   * # The guard
   *
   * The pushed entry must be removed if the conversation closes some other way — via the header's
   * back button, or because the screen got wider. The flag tells the two apart: without it, one
   * `history.back()` too many would consume an entry that is not ours, and on Android that closes
   * the app.
   */
  const pushedEntry = useRef(false);

  useEffect(() => {
    // `active` and not the retained conversation: that one is only computed after the startup
    // screens, hence after the hooks. The two coincide at one panel, where the selection falls
    // back to nothing.
    if (duo || !active) return;

    history.pushState({ wac: "conversation" }, "");
    pushedEntry.current = true;

    const goBack = () => {
      // Consumed by the system: there is nothing left to remove.
      pushedEntry.current = false;
      setActive(null);
    };

    addEventListener("popstate", goBack);
    return () => {
      removeEventListener("popstate", goBack);
      if (pushedEntry.current) {
        pushedEntry.current = false;
        history.back();
      }
    };
  }, [duo, active]);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;

    const tick = async () => {
      try {
        await session.poll();
        if (cancelled) return;

        // Open the first conversation while none is selected, **and only at two panels**.
        //
        // There it fills a void: a freshly paired device discovers its conversations during the
        // poll, and without this it shows a list on the left and nothing on the right, as if the
        // messages were not arriving when they are already decrypted.
        //
        // At one panel the same line does the opposite of what it intends: it opens a conversation
        // nobody asked for and covers the list, which is the home screen. The only way out is the
        // back button, on a screen the user never entered.
        if (duo) {
          setActive((current) => current ?? session.conversations.values().next().value ?? null);
        }

        // A successful poll clears the previous error.
        //
        // Without this a passing incident — network cut, server restarted — leaves a red banner on
        // screen indefinitely while everything works again. An alert that outlives its cause
        // teaches people to ignore it, and the day it matters it has already become invisible.
        setError(null);
        refresh();
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    };

    void tick();
    const id = setInterval(tick, POLL_MS);

    // The stream is not a dependency of the poll: it triggers it earlier, nothing more. If it
    // never connects, the interval above is enough to keep everything working.
    session.startStream(() => {
      if (!cancelled) refresh();
    });

    return () => {
      cancelled = true;
      clearInterval(id);
      session.stopStream();
    };
  }, [session, refresh, duo]);

  useEffect(() => {
    if (!session) return;

    notifier.current ??= createNotifier({
      select: (key: string) => {
        const view = session.conversations.get(key);
        if (view) setActive(view);
      },
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
  }, [session]);

  useEffect(() => {
    if (!session) return;

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
        const name = session.discloseConversationName
          ? view.accounts.map((account) => `@${account.handle}`).join(", ")
          : undefined;

        notifier.current?.arrived({ conversation: key, ...(name ? { name } : {}) });
      }
    }

    // Opening a thread retracts its notice. `markRead` has already run by the time this render
    // happens, so an unread count of zero is the same fact seen from here.
    for (const [key, view] of session.conversations) {
      if (session.unreadIn(view) === 0) notifier.current?.dismiss(key);
    }

    title.current?.show(unread);
  });

  if (busy) return <Centered>Loading…</Centered>;

  if (locked && !session) {
    return (
      <Unlock
        onUnlocked={(s, proposed) => {
          setSession(s);
          if (proposed) setMigration(proposed);
          setLocked(false);
        }}
        onError={setError}
      />
    );
  }

  if (!session) {
    return <Onboarding onReady={setSession} onError={setError} error={error} />;
  }

  const conversations = [...session.conversations.values()];

  // At two panels a conversation is always open: an empty right panel would be permanent
  // emptiness. At one panel, having no selection **is** the list screen — falling back to the
  // first conversation would make the list unreachable.
  const retained = active && session.conversations.get(active.key) ? active : null;
  const current = duo ? retained ?? conversations[0] ?? null : retained;

  return (
    <div
      // `h-dvh` and not `h-screen`: on mobile, `100vh` counts the height with the bars expanded, so
      // a hundred pixels or so end up below the screen — precisely the input field and the last
      // message.
      className="safe-sides safe-top mx-auto flex h-dvh max-w-5xl flex-col"
    >
      {/* At one panel, the header only shows on the list. In the conversation it cost a sixth of
          the height to repeat an identity the user knows, while the screen already carries its own
          header — the correspondent's, which is useful to them. The warning stays readable: the
          list is the home screen. */}
      {(duo || !current) && (
        <Header session={session} onForget={() => session.forget().then(() => location.reload())} />
      )}

      {/*
        Key log anomalies are shown at the app level, not inside a conversation: they concern
        account identities, hence every conversation at once.
      */}
      {session.logAlerts.length > 0 && (
        <div role="alert" className="border-b border-(--color-danger) bg-(--color-danger)/20 px-4 py-3 text-sm">
          <p className="font-medium text-(--color-danger)">Inconsistent key log</p>
          {session.logAlerts.map((alert) => (
            <p key={alert} className="mt-1 text-(--color-ink-muted)">
              {alert}
            </p>
          ))}
          <p className="mt-2 text-xs text-(--color-ink-muted)">
            The server failed to prove what it claims about account keys. This is not a network
            outage: it is exactly what this check exists to catch.
          </p>
        </div>
      )}

      <div className="flex min-h-0 flex-1">
        {/* At one panel only one of the two is mounted — not hidden: a hidden conversation would
            keep polling, scrolling and claiming keyboard focus. */}
        {(duo || !current) && (
          <ConversationList
            session={session}
            conversations={conversations}
            current={current}
            onSelect={setActive}
            onError={setError}
            onChanged={refresh}
          />
        )}
        {current ? (
          <Conversation
            session={session}
            view={current}
            onChanged={refresh}
            onError={setError}
            onBack={duo ? undefined : () => setActive(null)}
          />
        ) : (
          duo && <Centered>No conversations. Start one with someone&apos;s handle.</Centered>
        )}
      </div>

      {migration && (
        <MigrationBanner
          migration={migration}
          onDone={(fresh) => {
            setMigration(null);
            setActive(null);
            setSession(fresh);
          }}
          onError={setError}
        />
      )}

      {offline && (
        <p
          role="status"
          className="border-t border-(--color-warn) bg-(--color-warn)/10 px-4 py-2 text-sm text-(--color-warn)"
        >
          Offline. Messages written now will not go out; anything already received stays readable.
        </p>
      )}

      {fallback && (
        <p className="flex items-baseline justify-between gap-4 border-t border-(--color-ink-muted)/30 bg-(--color-ink-muted)/10 px-4 py-2 text-sm text-(--color-ink-muted)">
          <span>{fallback}</span>
          <button type="button" onClick={() => setFallback(null)} className="shrink-0 underline">
            Dismiss
          </button>
        </p>
      )}

      {error && (
        <p
          role="alert"
          className="flex items-baseline justify-between gap-4 border-t border-(--color-danger) bg-(--color-danger)/10 px-4 py-2 text-sm text-(--color-danger)"
        >
          <span>{error}</span>
          {/* Always dismissible: an error you cannot wave away ends up part of the scenery. */}
          <button type="button" onClick={() => setError(null)} className="shrink-0 underline">
            Dismiss
          </button>
        </p>
      )}
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-1 items-center justify-center p-8 text-center text-sm text-(--color-ink-muted)">
      {children}
    </div>
  );
}

function Header({ session, onForget }: { session: Session; onForget: () => void }) {
  return (
    <header className="border-b border-(--color-border-subtle) px-4 py-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        {/*
          The user's own fingerprint is no longer shown permanently: it is of no daily use to them.
          It now lives in the verification panel, next to the correspondent's — the one place where
          it is actually needed.
        */}
        <h1 className="font-medium">
          @{session.handle}{" "}
          <span className="font-normal text-(--color-ink-muted)">
            · {session.deviceId.slice(session.handle.length + 1)}
          </span>
        </h1>
        <button type="button" onClick={onForget} className="text-sm text-(--color-ink-muted) underline">
          Erase this identity
        </button>
      </div>
      {/*
        This warning does stay, because it is not about one conversation but about the whole tool:
        it is a limit the user has to know in order to decide what to trust it with.
      */}
      <p className="mt-2 text-xs text-(--color-ink-muted)">
        Web client: the server delivers this code on every load, and could deliver a version that
        exfiltrates your keys. No browser API fixes that. This is a learning project, unaudited —
        for genuinely sensitive conversations, use Signal.
      </p>
    </header>
  );
}
