import { useEffect, useState } from "react";
import { MIN_LENGTH, type Verdict, check } from "@/lib/password";
import { biometricEnabled, biometricAvailable } from "@/lib/biometrics";
import type { ProposedMigration, Session } from "@/lib/session";
import { useBump, useSession } from "@/state/SessionProvider";
import { useReport } from "@/state/report";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Field } from "@/ui/Field";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Input } from "@/ui/Input";
import { Panel } from "@/ui/Panel";
import { Switch } from "@/ui/Switch";

/**
 * Password prompt at startup, when a lock is set.
 *
 * # Why this one screen still takes props, when nothing else does
 *
 * Everywhere else in the tree the session arrives through `useSession()` and failures through
 * `useReport()`, and passing either as a prop is a mistake. This component is the single
 * exception, and it is a structural one rather than an oversight: `App.tsx` renders it when
 * `locked && !session`, which is to say **before a session exists at all**. There is no
 * `<SessionProvider>` above it to read from, and `onUnlocked` is precisely the call that creates
 * the session the provider will later hold. A hook here would throw on first paint.
 *
 * The signature is therefore frozen as it is, and this note exists so that the next person to
 * run the "no session in props" rule down the file list stops here instead of "fixing" it.
 *
 * What this does not solve: it says nothing about `onError`, which is kept for the same reason —
 * there is no `<ReportProvider>` guarantee this early in startup either, so the caller owns the
 * message. It is the caller's error channel, not a second one.
 */
export function Unlock({
  onUnlocked,
  onError,
}: {
  // The migration proposal travels with the session: it comes out of the same startup, and
  // dropping it here would lose it for locked installs — precisely the ones whose state only
  // becomes readable at this moment.
  onUnlocked: (session: Session, migration?: ProposedMigration) => void;
  onError: (message: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [refused, setRefused] = useState(false);
  const [canUseBiometric, setCanUseBiometric] = useState(false);

  useEffect(() => {
    void biometricEnabled().then(setCanUseBiometric);
  }, []);

  /**
   * Unlocking through the system prompt.
   *
   * The prompt is raised in the native process, on the key's path — this component only asks. A
   * refusal leaves the screen as it is, password field included: biometrics are a shortcut, never
   * the only way in, otherwise a broken sensor would lock the account out.
   */
  const unlockByPrompt = async () => {
    setBusy(true);
    setRefused(false);
    try {
      const { unlockWithBiometric } = await import("@/lib/biometrics");
      const master = await unlockWithBiometric();
      if (!master) return;

      const [{ start }, { importMaster }] = await Promise.all([
        import("@/lib/session"),
        import("@/lib/lock"),
      ]);
      const { session, migration } = await start(await importMaster(master));
      if (session) onUnlocked(session, migration);
    } catch {
      setRefused(true);
    } finally {
      setBusy(false);
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setRefused(false);
    try {
      const { start } = await import("@/lib/session");
      // The same path as an unlocked startup: an install that needs migrating must be migrated
      // here too, and only now is the state readable.
      const { session, migration } = await start(password);
      if (session) onUnlocked(session, migration);
    } catch {
      // Every error is presented as a wrong password: telling "bad password" apart from "corrupted
      // data" would teach an attacker when they are getting close.
      setRefused(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="safe-top safe-bottom safe-sides mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-section p-pane">
      <div className="flex flex-col gap-snug">
        {/* The padlock is the one piece of decoration on this screen, and it earns its place: it
            is the only thing a returning reader can recognise before reading a word, and it
            tells them the app did not lose their account, it is holding it shut. */}
        <span
          aria-hidden="true"
          className="flex size-10 items-center justify-center rounded-control bg-(--color-surface-sunken) text-(--color-ink-muted)"
        >
          <Icon name="lock" size={20} />
        </span>
        <h1 className="text-title font-medium text-(--color-ink)">Unlock</h1>
        <p className="text-body text-(--color-ink-muted)">
          Your conversations are encrypted on this device. The password unlocks them here and
          nowhere else: it is never sent to the server.
        </p>
      </div>

      {refused && <Banner tone="danger">Wrong password.</Banner>}

      {canUseBiometric && (
        <Button
          variant="secondary"
          busy={busy}
          icon={<Icon name="lock" />}
          onClick={() => void unlockByPrompt()}
          className="w-full"
        >
          Unlock with fingerprint or face
        </Button>
      )}

      <form onSubmit={submit} className="flex flex-col gap-gutter">
        <Field label="Password">
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              describedBy={describedBy}
              invalid={invalid}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              autoFocus
            />
          )}
        </Field>
        {/* `busy` rather than swapping the label for "Unlocking…": the derivation takes about a
            second, and a button whose text changes width mid-press moves under the finger. */}
        <Button
          type="submit"
          variant="primary"
          busy={busy}
          disabled={!password}
          className="w-full"
        >
          Unlock
        </Button>
      </form>

      {busy && (
        <p className="text-caption text-(--color-ink-muted)">
          Deriving the key takes about a second and 64 MiB of memory. The slowness is deliberate:
          it costs the same on every attempt by someone who has taken a copy of your data.
        </p>
      )}

      {/* The escape hatch, set apart from the form above it by distance alone. The screen is
          already a `gap-section` column, so this adds one more step on top of it: what follows is
          not another way to unlock, it is what you do when you cannot. A hairline said the same
          thing and drew a line across a screen whose entire job is to look calm. */}
      <div className="flex flex-col gap-snug pt-pane">
        <Button
          variant="quiet"
          size="sm"
          onClick={() => {
            void import("@/lib/session").then(({ Session }) =>
              Session.forget().then(() => window.location.reload()),
            );
          }}
          className="self-start"
        >
          I forgot this password
        </Button>
        <p className="text-caption text-(--color-ink-muted)">
          Forgetting it loses nothing for good: erase this device, then recover the account with
          your twelve-word phrase. Conversations in progress will not follow, though — a device
          already in place will have to add you back.
        </p>
      </div>
    </main>
  );
}

/**
 * Switch for biometric unlocking.
 *
 * # Why it only appears under a lock that is already set
 *
 * Biometrics create no key: they hold the lock's key. Without a lock there is nothing to hold, and
 * a switch that quietly set one would make the readability of your conversations depend on a
 * finger — with no password to fall back on the day the sensor says no.
 *
 * # Why the copy dwells on what you give up
 *
 * The trade is not intuitive: a password is stored nowhere, the key stashed for biometrics is.
 * Convenience is paid for in attack surface, and someone who does not know that will believe they
 * are hardening their security by turning the option on.
 *
 * # Why a switch and not a button
 *
 * The control used to be a link reading "Turn on" / "Turn off", which states the *action* and
 * leaves the reader to infer the current state from it — backwards, and the inference goes wrong
 * about as often as it goes right. A switch states the state and is operated by the same tap.
 *
 * What this does not solve: the switch shows the setting on **this** device only. Biometrics are
 * per-device by construction, and nothing here reveals whether another device has them on.
 */
export function BiometricToggle() {
  const session = useSession();
  const [available, setAvailable] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void Promise.all([biometricAvailable(), biometricEnabled()]).then(([canUse, isOn]) => {
      setAvailable(canUse);
      setEnabled(isOn);
    });
  }, []);

  // Nothing to offer: no block, no explanation. A greyed-out setting on a desktop machine would
  // only advertise a feature that cannot be reached.
  if (!available) return null;

  const toggle = async () => {
    setBusy(true);
    setError(null);
    try {
      if (enabled) {
        await session.disableBiometric();
        setEnabled(false);
      } else {
        await session.enableBiometric();
        setEnabled(true);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // A separate setting inside the panel that removes the lock, and a different subject from the
  // password form above: distance carries the change, as it does everywhere else in this file
  // now — `mt-section` against the form's own `gap-gutter` is the step that says so.
  return (
    <div className="mt-section flex flex-col gap-snug">
      <div className="flex items-start justify-between gap-gutter">
        <div className="min-w-0">
          <h3 className="text-body font-medium text-(--color-ink)">
            Open with fingerprint or face
          </h3>
          <p className="mt-tight text-caption text-(--color-ink-muted)">
            {enabled
              ? "Your lock's key is held by the system, behind its prompt. Your password still works."
              : "Your password is stored nowhere. Turning this on stores your lock's key on this device instead, protected by the system: more convenient, and more exposed if someone extracts the phone's storage."}
          </p>
        </div>
        <Switch
          label="Open with fingerprint or face"
          checked={enabled}
          disabled={busy}
          onCheckedChange={() => void toggle()}
        />
      </div>
      {error && <Banner tone="danger">{error}</Banner>}
    </div>
  );
}

/**
 * Lock settings, from inside the app.
 *
 * The two states are two different panels rather than one panel with a branch in its copy:
 * turning a lock on asks for a new password and judges it, removing one asks for the password
 * already set and destroys a protection. `tone="danger"` marks the second, because the edge is
 * what a reader takes in before the sentence.
 *
 * What this does not solve: it does not confirm the removal. Removing a lock is recoverable —
 * set one again — so a second step would cost every reader something to protect none of them.
 */
export function LockSettings({ onDone }: { onDone: () => void }) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * The verdict, which arrives after the password does.
   *
   * The estimator's dictionaries are behind a dynamic import — see `password.ts` — so the first
   * judgement lands a moment after the first keystroke. A verdict for a password that has since
   * changed must be dropped, otherwise a fast typist gets shown the reason their previous draft
   * was refused.
   */
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const match = password === confirmation;

  useEffect(() => {
    if (!password) {
      setVerdict(null);
      return;
    }

    let current = true;
    // The handle goes in as a known input: a password built out of one's own username is a
    // dictionary word to anyone who has seen the account, and to no generic word list.
    void check(password, [session.handle]).then((judged) => {
      if (current) setVerdict(judged);
    });

    return () => {
      current = false;
    };
  }, [password, session.handle]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (session.locked) {
        await session.disableLock(password);
        report.done("Lock removed");
      } else {
        await session.enableLock(password);
        report.done("Lock turned on");
      }
      // The lock lives on the session, and the rail shows its state: whoever reads the session
      // has to be told it moved. This replaces the `onChanged` the caller used to fire on close,
      // which fired whether or not anything had actually changed.
      bump();
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (session.locked) {
    return (
      <Panel
        tone="danger"
        title="Remove the lock"
        description="Without a lock, your conversations stay encrypted on disk, but anyone who opens this browser can read them."
        actions={<IconButton label="Close" icon={<Icon name="close" />} onClick={onDone} />}
      >
        <form onSubmit={submit} className="flex flex-col gap-gutter">
          <Field
            label="Current password"
            // Every failure here is reported as a wrong password for the same reason as the
            // unlock screen: distinguishing a bad password from unreadable data tells an
            // attacker when they are close.
            error={error === null ? undefined : "Wrong password."}
          >
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                describedBy={describedBy}
                invalid={invalid}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            )}
          </Field>
          <Button
            type="submit"
            variant="destructive"
            busy={busy}
            disabled={!password}
            className="self-start"
          >
            Remove
          </Button>
        </form>

        <BiometricToggle />
      </Panel>
    );
  }

  return (
    <Panel
      title="Lock this device"
      description="Your conversations will be encrypted with this password, which never leaves this device. It is not a recovery method: forgetting it loses nothing, your twelve-word phrase remains the only way back in."
      actions={<IconButton label="Close" icon={<Icon name="close" />} onClick={onDone} />}
    >
      <form onSubmit={submit} className="flex flex-col gap-gutter">
        <Field
          label="New password"
          hint={`${MIN_LENGTH} characters minimum.`}
          error={
            verdict && !verdict.ok ? (
              <>
                {verdict.reason}
                {verdict.advice && <span className="block opacity-80">{verdict.advice}</span>}
              </>
            ) : undefined
          }
        >
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              describedBy={describedBy}
              invalid={invalid}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              required
            />
          )}
        </Field>

        <Field
          label="Confirm password"
          error={confirmation && !match ? "The two entries do not match." : undefined}
        >
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              describedBy={describedBy}
              invalid={invalid}
              type="password"
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              autoComplete="new-password"
              required
            />
          )}
        </Field>

        {password && !verdict && (
          <p className="text-caption text-(--color-ink-muted)">Measuring…</p>
        )}

        {/*
          The number is an order of magnitude of guesses, not a bit count of an alphabet: it is
          what an attacker running published word lists, name lists, dates, keyboard runs and the
          usual letter-for-digit swaps would have to try. It says nothing about someone who knows
          the user — that person's first guesses are not in any list, and the copy has to stop
          short of implying otherwise.
        */}
        {verdict?.ok && verdict.guessesLog10 !== null && (
          <p className="text-caption text-(--color-ink-muted)">
            Around 10^{Math.round(verdict.guessesLog10)} tries for someone working through known
            passwords, words, names and the usual substitutions. Someone who knows you is not
            working through a list, and this number says nothing about them.
          </p>
        )}

        {verdict?.ok && verdict.guessesLog10 === null && (
          <Banner tone="warn">
            The strength checker did not load, so only the length was checked. This password may
            still be one of the ones everybody uses.
          </Banner>
        )}

        {error && <Banner tone="danger">{error}</Banner>}

        <Button
          type="submit"
          variant="primary"
          busy={busy}
          disabled={!verdict?.ok || !match}
          className="self-start"
        >
          Turn on the lock
        </Button>
      </form>
    </Panel>
  );
}
