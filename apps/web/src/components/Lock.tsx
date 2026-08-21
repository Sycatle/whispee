import { useEffect, useState } from "react";
import { MIN_LENGTH, type Verdict, check } from "@/lib/password";
import { biometricEnabled, biometricAvailable } from "@/lib/biometrics";
import type { ProposedMigration, Session } from "@/lib/session";

/** Password prompt at startup, when a lock is set. */
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
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">Unlock</h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          Your conversations are encrypted on this device. The password unlocks them here and
          nowhere else: it is never sent to the server.
        </p>
      </div>

      {canUseBiometric && (
        <button
          type="button"
          onClick={() => void unlockByPrompt()}
          disabled={busy}
          className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50 touch:min-h-11"
        >
          Unlock with fingerprint or face
        </button>
      )}

      <form onSubmit={submit} className="space-y-3">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="password"
          required
          autoFocus
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2"
        />
        <button
          type="submit"
          disabled={busy || !password}
          className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>

      {busy && (
        <p className="text-xs text-(--color-ink-muted)">
          Deriving the key takes about a second and 64 MiB of memory. The slowness is deliberate:
          it costs the same on every attempt by someone who has taken a copy of your data.
        </p>
      )}

      {refused && (
        <p role="alert" className="text-sm text-(--color-danger)">
          Wrong password.
        </p>
      )}

      <button
        type="button"
        onClick={() => {
          void import("@/lib/session").then(({ Session }) =>
            Session.forget().then(() => window.location.reload()),
          );
        }}
        className="text-sm text-(--color-ink-muted) underline"
      >
        I forgot this password
      </button>

      <p className="text-xs text-(--color-ink-muted)">
        Forgetting it loses nothing for good: erase this device, then recover the account with your
        twelve-word phrase. Conversations in progress will not follow, though — a device already in
        place will have to add you back.
      </p>
    </main>
  );
}

/** Lock settings, from inside the app. */
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
 */
function BiometricToggle({ session }: { session: Session }) {
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

  return (
    <div className="mt-4 border-t border-(--color-border-subtle) pt-3">
      <h3 className="font-medium">Open with fingerprint or face</h3>
      <p className="mt-1 text-(--color-ink-muted)">
        {enabled
          ? "Your lock's key is held by the system, behind its prompt. Your password still works."
          : "Your password is stored nowhere. Turning this on stores your lock's key on this device instead, protected by the system: more convenient, and more exposed if someone extracts the phone's storage."}
      </p>
      <button
        type="button"
        onClick={() => void toggle()}
        disabled={busy}
        className="mt-2 underline disabled:opacity-50 touch:min-h-11"
      >
        {busy ? "…" : enabled ? "Turn off" : "Turn on"}
      </button>
      {error && (
        <p role="alert" className="mt-2 text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}

export function LockSettings({ session, onDone }: { session: Session; onDone: () => void }) {
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
      } else {
        await session.enableLock(password);
      }
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (session.locked) {
    return (
      <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="font-medium">Remove the lock</h2>
          <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
            Close
          </button>
        </div>
        <p className="mt-2 text-(--color-ink-muted)">
          Without a lock, your conversations stay encrypted on disk, but anyone who opens this
          browser can read them.
        </p>
        <form onSubmit={submit} className="mt-3 flex gap-2">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="current password"
            required
            className="flex-1 rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1.5"
          />
          <button
            type="submit"
            disabled={busy || !password}
            className="rounded-md bg-(--color-danger) px-3 py-1.5 font-medium text-white disabled:opacity-50"
          >
            {busy ? "…" : "Remove"}
          </button>
        </form>
        {error && (
          <p role="alert" className="mt-2 text-(--color-danger)">
            Wrong password.
          </p>
        )}

        <BiometricToggle session={session} />
      </div>
    );
  }

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Lock this device</h2>
        <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
          Close
        </button>
      </div>

      <p className="mt-2 text-(--color-ink-muted)">
        Your conversations will be encrypted with this password, which never leaves this device. It
        is not a recovery method: forgetting it loses nothing, your twelve-word phrase remains the
        only way back in.
      </p>

      <form onSubmit={submit} className="mt-3 space-y-2">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={`password (${MIN_LENGTH} characters minimum)`}
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1.5"
        />
        <input
          type="password"
          value={confirmation}
          onChange={(e) => setConfirmation(e.target.value)}
          placeholder="confirmation"
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1.5"
        />

        {password && !verdict && <p className="text-xs text-(--color-ink-muted)">Measuring…</p>}

        {verdict && !verdict.ok && (
          <p className="text-(--color-danger)">
            {verdict.reason}
            {verdict.advice && <span className="block opacity-80">{verdict.advice}</span>}
          </p>
        )}

        {/*
          The number is an order of magnitude of guesses, not a bit count of an alphabet: it is
          what an attacker running published word lists, name lists, dates, keyboard runs and the
          usual letter-for-digit swaps would have to try. It says nothing about someone who knows
          the user — that person's first guesses are not in any list, and the copy has to stop
          short of implying otherwise.
        */}
        {verdict?.ok && verdict.guessesLog10 !== null && (
          <p className="text-xs text-(--color-ink-muted)">
            Around 10^{Math.round(verdict.guessesLog10)} tries for someone working through known
            passwords, words, names and the usual substitutions. Someone who knows you is not
            working through a list, and this number says nothing about them.
          </p>
        )}

        {verdict?.ok && verdict.guessesLog10 === null && (
          <p className="text-xs text-(--color-warn)">
            The strength checker did not load, so only the length was checked. This password may
            still be one of the ones everybody uses.
          </p>
        )}
        {confirmation && !match && (
          <p className="text-(--color-danger)">The two entries do not match.</p>
        )}

        <button
          type="submit"
          disabled={busy || !verdict?.ok || !match}
          className="rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Encrypting…" : "Turn on the lock"}
        </button>
      </form>

      {error && (
        <p role="alert" className="mt-2 text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}
