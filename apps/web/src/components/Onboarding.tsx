import { useEffect, useState } from "react";
import { ShowPairingCode, usePairingOffer } from "@/components/Pairing";
import { Session } from "@/lib/session";
import { supportsEd25519 } from "@/lib/keys";

export function Onboarding({
  onReady,
  onError,
  error,
}: {
  onReady: (session: Session) => void;
  onError: (message: string) => void;
  error: string | null;
}) {
  const [handle, setHandle] = useState("");
  const [phrase, setPhrase] = useState("");
  const [mode, setMode] = useState<"create" | "restore" | "pair">("create");
  const [busy, setBusy] = useState(false);
  const [ed25519, setEd25519] = useState<boolean | null>(null);
  /** The phrase produced at creation. Shown once, never shown again afterwards. */
  const [recovery, setRecovery] = useState<{ phrase: string; session: Session } | null>(null);

  useEffect(() => {
    void supportsEd25519().then(setEd25519);
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      if (mode === "create") {
        const [session, generated] = await Session.create(handle.trim());
        // The session is not handed over yet: the user has to see the phrase first. Going
        // straight to the conversation would lose it for good.
        setRecovery({ phrase: generated, session });
      } else {
        onReady(await Session.restoreFromPhrase(handle.trim(), phrase));
      }
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (recovery) {
    return <RecoveryPhrase phrase={recovery.phrase} onAcknowledged={() => onReady(recovery.session)} />;
  }

  if (mode === "pair") {
    return <PairThisDevice onReady={onReady} onError={onError} onCancel={() => setMode("create")} />;
  }

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">
          {mode === "create" ? "New account" : "Recover my account"}
        </h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          Your handle travels in the clear and is visible to the server and to everyone you talk
          to. Don&apos;t put anything sensitive in it, and above all no phone number and no email
          address — this system asks for neither.
        </p>
        <p className="mt-2 text-xs text-(--color-ink-muted)">
          This device will be named automatically after its type. Nothing more precise: an exact
          model would single out its owner far beyond what delivering messages requires.
        </p>
      </div>

      {ed25519 === false && (
        <p role="alert" className="rounded-md border border-(--color-danger) bg-(--color-danger)/10 p-3 text-sm text-(--color-danger)">
          This browser does not support Ed25519 in WebCrypto. Rather than fall back to a
          JavaScript implementation — where the private key would sit exposed in the script&apos;s
          memory — the app refuses to create an identity. Please use an up-to-date browser.
        </p>
      )}

      <form onSubmit={submit} className="space-y-3">
        <input
          value={handle}
          onChange={(e) => setHandle(e.target.value)}
          placeholder="handle (alice)"
          required
          maxLength={64}
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2"
        />
        {mode === "restore" && (
          <textarea
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            placeholder="your twelve recovery words"
            required
            rows={3}
            className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2 text-sm"
          />
        )}

        <button
          type="submit"
          disabled={busy || !handle.trim() || ed25519 !== true}
          className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Working…" : mode === "create" ? "Create the account" : "Recover the account"}
        </button>
      </form>

      <div className="flex flex-col gap-2 text-sm text-(--color-ink-muted)">
        {mode === "create" ? (
          <>
            <button type="button" onClick={() => setMode("pair")} className="underline">
              Add this device to an existing account
            </button>
            <button type="button" onClick={() => setMode("restore")} className="underline">
              I lost all my devices — recover with my phrase
            </button>
          </>
        ) : (
          <button type="button" onClick={() => setMode("create")} className="underline">
            Create a new account
          </button>
        )}
      </div>

      {mode === "restore" && (
        <p className="text-xs text-(--color-ink-muted)">
          Only use this if you have lost every one of your devices. To add a new device while you
          still have one at hand, do it from that one: your phrase then has no reason to be typed
          in again, so no reason to be exposed.
          <br />
          You will get your account back, but not your ongoing conversations: they live in
          encrypted groups that this new device is not a member of. Your saved history does still
          exist, and your phrase opens it — but until someone adds you back to the conversation,
          this device doesn&apos;t even know that history exists and cannot go and fetch it.
        </p>
      )}

      {error && (
        <p role="alert" className="text-sm text-(--color-danger)">
          {error}
        </p>
      )}
    </main>
  );
}

/**
 * A new device waiting to be paired.
 *
 * It shows its code and waits. It has no secret to type in: that is the whole point of this
 * direction — the code can be photographed, so it must hold nothing sensitive.
 */
function PairThisDevice({
  onReady,
  onError,
  onCancel,
}: {
  onReady: (session: Session) => void;
  onError: (message: string) => void;
  onCancel: () => void;
}) {
  const [handle, setHandle] = useState("");
  const [started, setStarted] = useState(false);
  const { code, seed, confirmation, error } = usePairingOffer(started);

  useEffect(() => {
    if (!seed) return;
    Session.fromSeed(handle.trim(), seed)
      .then(onReady)
      .catch((e: unknown) => onError(e instanceof Error ? e.message : String(e)));
  }, [seed, handle, onReady, onError]);

  useEffect(() => {
    if (error) onError(error);
  }, [error, onError]);

  if (started && code) {
    return <ShowPairingCode code={code} confirmation={confirmation} onCancel={onCancel} />;
  }

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">Add this device</h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          Enter the account&apos;s handle, then copy the code shown here onto a device where you
          are already signed in.
        </p>
      </div>

      <input
        value={handle}
        onChange={(e) => setHandle(e.target.value)}
        placeholder="account handle"
        maxLength={64}
        className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2"
      />

      <button
        type="button"
        disabled={!handle.trim()}
        onClick={() => setStarted(true)}
        className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50"
      >
        Show the pairing code
      </button>

      <button type="button" onClick={onCancel} className="text-sm text-(--color-ink-muted) underline">
        Back
      </button>
    </main>
  );
}

/**
 * The one and only time the recovery phrase is shown.
 *
 * It is not kept and cannot be shown again. That is deliberate: a phrase the app can show again
 * is a phrase anyone holding the unlocked device can show again too. So the screen forces an
 * explicit acknowledgement.
 */
function RecoveryPhrase({
  phrase,
  onAcknowledged,
}: {
  phrase: string;
  onAcknowledged: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">Your recovery phrase</h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          These twelve words are the <strong>only</strong> way to get your account back if you
          lose all your devices. They never leave this device: the server does not know them and
          cannot give them back to you.
        </p>
      </div>

      <ol className="grid grid-cols-3 gap-2 rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) p-4 font-mono text-sm">
        {phrase.split(/\s+/).map((word, index) => (
          <li key={word + String(index)} className="tabular-nums">
            <span className="text-(--color-ink-muted)">{index + 1}.</span> {word}
          </li>
        ))}
      </ol>

      <p className="text-sm text-(--color-danger)">
        Write them down offline. This screen cannot be shown again — not out of excessive caution,
        but because the app does not keep the phrase.
      </p>

      {/*
        Said here, not in a settings screen nobody will open: this is the moment those twelve
        words also become the key to the history. Backup is on by default, so the trade-off is
        made now, where the phrase is on screen.
      */}
      <p className="text-sm text-(--color-ink-muted)">
        These twelve words also encrypt your saved history. Anyone who gets them can therefore
        read your whole archived past, retroactively included. You can turn that backup off in
        settings.
      </p>

      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          className="mt-1"
        />
        <span>I have written down these twelve words and I understand they cannot be recovered.</span>
      </label>

      <button
        type="button"
        disabled={!confirmed}
        onClick={onAcknowledged}
        className="w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50"
      >
        Continue
      </button>
    </main>
  );
}
