import { useEffect, useState } from "react";
import { ShowPairingCode, usePairingOffer } from "@/components/Pairing";
import { Session } from "@/lib/session";
import { supportsEd25519 } from "@/lib/keys";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Checkbox } from "@/ui/Checkbox";
import { Field } from "@/ui/Field";
import { Input } from "@/ui/Input";
import { Textarea } from "@/ui/Textarea";
import { cn } from "@/ui/cn";

type Mode = "create" | "restore" | "pair";

/**
 * The three ways in, each stated as what it does rather than as what it is called.
 *
 * A name alone — "Restore" — asks the reader to guess which of the three situations they are in,
 * and the wrong guess here is expensive: a phrase typed on a device that did not need it is a
 * phrase exposed for nothing. So every option carries its sentence, next to the control that
 * commits to it.
 *
 * They are stacked rather than laid side by side because three sentences do not fit across
 * 28rem. The alternative — three bare names with the sentence of the *selected* one underneath —
 * shows the explanation only after the choice it was supposed to inform.
 */
const MODES: { mode: Mode; name: string; what: string }[] = [
  {
    mode: "create",
    name: "Create an account",
    what: "Makes a new identity on this device and shows you its recovery phrase, once.",
  },
  {
    mode: "pair",
    name: "Add this device",
    what: "Joins an account you are still signed in to somewhere else. No phrase to type.",
  },
  {
    mode: "restore",
    name: "Recover an account",
    what: "Rebuilds an account from its twelve words, once every device is gone.",
  },
];

/**
 * The first screen of the product, and the only one rendered before a session exists.
 *
 * # Why this component takes props where the rest of the tree does not
 *
 * `state/SessionProvider.tsx` states the rule: `session` is never passed as a prop, `useSession()`
 * is the only way to reach it. This is the legitimate exception, and it is one because of *when*
 * it renders rather than because of taste. `App.tsx` mounts it precisely when there is no session
 * — it is the branch that runs on `!session` — so it sits **above** the provider. Calling
 * `useSession()` here would throw on the very first render of a fresh install.
 *
 * It is also the component that *produces* the session, so nothing could be handed down to it
 * anyway: `onReady` passes the new session up to the state that will own it. The same reasoning
 * covers `PairThisDevice` and `RecoveryPhrase` below, which are the two continuations of this
 * screen and live on the same side of the provider.
 *
 * What this does not license: a component rendered *under* the provider taking `session` as a
 * prop because it happens to be convenient. The exception is "there is no session yet", and that
 * is true in exactly one place.
 */
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
  const [mode, setMode] = useState<Mode>("create");
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
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-section p-pane">
      {/*
        The one place in the application allowed to use `--text-display`. Its note in `index.css`
        says so — "the first-run headline, once" — and the continuation screens below deliberately
        stay at `--text-title`, so the size keeps meaning "you have arrived" instead of becoming
        the house heading.
      */}
      <h1 className="text-display font-medium text-(--color-ink)">
        {mode === "create" ? "New account" : "Recover my account"}
      </h1>

      {ed25519 === false && (
        <Banner tone="danger" title="This browser cannot create an identity">
          It does not support Ed25519 in WebCrypto. Rather than fall back to a JavaScript
          implementation — where the private key would sit exposed in the script&apos;s memory —
          the app refuses to create an identity. Please use an up-to-date browser.
        </Banner>
      )}

      <ModeChoice mode={mode} onChoose={setMode} />

      <form onSubmit={submit} className="flex flex-col gap-pane">
        <Field
          label="Handle"
          hint="It travels in the clear and is visible to the server and to everyone you talk to. Don't put anything sensitive in it, and above all no phone number and no email address — this system asks for neither."
        >
          {(control) => (
            <Input
              id={control.id}
              describedBy={control.describedBy}
              value={handle}
              onChange={(e) => setHandle(e.target.value)}
              placeholder="alice"
              required
              maxLength={64}
              autoComplete="username"
            />
          )}
        </Field>

        {mode === "restore" && (
          <Field label="Recovery phrase" hint="The twelve words, in order, separated by spaces.">
            {(control) => (
              <Textarea
                id={control.id}
                describedBy={control.describedBy}
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                placeholder="your twelve recovery words"
                required
                rows={3}
                className="font-evidence"
              />
            )}
          </Field>
        )}

        {/*
          `busy` rather than swapping the label for "Working…": the label is what the user reads
          to know what they pressed, and a button whose text changes under a finger is a button
          that appears to have become a different button. Declaring `busy` also reserves the
          spinner's width permanently, so the control does not resize when the wait starts.
        */}
        <Button
          type="submit"
          variant="primary"
          busy={busy}
          disabled={!handle.trim() || ed25519 !== true}
          className="w-full"
        >
          {mode === "create" ? "Create the account" : "Recover the account"}
        </Button>
      </form>

      <p className="text-caption text-(--color-ink-muted)">
        This device will be named automatically after its type. Nothing more precise: an exact
        model would single out its owner far beyond what delivering messages requires.
      </p>

      {mode === "restore" && (
        <p className="text-caption text-(--color-ink-muted)">
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

      {error && <Banner tone="danger" title={error} />}
    </main>
  );
}

/**
 * The three modes, as one segmented control rather than a row of links.
 *
 * `aria-pressed` and not `role="radiogroup"`: a radiogroup owes its user a roving tabindex and
 * arrow-key navigation, and a group that claims the role without them is worse than plain
 * buttons — it announces a keyboard contract it does not honour. Three toggle buttons in a
 * labelled group are a complete, unremarkable pattern, and Tab reaches all three.
 *
 * What it does not solve: `pair` is not really a peer of the other two, since choosing it
 * replaces the whole screen instead of reshaping this form. The control shows it as a peer
 * because that is how the user thinks about it — three ways to end up signed in.
 */
function ModeChoice({ mode, onChoose }: { mode: Mode; onChoose: (mode: Mode) => void }) {
  return (
    <div
      role="group"
      aria-label="How you want to get in"
      // `overflow-hidden` so the filled segment is clipped by the container's corners. It also
      // clips a focus ring drawn outside the element, which is why the ring below is inset.
      className="overflow-hidden rounded-control border border-(--color-border-subtle)"
    >
      {MODES.map((option) => {
        const selected = option.mode === mode;

        return (
          <button
            key={option.mode}
            type="button"
            aria-pressed={selected}
            onClick={() => onChoose(option.mode)}
            className={cn(
              "block w-full border-b border-(--color-border-subtle) px-gutter py-snug text-left last:border-b-0",
              "transition-colors duration-(--duration-quick) ease-out motion-reduce:transition-none",
              "focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-(--color-accent)",
              "touch:min-h-11",
              selected
                ? "bg-(--color-accent) text-(--color-accent-ink)"
                : "bg-(--color-surface-raised) text-(--color-ink) hover:bg-(--color-surface-sunken)",
            )}
          >
            <span className="block text-body font-medium">{option.name}</span>
            <span
              className={cn(
                "mt-tight block text-caption",
                selected ? null : "text-(--color-ink-muted)",
              )}
            >
              {option.what}
            </span>
          </button>
        );
      })}
    </div>
  );
}

/**
 * A new device waiting to be paired.
 *
 * It shows its code and waits. It has no secret to type in: that is the whole point of this
 * direction — the code can be photographed, so it must hold nothing sensitive.
 *
 * Like `Onboarding` above, it renders before any session exists and therefore takes its
 * callbacks as props; see the note there for why that is the one legitimate exception.
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
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-section p-pane">
      <div>
        <h1 className="text-title font-medium text-(--color-ink)">Add this device</h1>
        <p className="mt-snug text-prose text-(--color-ink-muted)">
          Enter the account&apos;s handle, then copy the code shown here onto a device where you
          are already signed in.
        </p>
      </div>

      <Field label="Account handle">
        {(control) => (
          <Input
            id={control.id}
            describedBy={control.describedBy}
            value={handle}
            onChange={(e) => setHandle(e.target.value)}
            placeholder="alice"
            maxLength={64}
            autoComplete="username"
          />
        )}
      </Field>

      <div className="flex flex-col gap-snug">
        <Button
          variant="primary"
          disabled={!handle.trim()}
          onClick={() => setStarted(true)}
          className="w-full"
        >
          Show the pairing code
        </Button>
        <Button variant="quiet" onClick={onCancel} className="w-full">
          Back
        </Button>
      </div>
    </main>
  );
}

/**
 * The one and only time the recovery phrase is shown.
 *
 * It is not kept and cannot be shown again. That is deliberate: a phrase the app can show again
 * is a phrase anyone holding the unlocked device can show again too. So the screen forces an
 * explicit acknowledgement.
 *
 * Rendered before the session is handed over, hence the props; see the note on `Onboarding`.
 */
function RecoveryPhrase({
  phrase,
  onAcknowledged,
}: {
  phrase: string;
  onAcknowledged: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const words = phrase.split(/\s+/);

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-section p-pane">
      <div>
        <h1 className="text-title font-medium text-(--color-ink)">Your recovery phrase</h1>
        <p className="mt-snug text-prose text-(--color-ink-muted)">
          These twelve words are the <strong>only</strong> way to get your account back if you
          lose all your devices. They never leave this device: the server does not know them and
          cannot give them back to you.
        </p>
      </div>

      {/*
        Numbered, fixed-pitch, and selectable as one block — none of which is decoration.
        This phrase gets copied out by hand onto paper: the position of a word is part of it, and
        `--font-evidence` is the family this project embeds precisely so that a human comparing
        characters is not doing it in a proportional face whose l, I and 1 converge.
        `select-all` makes the whole grid one click for whoever is using a password manager
        instead of paper.

        The digits are `select-none` and `aria-hidden`: the `<ol>` already gives a screen reader
        the position, and a copy that carried "1. abandon 2. ability" back into the restore box
        would not restore anything. What that does not solve: excluding `select-none` text from a
        copy is engine behaviour, not a guarantee — the restore side must keep tolerating a
        pasted phrase that arrives dirty.
      */}
      <ol className="grid select-all grid-cols-3 gap-snug rounded-control border border-(--color-border-subtle) bg-(--color-surface-raised) p-pane font-evidence text-body text-(--color-ink)">
        {words.map((word, index) => (
          <li key={`${String(index)}-${word}`} className="flex items-baseline gap-tight">
            <span
              aria-hidden="true"
              className="w-4 shrink-0 select-none text-right tabular-nums text-(--color-ink-muted)"
            >
              {index + 1}
            </span>
            <span>{word}</span>
          </li>
        ))}
      </ol>

      <Banner tone="danger" title="Write them down offline, now.">
        This screen cannot be shown again — not out of excessive caution, but because the app does
        not keep the phrase. Anyone who reads these words owns the account: they are the account.
        {/*
          Said here, not in a settings screen nobody will open: this is the moment those twelve
          words also become the key to the history. Backup is on by default, so the trade-off is
          made now, where the phrase is on screen.
        */}
        <span className="mt-snug block">
          These twelve words also encrypt your saved history. Anyone who gets them can therefore
          read your whole archived past, retroactively included. You can turn that backup off in
          settings.
        </span>
      </Banner>

      <Checkbox
        label="I have written down these twelve words and I understand they cannot be recovered."
        checked={confirmed}
        onChange={(e) => setConfirmed(e.target.checked)}
      />

      <Button
        variant="primary"
        disabled={!confirmed}
        onClick={onAcknowledged}
        className="w-full"
      >
        Continue
      </Button>
    </main>
  );
}
