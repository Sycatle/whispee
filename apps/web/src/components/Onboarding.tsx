import { useEffect, useState } from "react";
import { ShowPairingCode, usePairingOffer } from "@/components/Pairing";
import { ApiError } from "@/lib/api";
import {
  MAX_CODE_POINTS as MAX_NAME_LENGTH,
  sanitize as sanitizeName,
  validate as validateName,
} from "@/lib/display-name";
import { MAX_LENGTH as MAX_HANDLE_LENGTH, normalize, suggest, validate } from "@/lib/handle";
import { Session } from "@/lib/session";
import { supportsEd25519 } from "@/lib/keys";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Checkbox } from "@/ui/Checkbox";
import { Field } from "@/ui/Field";
import { Input } from "@/ui/Input";
import { Textarea } from "@/ui/Textarea";
import { cn } from "@/ui/cn";
import { displayNameMessage } from "@/ui/displayNameMessage";
import { handleMessage } from "@/ui/handleMessage";

type Mode = "create" | "restore" | "pair";

/**
 * How many alternatives the screen offers before it stops offering.
 *
 * Three, and the number is about when to stop rather than when to help. A screen that keeps
 * producing names as long as they keep colliding is a slot machine: the person stops reading the
 * suggestions and starts pressing the button, and the handle they end up with is one nobody
 * chose. After three the field is theirs again — the collision message stays, and the next move
 * is a name they thought of.
 */
const MAX_SUGGESTIONS = 3;

/**
 * Four random digits, drawn from the CSPRNG rather than from `Math.random`.
 *
 * `lib/handle.ts` explains why the suggestion must not be a counter: `charlie2` would tell its
 * reader that `charlie1` exists. This is the other half — `Math.random` is seeded per context,
 * so two tabs opened at the same moment would propose the same name and turn a
 * collision-avoidance mechanism into a collision generator.
 */
function draw(): number {
  const bits = new Uint32Array(1);
  crypto.getRandomValues(bits);
  return bits[0] / 2 ** 32;
}

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
  /**
   * The name somebody gives when they sign up, and the thing the account is actually *about*.
   *
   * # Why the first question is a name and not a handle
   *
   * A handle has to be unique, which makes it the worst possible first question: it asks a person
   * to invent an identifier before they have any idea which ones are free, and it answers them
   * with a collision. A name has no such constraint — every Bob may be Bob — so the field can be
   * answered the way its label is read.
   *
   * The handle is then drawn from it, and drawn is the operative word: see `derived` below.
   */
  const [name, setName] = useState("");
  /**
   * The four digits, held as the seed that produced them rather than as the digits.
   *
   * `suggest` draws its own randomness, which is right for its usual caller and wrong here: the
   * handle is recomputed on **every keystroke of the name**, and a function that redrew each time
   * would spin four digits under the reader's eyes while they typed. Freezing the seed and
   * passing it back in makes the same function pure for the duration of the form — the stem
   * follows the name, the digits stay put — and redrawing is then an explicit act, which is
   * exactly what a collision is.
   */
  const [seed, setSeed] = useState(draw);
  /**
   * Whether the reader has taken the handle over.
   *
   * It decides more than which value is submitted. A drawn handle that collides is redrawn and
   * resubmitted without a word, because nobody asked for that one; a chosen handle that collides
   * is reported, because somebody did. Same status code, two different events.
   */
  const [custom, setCustom] = useState(false);
  const [phrase, setPhrase] = useState("");
  const [mode, setMode] = useState<Mode>("create");
  const [busy, setBusy] = useState(false);
  const [ed25519, setEd25519] = useState<boolean | null>(null);
  /** The phrase produced at creation. Shown once, never shown again afterwards. */
  const [recovery, setRecovery] = useState<{ phrase: string; session: Session } | null>(null);
  /** An alternative offered after a collision, and how many have been offered so far. */
  const [alternative, setAlternative] = useState<string | null>(null);
  const [offered, setOffered] = useState(0);

  useEffect(() => {
    void supportsEd25519().then(setEd25519);
  }, []);

  // The field keeps whatever was typed and the canonical form is derived, rather than the field
  // rewriting itself on every keystroke. A field that silently drops the character just typed is
  // a field that appears broken, and the person never learns which characters this system takes.
  const canonical = normalize(handle);
  // Nothing is red before anything is typed: an empty required field is not a mistake, it is a
  // field waiting its turn.
  const problem = handle === "" ? null : validate(canonical);

  const cleanName = sanitizeName(name);
  const nameProblem = name === "" ? null : validateName(cleanName);

  /**
   * The handle a name will claim: its stem, then the four digits.
   *
   * **Always the digits, never the bare stem.** Trying `bob` first would give the first Bob a
   * clean handle and charge every Bob after them a round trip to find out — and that round trip
   * comes back 409, which `lib/handle.ts` spends a section explaining is a population count
   * published to anybody who asks. Digits from the start cost one query nobody makes and put
   * every Bob on the same footing.
   *
   * A name with no ASCII stem — `李`, an emoji, a script this alphabet cannot hold — normalises
   * to nothing and leaves the digits alone. `@4821` is a valid handle and an ugly one, and the
   * answer to it is the field below rather than a word invented on that person's behalf.
   */
  const derived = suggest(cleanName, () => seed);

  /** What will actually be claimed: theirs if they took it, the drawn one otherwise. */
  const chosen = mode === "create" ? (custom ? canonical : derived) : canonical;
  const chosenProblem = mode === "create" && !custom ? validate(derived) : problem;

  /**
   * Claims a handle, and retries on its own only when the handle was drawn.
   *
   * `attempt` is a parameter and not the `offered` state, and that is not a stylistic choice: a
   * recursive call reads the state its closure captured, so `offered` would be zero on every
   * retry and a handle that collided persistently would be retried until the tab died. The state
   * still exists for what it is good at — telling the *render* how many alternatives have been
   * shown — and the loop counts on the stack, where a loop's counter belongs.
   */
  const enrol = async (claiming: string, attempt = 0) => {
    setBusy(true);
    setAlternative(null);
    try {
      if (mode === "create") {
        const [session, generated] = await Session.create(claiming);
        /*
          The name is set before the session is handed over, and it is worth being explicit that
          this can fail on its own. `setDisplayName` publishes to every conversation the account
          is in — none, at this instant — so there is nothing to fail against; but it also writes
          to storage, and a rejected write here would leave an account with no name.

          It is deliberately **not** awaited inside the `try` that owns the 409 handling below:
          a failure to record a name is not a collision, and reporting it as one would offer an
          alternative handle to somebody whose handle was accepted.
        */
        await session.setDisplayName(cleanName);
        // The session is not handed over yet: the user has to see the phrase first. Going
        // straight to the conversation would lose it for good.
        setRecovery({ phrase: generated, session });
      } else {
        onReady(await Session.restoreFromPhrase(claiming, phrase));
      }
    } catch (e) {
      // A 409 here means the handle belongs to a different account key, and only in creation.
      //
      // Not to be confused with the reinstall case: claiming a handle again **with the same
      // key** is idempotent and comes back 200 — that is `routes::create_account`, and it is how
      // a device that lost its storage gets its account back. `Session.create` generates a fresh
      // account key every time, so a 409 on this path is never a reinstall, it is somebody
      // else's name. Recovery goes through `restoreFromPhrase`, which registers a device and
      // never touches this route, so its 409s are about device ids and get no suggestion.
      //
      // Using the 409 as the collision signal creates no leak. The status is already returned by
      // an open, unauthenticated route and has been since `create_account` was written: anyone
      // can enumerate taken handles with a POST and a throwaway key, with or without this
      // screen. That oracle is real and it is **not** fixed here — fixing it means proof of work
      // or an authenticated creation path, which is a change to the account model rather than to
      // a form. What this code does is read a signal that already exists.
      const collision = mode === "create" && e instanceof ApiError && e.status === 409;

      /*
        A drawn handle that collides is redrawn and tried again, in silence.

        Nobody chose `@bob4821`, so being told it is taken is news about a decision the reader was
        never party to — and the repair is the one this code can make on its own. Four digits
        collide about once in ten thousand names, so this is a branch that almost never runs and
        the loop still has to terminate: `MAX_SUGGESTIONS` is the same ceiling the manual path
        uses, and past it the failure is reported like any other rather than retried forever.

        A handle they typed is a different event. It is reported, with an alternative offered, and
        the field stays theirs — which is the behaviour this screen has always had.
      */
      if (collision && !custom && attempt < MAX_SUGGESTIONS) {
        const next = draw();
        setSeed(next);
        setBusy(false);
        await enrol(suggest(cleanName, () => next), attempt + 1);
        return;
      }

      if (collision && custom && offered < MAX_SUGGESTIONS) {
        setAlternative(suggest(claiming, draw));
        setOffered(offered + 1);
      }
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    await enrol(chosen);
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
        {mode === "create" && (
          <>
            <Field
              label="Your name"
              hint="What people see next to your messages. It is not unique — several people may go by the same name — and it never reaches the server: it travels inside the encrypted conversation. You can change it whenever you like."
              error={displayNameMessage(nameProblem)}
            >
              {(control) => (
                <Input
                  id={control.id}
                  describedBy={control.describedBy}
                  invalid={control.invalid}
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Bob"
                  required
                  autoComplete="nickname"
                  // Twice the display cap, like the settings panel and for its reason: the field
                  // must accept a paste that is too long so the reader sees *why* it is refused.
                  maxLength={MAX_NAME_LENGTH * 2}
                />
              )}
            </Field>

            {/*
              The handle the name will claim, shown before it is claimed and not after.

              It is the one thing on this screen that cannot be changed later — it is the account
              — so it is on screen while the decision is still open, rather than discovered on the
              first message. Shown as a fact rather than as a field, because it is answered
              already; the button is there for the minority who care which one they get.
            */}
            {!custom && (
              <div className="flex items-center justify-between gap-gutter rounded-control border border-(--color-border-subtle) bg-(--color-surface-raised) p-gutter">
                <p className="min-w-0 text-caption text-(--color-ink-muted)">
                  You will be{" "}
                  <span className="font-evidence wrap-anywhere text-(--color-ink)">
                    @{derived}
                  </span>
                  . This is what identifies you, and it cannot be changed afterwards.
                </p>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setCustom(true);
                    setHandle(derived);
                  }}
                >
                  Change
                </Button>
              </div>
            )}
          </>
        )}

        {(mode !== "create" || custom) && (
        <Field
          label="Handle"
          hint="Lowercase letters, digits and underscores, 3 to 32 characters. It travels in the clear and is visible to the server and to everyone you talk to. Don't put anything sensitive in it, and above all no phone number and no email address — this system asks for neither."
          error={problem === null ? undefined : handleMessage(problem)}
        >
          {(control) => (
            <Input
              id={control.id}
              describedBy={control.describedBy}
              invalid={control.invalid}
              value={handle}
              onChange={(e) => {
                setHandle(e.target.value);
                // A suggestion is about the handle that collided. Once the field says something
                // else it is an answer to a question nobody is asking any more.
                setAlternative(null);
              }}
              placeholder="alice"
              required
              // The format's own ceiling, not a round number. The field used to stop at 64,
              // which let someone type thirty characters that could never be accepted before
              // anything told them so.
              maxLength={MAX_HANDLE_LENGTH}
              autoComplete="username"
            />
          )}
        </Field>
        )}

        {/*
          The alternative offered after a collision, adopted in one press.

          A suggestion the user has to retype is not a suggestion, it is a hint — and a hint that
          costs thirty keystrokes will be ignored in favour of adding a digit by hand, which is
          the counter this whole mechanism exists to avoid.
        */}
        {mode === "create" && alternative !== null && (
          <div className="flex flex-col gap-snug rounded-control border border-(--color-border-subtle) bg-(--color-surface-raised) p-gutter">
            <p className="text-caption text-(--color-ink-muted)">
              That handle is taken. <span className="font-evidence text-(--color-ink)">@{alternative}</span> is
              free to try.
            </p>
            <Button
              type="button"
              variant="secondary"
              busy={busy}
              onClick={() => {
                setHandle(alternative);
                void enrol(alternative);
              }}
            >
              Use @{alternative}
            </Button>
          </div>
        )}

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

          Disabled on the format and not only on emptiness. The server would refuse a malformed
          handle with a 400, and letting the press through would spend a round trip to say what
          the field already knows — and say it as a banner at the bottom of the screen rather
          than under the control that caused it.
        */}
        <Button
          type="submit"
          variant="primary"
          busy={busy}
          disabled={
            chosenProblem !== null ||
            chosen === "" ||
            (mode === "create" && validateName(cleanName) !== null) ||
            ed25519 !== true
          }
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
 *
 * # This one keeps its hairlines, against the rule everywhere else
 *
 * Section boundaries elsewhere in the client have given up their `border-b` for space, because a
 * rule between two blocks that merely follow one another is a line drawn where nothing happens.
 * This is not that case, and the distinction is worth stating so the next pass does not
 * "finish the job" here.
 *
 * These three are rows of one control, not sections of a page. They share a border box, they are
 * flush against each other by design — the segments have to touch, or they stop reading as one
 * choice with three positions and start reading as three separate buttons — and the only thing
 * marking where one option's two lines end and the next one's begin is the rule between them.
 * Take it away and the group becomes six lines of text in a box, with the reader counting to
 * work out which caption belongs to which name.
 *
 * So: a rule between two blocks of different natures is noise; a rule between two rows of the
 * same nature in a dense list is doing work. `last:border-b-0` keeps the final row from drawing
 * a second line on top of the container's own edge.
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

  // Same derivation as the creation form above, and it has to be the same: this field names an
  // account that already exists, so a handle shaped differently from the one that was created
  // matches nothing. The two fields used to disagree — this one had no validation at all — and
  // the failure that produced was a pairing code shown, scanned, and then a registration
  // refused for a reason that appeared nowhere near the field that caused it.
  const canonical = normalize(handle);
  const problem = handle === "" ? null : validate(canonical);

  useEffect(() => {
    if (!seed) return;
    Session.fromSeed(canonical, seed)
      .then(onReady)
      .catch((e: unknown) => onError(e instanceof Error ? e.message : String(e)));
  }, [seed, canonical, onReady, onError]);

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

      <Field
        label="Account handle"
        error={problem === null ? undefined : handleMessage(problem)}
      >
        {(control) => (
          <Input
            id={control.id}
            describedBy={control.describedBy}
            invalid={control.invalid}
            value={handle}
            onChange={(e) => setHandle(e.target.value)}
            placeholder="alice"
            maxLength={MAX_HANDLE_LENGTH}
            autoComplete="username"
          />
        )}
      </Field>

      <div className="flex flex-col gap-snug">
        <Button
          variant="primary"
          disabled={validate(canonical) !== null}
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
