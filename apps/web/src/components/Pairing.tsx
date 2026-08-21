import { useEffect, useRef, useState } from "react";
import { QrCode } from "@/components/QrCode";
import { scanAvailable, scan } from "@/lib/scanner";
import { useSession } from "@/state/SessionProvider";
import { useReport } from "@/state/report";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Field } from "@/ui/Field";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Panel } from "@/ui/Panel";
import { Textarea } from "@/ui/Textarea";

/**
 * Adding a device, from the side of the **already authenticated** device.
 *
 * This is where the addition belongs, not on the welcome screen: as long as you are holding a
 * device, there is no reason to type the recovery phrase again — so no reason to expose it a
 * second time.
 */
export function PairDevice({ onDone }: { onDone: () => void }) {
  const session = useSession();
  const [code, setCode] = useState("");
  const [confirmation, setConfirmation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [camera, setCamera] = useState(false);
  const video = useRef<HTMLVideoElement>(null);
  const stopCamera = useRef<(() => void) | null>(null);

  // The camera must go off on unmount, including if the panel closes mid-scan. A green light
  // still on afterwards is unsettling at best and a leak at worst.
  useEffect(() => () => stopCamera.current?.(), []);

  /**
   * Scan, then pair straight away.
   *
   * No intermediate confirmation step: the code read is not an intention to approve, it is the
   * same data you would have typed by hand. Verification comes right after — the confirmation
   * code shown on both sides, which is the only check that counts.
   */
  const readTheSquare = async () => {
    setError(null);
    setCamera(true);
    try {
      if (!video.current) return;

      const { read, stop } = await scan(video.current);
      stopCamera.current = stop;

      const scanned = await read;
      setCode(scanned);
      setCamera(false);
      setBusy(true);
      setConfirmation(await session.pairDevice(scanned.trim()));
    } catch (e) {
      // A refused camera is not a failure: the text field is still there, and it is enough.
      setError(
        e instanceof Error && e.name === "NotAllowedError"
          ? "Camera denied. Copy the code shown on the other device instead."
          : e instanceof Error
            ? e.message
            : String(e),
      );
      setCamera(false);
    } finally {
      stopCamera.current = null;
      setBusy(false);
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setConfirmation(await session.pairDevice(code.trim()));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (confirmation) {
    return (
      <Panel
        title="Confirmation code"
        description="This code must be identical on both screens. If it differs, stop: the device you are pairing is not the one you think it is."
        // "Done" here has exactly one effect — it closes this panel — so it becomes a glyph by
        // the rule at the top of `ui/IconButton.tsx`: frequent, reversible, and a tick is the one
        // picture nobody has to be taught. The accessible name stays "Done", because that is
        // what the reader is agreeing to: the two codes matched.
        //
        // A tick and not a cross. It closes the panel either way, so the cross was defensible on
        // effect — and it read as dismissal to the eye while announcing an affirmation to a
        // screen reader, which is two different messages about the same button. `confirm` exists
        // for exactly this: the gesture here is agreement, not escape.
        actions={
          <IconButton
            label="Done"
            variant="primary"
            icon={<Icon name="confirm" />}
            onClick={onDone}
          />
        }
      >
        {/* The one string on this screen a human is asked to compare character by character, so
            it is set in `--font-evidence` and spaced out. Wide tracking is not decoration here:
            it stops two adjacent characters from being read as one. */}
        <output className="block font-(--font-evidence) text-title tracking-widest text-(--color-ink)">
          {confirmation}
        </output>
        <p className="mt-gutter text-caption text-(--color-ink-muted)">
          The new device joins your ongoing conversations within seconds.
        </p>
      </Panel>
    );
  }

  return (
    <Panel
      title="Add a device"
      description="On the new device, choose “Add this device to an account”, then scan its square or copy its code here. This code holds no secret: it is only an ephemeral public key, useless to anyone who intercepts it."
      actions={<IconButton label="Close" icon={<Icon name="close" />} onClick={onDone} />}
    >
      <p className="text-caption text-(--color-ink-muted)">
        Only scan the screen you are holding: that is the one thing telling your device apart from
        a stranger&apos;s. Both screens will then show the same confirmation code — if they differ,
        stop.
      </p>

      {camera && (
        <div className="mt-gutter flex flex-col gap-snug">
          {/* `playsInline`, without which iOS opens the video full screen, covering the panel and
              making it look like the app changed screens. */}
          <video
            ref={video}
            playsInline
            muted
            className="w-full rounded-control border border-(--color-border-subtle)"
          />
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              stopCamera.current?.();
              setCamera(false);
            }}
            className="self-start"
          >
            Stop the camera
          </Button>
        </div>
      )}

      {!camera && scanAvailable() && (
        <Button
          variant="primary"
          icon={<Icon name="pair" />}
          busy={busy}
          onClick={() => void readTheSquare()}
          className="mt-gutter w-full"
        >
          Scan the square
        </Button>
      )}

      <form onSubmit={submit} className="mt-gutter flex flex-col gap-gutter">
        <Field
          label="Code shown by the new device"
          hint="Paste it as it appears, in full."
        >
          {({ id, describedBy, invalid }) => (
            <Textarea
              id={id}
              describedBy={describedBy}
              invalid={invalid}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              rows={2}
              required
              className="font-(--font-evidence) text-body"
            />
          )}
        </Field>
        <Button
          type="submit"
          variant="primary"
          busy={busy}
          disabled={!code.trim()}
          className="self-start"
        >
          Pair
        </Button>
      </form>

      {error && (
        <div className="mt-gutter">
          <Banner tone="danger">{error}</Banner>
        </div>
      )}
    </Panel>
  );
}

/**
 * The **new** device's screen: it displays, it never types anything in.
 *
 * This direction is mandatory. A displayed code can be photographed, so it must hold no secret.
 * The original device is the one that seals and sends, and only that way round.
 *
 * # Why this one keeps its props
 *
 * `code` and `confirmation` are not session state, they are the output of `usePairingOffer`
 * running in the caller — on a device that has no session yet, which is the entire point of the
 * screen. There is nothing here for `useSession()` to read.
 */
export function ShowPairingCode({
  code,
  confirmation,
  onCancel,
}: {
  code: string;
  confirmation: string | null;
  onCancel: () => void;
}) {
  const report = useReport();

  return (
    <main className="safe-top safe-bottom safe-sides mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-section p-pane">
      <div className="flex flex-col gap-snug">
        <h1 className="text-title font-medium text-(--color-ink)">Add this device</h1>
        <p className="text-body text-(--color-ink-muted)">
          On a device where you are already signed in, open &ldquo;Add a device&rdquo; and scan
          this square — or copy the code below. It holds no secret: your recovery phrase stays
          where it is, and does not have to be typed again.
        </p>
      </div>

      <div className="flex justify-center">
        <QrCode value={code} />
      </div>

      <div className="flex flex-col gap-snug">
        {/* The text stays, under the square: not every platform can scan, and a desktop computer
            often has no camera pointed at the other screen. */}
        {/* Sunken, not raised: the panel around it is now `--color-surface-raised` itself, so the
            code block was about to become an outline with no fill of its own. A block of evidence
            set into the panel reads as a thing to copy out, which is what it is — and it matches
            the recovery phrase in `Devices.tsx`, which is the same kind of block. */}
        <p className="break-all rounded-control border border-(--color-border-subtle) bg-(--color-surface-sunken) p-gutter font-(--font-evidence) text-caption text-(--color-ink)">
          {code}
        </p>
        {/*
          The success used to be a `copied` flag that turned this label into "Copied" and never
          turned back, which said nothing on a second copy and nothing at all to a screen reader.
          The toast is announced, it expires, and it is the same acknowledgement every other
          action in the application gives.

          What this does not solve: a clipboard write that is refused still says nothing. The
          promise rejects and no report is made — the code is on screen to be typed either way.
        */}
        <Button
          variant="secondary"
          size="sm"
          icon={<Icon name="copy" />}
          onClick={() => {
            void navigator.clipboard
              .writeText(code)
              .then(() => report.done("Pairing code copied"));
          }}
          className="self-start"
        >
          Copy the code
        </Button>
      </div>

      {confirmation ? (
        <div>
          <p className="text-body text-(--color-ink)">Confirmation code:</p>
          <output className="mt-tight block font-(--font-evidence) text-title tracking-widest text-(--color-ink)">
            {confirmation}
          </output>
          <p className="mt-snug text-caption text-(--color-ink-muted)">
            It must be identical on both screens.
          </p>
        </div>
      ) : (
        <p className="text-body text-(--color-ink-muted)">Waiting for the other device…</p>
      )}

      <Button variant="quiet" size="sm" onClick={onCancel} className="self-start">
        Cancel
      </Button>
    </main>
  );
}

/** Generates the offer and waits for the packet. In a hook: the loop must stop on unmount. */
export function usePairingOffer(enabled: boolean) {
  const [code, setCode] = useState<string | null>(null);
  const [seed, setSeed] = useState<Uint8Array | null>(null);
  const [confirmation, setConfirmation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const cancel = useRef({ cancelled: false });

  useEffect(() => {
    if (!enabled) return;
    const signal = { cancelled: false };
    cancel.current = signal;

    void (async () => {
      const { loadCrypto } = await import("@/lib/wasm");
      const { encodePairingCode, awaitPairing } = await import("@/lib/pairing");
      const crypto = await loadCrypto();

      const offer = new crypto.Pairing();
      const id = offer.id();
      setCode(encodePairingCode({ id, publicKey: offer.publicKey() }));

      try {
        const sealed = await awaitPairing(id, signal);
        if (!sealed || signal.cancelled) return;

        const opened = offer.open(sealed) as { plaintext: Uint8Array; confirmation: string };
        setConfirmation(opened.confirmation);
        setSeed(opened.plaintext);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();

    return () => {
      signal.cancelled = true;
    };
  }, [enabled]);

  return { code, seed, confirmation, error };
}
