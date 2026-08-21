import { useEffect, useRef, useState } from "react";
import type { Session } from "@/lib/session";
import { QrCode } from "@/components/QrCode";
import { scanAvailable, scan } from "@/lib/scanner";

/**
 * Adding a device, from the side of the **already authenticated** device.
 *
 * This is where the addition belongs, not on the welcome screen: as long as you are holding a
 * device, there is no reason to type the recovery phrase again — so no reason to expose it a
 * second time.
 */
export function PairDevice({ session, onDone }: { session: Session; onDone: () => void }) {
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
      <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
        <h2 className="font-medium">Confirmation code</h2>
        <p className="mt-2 text-(--color-ink-muted)">
          This code must be identical on both screens. If it differs, stop: the device you are
          pairing is not the one you think it is.
        </p>
        <p className="mt-3 font-mono text-2xl tracking-widest">{confirmation}</p>
        <p className="mt-3 text-xs text-(--color-ink-muted)">
          The new device joins your ongoing conversations within seconds.
        </p>
        <button
          type="button"
          onClick={onDone}
          className="mt-4 rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white"
        >
          Done
        </button>
      </div>
    );
  }

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Add a device</h2>
        <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
          Close
        </button>
      </div>

      <p className="mt-2 text-(--color-ink-muted)">
        On the new device, choose &ldquo;Add this device to an account&rdquo;, then scan its square
        or copy its code here. This code holds no secret: it is only an ephemeral public key,
        useless to anyone who intercepts it.
      </p>

      <p className="mt-2 text-xs text-(--color-ink-muted)">
        Only scan the screen you are holding: that is the one thing telling your device apart from
        a stranger&apos;s. Both screens will then show the same confirmation code — if they differ,
        stop.
      </p>

      {camera && (
        <div className="mt-3">
          {/* `playsInline`, without which iOS opens the video full screen, covering the panel and
              making it look like the app changed screens. */}
          <video
            ref={video}
            playsInline
            muted
            className="w-full rounded-md border border-(--color-border-subtle)"
          />
          <button
            type="button"
            onClick={() => {
              stopCamera.current?.();
              setCamera(false);
            }}
            className="mt-2 text-(--color-ink-muted) underline touch:min-h-11"
          >
            Stop the camera
          </button>
        </div>
      )}

      {!camera && scanAvailable() && (
        <button
          type="button"
          onClick={() => void readTheSquare()}
          disabled={busy}
          className="mt-3 w-full rounded-md bg-(--color-accent) px-3 py-2 font-medium text-white disabled:opacity-50 touch:min-h-11"
        >
          Scan the square
        </button>
      )}

      <form onSubmit={submit} className="mt-3 space-y-2">
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="code shown by the new device"
          rows={2}
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1.5 font-mono text-xs"
        />
        <button
          type="submit"
          disabled={busy || !code.trim()}
          className="rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Sending…" : "Pair"}
        </button>
      </form>

      {error && (
        <p role="alert" className="mt-3 text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}

/**
 * The **new** device's screen: it displays, it never types anything in.
 *
 * This direction is mandatory. A displayed code can be photographed, so it must hold no secret.
 * The original device is the one that seals and sends, and only that way round.
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
  const [copied, setCopied] = useState(false);

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-6 p-6">
      <div>
        <h1 className="text-xl font-medium">Add this device</h1>
        <p className="mt-2 text-sm text-(--color-ink-muted)">
          On a device where you are already signed in, open &ldquo;Add a device&rdquo; and scan
          this square — or copy the code below. It holds no secret: your recovery phrase stays
          where it is, and does not have to be typed again.
        </p>
      </div>

      <div className="flex justify-center">
        <QrCode value={code} />
      </div>

      <div className="space-y-2">
        {/* The text stays, under the square: not every platform can scan, and a desktop computer
            often has no camera pointed at the other screen. */}
        <p className="break-all rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) p-4 font-mono text-xs">
          {code}
        </p>
        <button
          type="button"
          onClick={() => {
            void navigator.clipboard.writeText(code).then(() => setCopied(true));
          }}
          className="text-sm text-(--color-ink-muted) underline"
        >
          {copied ? "Copied" : "Copy the code"}
        </button>
      </div>

      {confirmation ? (
        <div>
          <p className="text-sm">Confirmation code:</p>
          <p className="mt-1 font-mono text-2xl tracking-widest">{confirmation}</p>
          <p className="mt-2 text-xs text-(--color-ink-muted)">
            It must be identical on both screens.
          </p>
        </div>
      ) : (
        <p className="text-sm text-(--color-ink-muted)">Waiting for the other device…</p>
      )}

      <button type="button" onClick={onCancel} className="text-sm text-(--color-ink-muted) underline">
        Cancel
      </button>
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
