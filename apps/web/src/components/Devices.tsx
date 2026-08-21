import { useEffect, useState } from "react";
import type { ResolvedAccount } from "@/lib/account";
import { describePresence } from "@/lib/presence";
import type { Session } from "@/lib/session";

/**
 * Account devices: revocation, and rotation when a device has been stolen.
 *
 * # The distinction this panel exists to make legible
 *
 * Losing a device and having one stolen do not call for the same response, and the interface
 * is the only place the user can learn why.
 *
 * Every device on an account holds the same seed — that is what gives them all the same
 * rights, with no "primary" device. The cost is that a **stolen** device holds the whole
 * account: revoking it does not stop it from attesting a new one a second later. Only rotating
 * the account key ends that, by making every attestation unverifiable at once.
 *
 * Showing both buttons side by side without that explanation would lead straight to the wrong
 * choice, and the user would believe they had protected themselves.
 */
export function DeviceSettings({
  session,
  onError,
  onClose,
}: {
  session: Session;
  onError: (message: string) => void;
  onClose: () => void;
}) {
  const [account, setAccount] = useState<ResolvedAccount | null>(null);
  const [busy, setBusy] = useState(false);
  const [rotation, setRotation] = useState(false);
  const [phrase, setPhrase] = useState<string | null>(null);

  const reload = () => {
    session
      .resolve(session.handle)
      .then(setAccount)
      .catch((e: unknown) => onError(e instanceof Error ? e.message : String(e)));
  };

  useEffect(reload, [session, onError]);

  const revoke = async (deviceId: string) => {
    setBusy(true);
    try {
      await session.revokeOwnDevice(deviceId);
      reload();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const rotate = async () => {
    setBusy(true);
    try {
      setPhrase(await session.rotateAccount());
      reload();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // After rotation: the new phrase, once. The old one is worth nothing now.
  if (phrase) {
    return (
      <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
        <h2 className="font-medium">New recovery phrase</h2>
        <p className="mt-2 text-(--color-ink-muted)">
          Write it down now. The old one no longer gives access to anything, and this one will
          not be shown again.
        </p>
        <p className="mt-3 rounded-md border border-(--color-border-subtle) bg-(--color-surface) px-3 py-2 font-mono text-xs leading-relaxed">
          {phrase}
        </p>
        <p className="mt-3 text-xs text-(--color-ink-muted)">
          Your other devices must be <strong>paired again</strong>: they hold the old key. The
          people you talk to will see a fingerprint change warning — it is correct, your account
          key has changed.
        </p>
        <button
          type="button"
          onClick={() => {
            setPhrase(null);
            onClose();
          }}
          className="mt-4 rounded-md bg-(--color-accent) px-3 py-1.5 text-sm font-medium text-white"
        >
          I&apos;ve written it down
        </button>
      </div>
    );
  }

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Your devices</h2>
        <button type="button" onClick={onClose} className="text-(--color-ink-muted) underline">
          Close
        </button>
      </div>

      <p className="mt-2 text-xs text-(--color-ink-muted)">
        All your devices have exactly the same access, everywhere. There is no primary device.
      </p>

      {account === null ? (
        <p className="mt-3 text-(--color-ink-muted)">Loading…</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {account.devices.map((device) => (
            <li key={device.id} className="flex items-center justify-between gap-3">
              <span className="font-mono text-xs">
                {device.id}
                {device.id === session.deviceId && (
                  <span className="ml-2 font-sans text-(--color-ink-muted)">(this one)</span>
                )}
                {/*
                  Served to the account owner alone. This is what makes visible a device thought
                  to be switched off that is still collecting messages — the symptom of a lost
                  device, or worse.
                */}
                {device.lastSeen !== undefined && (
                  <span className="ml-2 block font-sans text-(--color-ink-muted)">
                    {/*
                      The server clock if we have already read it, the local one otherwise:
                      comparing two timestamps produced by different machines is exactly what
                      makes a status flicker for anyone whose clock is off.
                    */}
                    {describePresence(
                      device.lastSeen * 1000,
                      session.presenceClock || Date.now(),
                    )}
                  </span>
                )}
              </span>
              {device.id !== session.deviceId && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => revoke(device.id)}
                  className="shrink-0 text-xs underline text-(--color-ink-muted)"
                >
                  revoke
                </button>
              )}
            </li>
          ))}

          {account.revoked.map((device) => (
            <li key={device.id} className="flex items-center justify-between gap-3">
              <span className="font-mono text-xs text-(--color-ink-muted) line-through">
                {device.id}
              </span>
              <span className="shrink-0 text-xs text-(--color-ink-muted)">revoked</span>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-4 border-t border-(--color-border-subtle) pt-3">
        <p className="text-xs text-(--color-ink-muted)">
          <strong>Revoking</strong> is the right answer for a device that is lost or out of
          service: it stops receiving, and no longer decrypts the rest of your conversations.
        </p>

        {rotation ? (
          <div className="mt-3 space-y-2 rounded-md border border-(--color-danger) bg-(--color-danger)/10 p-3">
            <p className="font-medium text-(--color-danger)">
              If a device was stolen from you, revoking it is not enough
            </p>
            <p className="text-xs text-(--color-ink-muted)">
              It holds your account key, like all your devices. Whoever has it can therefore
              declare a new device straight away. Changing the account key is the only measure
              that stops them.
            </p>
            <p className="text-xs text-(--color-ink-muted)">What this means:</p>
            <ul className="list-disc space-y-1 pl-5 text-xs text-(--color-ink-muted)">
              <li>A new recovery phrase. The old one will be worth nothing.</li>
              <li>Your other devices will have to be paired again.</li>
              <li>
                The people you talk to will see an identity change warning, and it will be
                correct.
              </li>
              <li>
                <strong>All of your backed-up history will become permanently unreadable</strong>
                : it is encrypted under a key derived from the old phrase, and nothing can
                re-encrypt it. Since the backup is on by default, this applies to you even if you
                never touched the setting.
              </li>
              <li>
                The thief holds the same key you do and can act first. Do this now.
              </li>
            </ul>
            <div className="flex gap-3 pt-1">
              <button
                type="button"
                disabled={busy}
                onClick={rotate}
                className="rounded-md bg-(--color-danger) px-3 py-1.5 text-xs font-medium text-white"
              >
                Change the account key
              </button>
              <button
                type="button"
                onClick={() => setRotation(false)}
                className="text-xs underline text-(--color-ink-muted)"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setRotation(true)}
            className="mt-2 text-xs underline text-(--color-danger)"
          >
            A device was stolen from me
          </button>
        )}
      </div>
    </div>
  );
}
