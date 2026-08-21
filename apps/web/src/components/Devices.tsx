import { useEffect, useState } from "react";
import type { ResolvedAccount } from "@/lib/account";
import { describePresence } from "@/lib/presence";
import { useBump, useSession } from "@/state/SessionProvider";
import { useReport } from "@/state/report";
import { Avatar } from "@/ui/Avatar";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Panel } from "@/ui/Panel";
import { Spinner } from "@/ui/Spinner";

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
 *
 * # Why an identicon sits beside each identifier
 *
 * A device identifier is a run of hex, and a list of them is a wall a reader skims rather than
 * reads. The identicon is derived from the identifier itself, so two devices are told apart by a
 * shape before anyone compares characters, and "this one" is found at a glance.
 *
 * What this does not solve: the identicon is a five-by-five grid over a short hash — two
 * identifiers can draw the same picture. It is a way of *noticing* which row is which, never a
 * way of proving what a row is. The identifier underneath is the evidence, and it is set in
 * `--font-evidence` because that is the string a human actually compares.
 */
export function DeviceSettings({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const [account, setAccount] = useState<ResolvedAccount | null>(null);
  const [busy, setBusy] = useState(false);
  const [rotation, setRotation] = useState(false);
  const [phrase, setPhrase] = useState<string | null>(null);

  const reload = () => {
    session
      .resolve(session.handle)
      .then(setAccount)
      .catch((e: unknown) => report.error(e instanceof Error ? e.message : String(e)));
  };

  useEffect(reload, [session, report]);

  const revoke = async (deviceId: string) => {
    setBusy(true);
    try {
      await session.revokeOwnDevice(deviceId);
      reload();
      // The device list is part of the session everybody else reads. This is what the caller
      // used to do for us on close, except it now fires when something actually changed.
      bump();
      report.done("Device revoked");
    } catch (e) {
      report.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const rotate = async () => {
    setBusy(true);
    try {
      setPhrase(await session.rotateAccount());
      reload();
      bump();
    } catch (e) {
      report.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // After rotation: the new phrase, once. The old one is worth nothing now.
  if (phrase) {
    return (
      <Panel
        tone="danger"
        title="New recovery phrase"
        description="Write it down now. The old one no longer gives access to anything, and this one will not be shown again."
        actions={
          <Button variant="primary" onClick={() => {
            setPhrase(null);
            onClose();
          }}>
            I&apos;ve written it down
          </Button>
        }
      >
        {/* `--font-evidence` and `select-all`: twelve words copied out by hand are twelve chances
            to transcribe one wrong, and the whole phrase is worthless if one word is. */}
        <p className="select-all rounded-control border border-(--color-border-subtle) bg-(--color-surface-sunken) p-gutter font-(--font-evidence) text-body leading-relaxed text-(--color-ink)">
          {phrase}
        </p>
        <p className="mt-gutter text-caption text-(--color-ink-muted)">
          Your other devices must be <strong>paired again</strong>: they hold the old key. The
          people you talk to will see a fingerprint change warning — it is correct, your account
          key has changed.
        </p>
      </Panel>
    );
  }

  return (
    <Panel
      title="Your devices"
      description="All your devices have exactly the same access, everywhere. There is no primary device."
      actions={
        <IconButton label="Close" icon={<Icon name="close" />} onClick={onClose} />
      }
    >
      {account === null ? (
        <p className="flex items-center gap-snug text-body text-(--color-ink-muted)">
          <Spinner label="Loading your devices" />
          Loading…
        </p>
      ) : (
        <ul className="flex flex-col gap-snug">
          {account.devices.map((device) => (
            <li key={device.id} className="flex items-center gap-gutter">
              <Avatar seed={device.id} label={`Device ${device.id}`} size="sm" />
              <span className="min-w-0 flex-1">
                <span className="block break-all font-(--font-evidence) text-caption text-(--color-ink)">
                  {device.id}
                </span>
                {device.id === session.deviceId && (
                  <span className="text-caption text-(--color-ink-muted)">(this one)</span>
                )}
                {/*
                  Served to the account owner alone. This is what makes visible a device thought
                  to be switched off that is still collecting messages — the symptom of a lost
                  device, or worse.
                */}
                {device.lastSeen !== undefined && (
                  <span className="block text-caption text-(--color-ink-muted)">
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
                <Button
                  variant="quiet"
                  size="sm"
                  disabled={busy}
                  onClick={() => revoke(device.id)}
                  className="shrink-0"
                >
                  Revoke
                </Button>
              )}
            </li>
          ))}

          {account.revoked.map((device) => (
            <li key={device.id} className="flex items-center gap-gutter opacity-60">
              <Avatar seed={device.id} label={`Revoked device ${device.id}`} size="sm" />
              <span className="min-w-0 flex-1 break-all font-(--font-evidence) text-caption text-(--color-ink-muted) line-through">
                {device.id}
              </span>
              <span className="shrink-0 text-caption text-(--color-ink-muted)">revoked</span>
            </li>
          ))}
        </ul>
      )}

      {/* The list above and the explanation below are two different kinds of thing — a roster
          and an argument about what revoking costs — so the change of subject is carried by the
          distance rather than by a rule. `mt-section` is a step above the `gap-snug` between the
          device rows, which is what makes the break read as a break at all. */}
      <div className="mt-section">
        <p className="text-caption text-(--color-ink-muted)">
          <strong>Revoking</strong> is the right answer for a device that is lost or out of
          service: it stops receiving, and no longer decrypts the rest of your conversations.
        </p>

        {/*
          The confirmation is a state of this panel rather than a dialog laid over it, and that
          is deliberate rather than a limitation: the reader has to weigh five consequences
          before pressing, and a dialog would either be too small to hold them or would hide the
          device list the decision is about. The cost is stated in full, then the destructive
          button, then a way out.

          What this does not solve: it does not slow anybody down. Someone who has already
          decided presses twice in a second, and rotation is irreversible from the first press.
          The copy therefore has to carry the whole warning — there is no second guard behind it.
        */}
        {rotation ? (
          <Banner tone="danger" title="If a device was stolen from you, revoking it is not enough">
            <p>
              It holds your account key, like all your devices. Whoever has it can therefore
              declare a new device straight away. Changing the account key is the only measure
              that stops them.
            </p>
            <p className="mt-snug">What this means:</p>
            <ul className="mt-tight list-disc space-y-1 pl-5">
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
            <div className="mt-gutter flex flex-wrap items-center gap-snug">
              <Button variant="destructive" size="sm" busy={busy} onClick={rotate}>
                Change the account key
              </Button>
              <Button variant="quiet" size="sm" onClick={() => setRotation(false)}>
                Cancel
              </Button>
            </div>
          </Banner>
        ) : (
          <Button
            variant="quiet"
            size="sm"
            onClick={() => setRotation(true)}
            className="mt-snug text-(--color-danger) hover:text-(--color-danger)"
          >
            A device was stolen from me
          </Button>
        )}
      </div>
    </Panel>
  );
}
