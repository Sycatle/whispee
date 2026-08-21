import { useState } from "react";
import type { ResolvedAccount } from "@/lib/account";
import type { VerificationState } from "@/lib/session";
import { Fingerprint } from "./Fingerprint";

/**
 * Identity verification: silent when nothing is wrong, blunt on anomaly.
 *
 * # Why nothing is shown while all is well
 *
 * A permanent "identity not verified" warning takes a few days to learn to ignore. On the day
 * it matters — the fingerprint changed — it has already become invisible. A perpetual banner
 * is not a precaution: it is what makes the useful alert inaudible.
 *
 * Signal and WhatsApp say nothing in the nominal case and only warn on a change. That is
 * better for the user *and* for security, because it preserves the alert's claim on attention.
 *
 * # What is still missing to close the initial trust gap
 *
 * Staying silent on `unverified` is a bet: that the first KeyPackage served really was the
 * peer's (trust on first use). Closing it takes **key transparency** — an auditable Merkle log
 * of public keys that the client checks automatically. That is what WhatsApp and Apple deploy,
 * and it is what lets you ask nothing of the user without trusting the server either.
 *
 * # The fingerprint covers the account, not the device
 *
 * So it does not move when a peer adds a phone. That is deliberate: a fingerprint that changed
 * on every added device would force a re-check after every mundane event, and would be ignored
 * within weeks. Device additions are reported separately, by [`DeviceAdded`].
 */
export function Verification({
  account,
  state,
}: {
  account: ResolvedAccount;
  state: VerificationState;
}) {
  // The server served a device it could not have produced. This is worse than a fingerprint
  // change: there is no benign explanation.
  if (account.rejected.length > 0) {
    return (
      <div
        role="alert"
        className="border-b border-(--color-danger) bg-(--color-danger)/20 px-4 py-3 text-sm"
      >
        <p className="font-medium text-(--color-danger)">
          Unattested device presented for @{account.handle}
        </p>
        <p className="mt-1 text-(--color-ink-muted)">
          The server announced {account.rejected.length}{" "}
          {account.rejected.length === 1 ? "device" : "devices"} whose signature does not match
          this account. A legitimate account cannot produce that: either the server has been
          compromised, or it is trying to insert itself into the conversation. These devices were
          discarded and receive nothing.
        </p>
      </div>
    );
  }

  // Nominal: nothing. No green check, no banner, no dot.
  if (state.status !== "changed") return null;

  return (
    <div
      role="alert"
      className="border-b border-(--color-danger) bg-(--color-danger)/10 px-4 py-3 text-sm"
    >
      <p className="font-medium text-(--color-danger)">
        @{account.handle}&apos;s fingerprint has changed
      </p>
      <p className="mt-1 text-(--color-ink-muted)">
        Either @{account.handle} restored their account from their recovery phrase, or someone
        has stepped in between. The first explanation is rare, the second is an attack — and
        nothing in the protocol tells them apart. Check before you send anything sensitive.
      </p>
    </div>
  );
}

/**
 * Reports devices that have appeared on a peer's account.
 *
 * It is **this notification, not the fingerprint, that catches a hostile device**. A device
 * added by a compromised account is duly attested, so indistinguishable from a legitimate
 * addition: only the user can say whether they really own that device. Hence a notice rather
 * than an automatic verdict.
 */
export function DeviceAdded({ handle, devices }: { handle: string; devices: string[] }) {
  if (devices.length === 0) return null;

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-2 text-xs text-(--color-ink-muted)">
      @{handle} added {devices.length === 1 ? "a device" : `${devices.length} devices`}:{" "}
      {devices.join(", ")}. If this was not you, that account may be compromised.
    </div>
  );
}

/**
 * Manual fingerprint comparison, on demand.
 *
 * Stays available for whoever really wants to check, without forcing the ritual on everyone.
 * The natural next step is a QR code shown and scanned: two seconds and no misreading, where
 * comparing digits by eye is tedious and unreliable — but that assumes camera access, out of
 * scope here.
 */
export function VerificationPanel({
  account,
  state,
  myName,
  myFingerprint,
  onVerified,
  onClose,
}: {
  account: ResolvedAccount;
  state: VerificationState;
  myName: string;
  myFingerprint: string;
  onVerified: () => void;
  onClose: () => void;
}) {
  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Verify @{account.handle}&apos;s identity</h2>
        <button type="button" onClick={onClose} className="text-(--color-ink-muted) underline">
          Close
        </button>
      </div>

      <p className="mt-2 text-(--color-ink-muted)">
        Compare these two fingerprints out loud or over another channel. If they match, nobody
        has stepped in between.
      </p>

      <p className="mt-1 text-xs text-(--color-ink-muted)">
        The fingerprint covers the account: it stays the same when @{account.handle} adds or
        removes a device. This account currently declares {account.devices.length}.
      </p>

      <div className="mt-4 space-y-3">
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-wide text-(--color-ink-muted)">
            @{account.handle}
          </p>
          <Fingerprint value={account.fingerprint} />
        </div>

        {state.status === "changed" && (
          <div className="space-y-1">
            <p className="text-xs uppercase tracking-wide text-(--color-danger)">
              Previously verified fingerprint
            </p>
            <Fingerprint value={state.previous} />
          </div>
        )}

        <div className="space-y-1">
          <p className="text-xs uppercase tracking-wide text-(--color-ink-muted)">
            {myName} (yours)
          </p>
          <Fingerprint value={myFingerprint} />
        </div>
      </div>

      {state.status === "verified" ? (
        <p className="mt-4 text-(--color-ok)">✓ You have already verified this fingerprint.</p>
      ) : (
        <button
          type="button"
          onClick={onVerified}
          className="mt-4 rounded-control bg-(--color-accent) px-gutter py-control font-medium text-(--color-accent-ink)"
        >
          The fingerprints match
        </button>
      )}
    </div>
  );
}

/** Discreet entry point to verification, in the conversation header. */
export function VerificationToggle({
  state,
  onClick,
}: {
  state: VerificationState;
  onClick: () => void;
}) {
  const [hover, setHover] = useState(false);
  return (
    <button
      type="button"
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      title="Verify identity"
      className={`text-xs ${state.status === "verified" ? "text-(--color-ok)" : "text-(--color-ink-muted)"} ${hover ? "underline" : ""}`}
    >
      {state.status === "verified" ? "✓ verified" : "verify identity"}
    </button>
  );
}
