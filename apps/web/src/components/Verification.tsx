import { useState } from "react";
import type { ResolvedAccount } from "@/lib/account";
import type { VerificationState } from "@/lib/session";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { ProofStrip } from "@/ui/ProofStrip";
import { useBump, useSession } from "@/state/SessionProvider";
import { useReport } from "@/state/report";
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
 *
 * # Why the alert lives at the conversation and the comparison lives in the detail column
 *
 * [`Verification`] renders in the thread, above the messages. [`VerificationPanel`] renders in
 * the right-hand column, which is closed by default. The split is not a layout preference: a
 * closed column is documentation one goes looking for, and an alert nobody opened the drawer for
 * is an alert that was never raised. The thing that shouts has to be where the reader already is;
 * the thing that rewards attention can wait behind a click.
 *
 * What that does not solve: a reader who scrolls past the banner without reading it is in exactly
 * the same position as one who never opened the column. Placement buys a chance at attention, not
 * attention itself.
 */
export function Verification({
  account,
  state,
}: {
  account: ResolvedAccount;
  state: VerificationState;
}) {
  // The padding is applied here rather than by the caller because the caller — `Conversation.tsx`
  // — stacks these directly between the header and the message list with no wrapper of its own,
  // and a card flush against both edges reads as a bar rather than as something inserted.
  const inset = "px-pane pt-snug";

  // The server served a device it could not have produced. This is worse than a fingerprint
  // change: there is no benign explanation.
  if (account.rejected.length > 0) {
    return (
      <div className={inset}>
        <Banner tone="danger" title={`Unattested device presented for @${account.handle}`}>
          The server announced {account.rejected.length}{" "}
          {account.rejected.length === 1 ? "device" : "devices"} whose signature does not match
          this account. A legitimate account cannot produce that: either the server has been
          compromised, or it is trying to insert itself into the conversation. These devices were
          discarded and receive nothing.
        </Banner>
      </div>
    );
  }

  // Nominal: nothing. No green check, no banner, no dot.
  if (state.status !== "changed") return null;

  return (
    <div className={inset}>
      <Banner tone="danger" title={`@${account.handle}'s fingerprint has changed`}>
        Either @{account.handle} restored their account from their recovery phrase, or someone
        has stepped in between. The first explanation is rare, the second is an attack — and
        nothing in the protocol tells them apart. Check before you send anything sensitive.
      </Banner>
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
 *
 * `info` rather than `warn`, and the tone is the whole claim: a `warn` banner takes `role="alert"`
 * and cuts across a screen reader mid-sentence. Somebody buying a laptop is not an emergency, and
 * spending the interruption here is spending it against the fingerprint alert above.
 *
 * What that does not solve: an addition the user does not recognise *is* the emergency, and this
 * component cannot know which of the two it is holding. It states the fact and hands the
 * judgement over, which is the only honest thing available to it.
 */
export function DeviceAdded({ handle, devices }: { handle: string; devices: string[] }) {
  if (devices.length === 0) return null;

  return (
    <Banner tone="info">
      @{handle} added {devices.length === 1 ? "a device" : `${devices.length} devices`}:{" "}
      {devices.join(", ")}. If this was not you, that account may be compromised.
    </Banner>
  );
}

/**
 * Manual fingerprint comparison, as a section of the detail column.
 *
 * # A section, not a panel of its own
 *
 * It used to be a free-standing surface with its own border, background and Close link, opened
 * over the conversation. It is now unwrapped content the detail column lays out, because it is
 * one step of the reading that column already exists for: the strip says *something changed*, the
 * words say *what kind of change*, and this is where the reader does the only thing that settles
 * it. Three surfaces for one question was three chances to close the wrong one.
 *
 * # The strip is here, and it is not the comparison
 *
 * The proof strips sit above each fingerprint so the eye gets the shapes before the digits — but
 * nineteen bits of pattern are grindable in seconds of CPU. **The strip detects a change; it does
 * not verify an identity.** Only the hexadecimal below it, read out over another channel, does
 * that, and it is why the digits are set in `--font-evidence` on a fixed grid rather than as
 * running text.
 *
 * # What this still does not solve
 *
 * Comparing digits by eye is tedious and unreliable, and a reader in a hurry will click "The
 * fingerprints match" having glanced at the first block. The natural next step is a QR code shown
 * and scanned: two seconds and no misreading — but that assumes camera access, out of scope here.
 */
export function VerificationPanel({
  account,
  onClose,
}: {
  account: ResolvedAccount;
  onClose: () => void;
}) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const [busy, setBusy] = useState(false);

  const state = session.verificationOf(account);
  const mine = session.accountFingerprint();

  const confirm = () => {
    setBusy(true);
    void session
      .markVerified(account)
      .then(() => {
        bump();
        report.done(`Marked @${account.handle} as verified.`);
        onClose();
      })
      .catch((e: unknown) => report.error(e instanceof Error ? e.message : String(e)))
      .finally(() => setBusy(false));
  };

  return (
    <div className="space-y-snug">
      <p className="text-body text-(--color-ink-muted)">
        Read these two fingerprints to each other out loud, or over a channel this server does not
        carry. If every block matches, nobody has stepped in between.
      </p>

      <p className="text-caption text-(--color-ink-muted)">
        The fingerprint covers the account, so it stays the same when @{account.handle} adds or
        removes a device. This account currently declares {account.devices.length}.
      </p>

      <div className="space-y-gutter">
        <div className="space-y-tight">
          <p className="text-caption tracking-wide text-(--color-ink-muted) uppercase">
            @{account.handle}
          </p>
          <ProofStrip fingerprint={account.fingerprint} scale="detail" verification={state} />
          <Fingerprint value={account.fingerprint} />
        </div>

        {state.status === "changed" && (
          <div className="space-y-tight">
            <p className="text-caption tracking-wide text-(--color-danger) uppercase">
              Previously verified fingerprint
            </p>
            <ProofStrip fingerprint={state.previous} scale="detail" />
            <Fingerprint value={state.previous} />
          </div>
        )}

        <div className="space-y-tight">
          <p className="text-caption tracking-wide text-(--color-ink-muted) uppercase">
            @{session.handle} (yours)
          </p>
          <ProofStrip fingerprint={mine} scale="detail" />
          <Fingerprint value={mine} />
        </div>
      </div>

      <div className="flex flex-wrap gap-snug">
        {state.status === "verified" ? (
          <p className="text-caption text-(--color-ok)">
            You have already compared this fingerprint by hand. It has not changed since.
          </p>
        ) : (
          <Button variant="primary" size="sm" busy={busy} onClick={confirm}>
            The fingerprints match
          </Button>
        )}
        <Button variant="quiet" size="sm" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
