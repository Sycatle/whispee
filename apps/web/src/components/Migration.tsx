import { useState } from "react";
import type { ProposedMigration, Session } from "@/lib/session";

/**
 * Offers the move to native storage, without performing it.
 *
 * # Why an offer and not an automatic operation
 *
 * It registers one device and **revokes another**. Those are account-level acts, visible to the
 * server and to your contacts; nothing about "opening the app" asks for them. And the price is
 * real: the MLS identity changes, so conversations are rejoined from scratch and history is
 * re-read from the vault. Choosing the moment is up to the user.
 *
 * # What the text has to say, and why it is long
 *
 * The benefit — storage the system won't evict — is invisible until it has been missed. The cost
 * shows up immediately. A banner promising "more security" without saying what changes would get
 * blind acceptance, or refusal out of caution, which amounts to the same thing: the decision
 * would not be an informed one.
 */
export function MigrationBanner({
  migration,
  onDone,
  onError,
}: {
  migration: ProposedMigration;
  onDone: (session: Session) => void;
  onError: (message: string) => void;
}) {
  const [step, setStep] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;

  const run = async () => {
    setStep("Preparing…");
    try {
      onDone(await migration.execute(setStep));
    } catch (error) {
      // A failure breaks nothing: both devices stay active, and the next start picks up from
      // there. Saying so keeps the user from worrying about seeing two devices in their settings.
      console.error("migration interrupted", error);
      onError(
        error instanceof Error
          ? error.message
          : "The migration did not complete. It will resume on the next start.",
      );
      setStep(null);
    }
  };

  return (
    <section className="border-t border-(--color-ink-muted)/30 bg-(--color-ink-muted)/10 px-4 py-3 text-sm">
      <h2 className="font-medium">
        {migration.resume ? "Unfinished migration" : "This device's storage"}
      </h2>

      <p className="mt-1 text-(--color-ink-muted)">
        {migration.resume
          ? "A second device was registered but the old one has not been removed yet. " +
            "Both work; resuming finishes the move and removes the old one."
          : "This app can keep your conversations outside the browser, where the system won't " +
            "erase them. The move registers a new device and removes this one: your " +
            "conversations are rejoined from scratch and history is reloaded from the backup. " +
            "Your contacts will see a device change."}
      </p>

      {step ? (
        <p className="mt-2 text-(--color-ink-muted)" role="status">
          {step}
        </p>
      ) : (
        <div className="mt-2 flex gap-4">
          <button type="button" onClick={() => void run()} className="underline">
            {migration.resume ? "Resume" : "Switch to app storage"}
          </button>
          {/* Dismissed for this session only: the offer comes back on the next start, because a
              refusal today is not a permanent refusal — and because nothing tells the two
              apart. */}
          <button
            type="button"
            onClick={() => setDismissed(true)}
            className="text-(--color-ink-muted) underline"
          >
            Later
          </button>
        </div>
      )}
    </section>
  );
}
