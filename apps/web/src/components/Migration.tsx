import { useState } from "react";
import type { ProposedMigration, Session } from "@/lib/session";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Spinner } from "@/ui/Spinner";

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
 *
 * # Why `tone="info"` for something the app would rather you did
 *
 * `warn` and `danger` mean "something is wrong"; nothing is wrong here, and both of those tones
 * carry `role="alert"`, which would interrupt a screen reader mid-sentence to deliver a
 * suggestion. An offer that shouts is an offer that gets dismissed unread — and dismissing it
 * unread is exactly the outcome the long text above exists to avoid. `info` is `role="status"`:
 * announced when the reader gets to it.
 *
 * What this does not solve: the banner is anchored at the bottom by whoever renders it, not by
 * anything here. It is a block in the shell's column, so it inherits its position from that
 * column — which is why it carries a margin rather than a border-to-border strip.
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
    <Banner
      tone="info"
      title={migration.resume ? "Unfinished migration" : "This device's storage"}
      className="m-pane shrink-0"
    >
      <p>
        {migration.resume
          ? "A second device was registered but the old one has not been removed yet. " +
            "Both work; resuming finishes the move and removes the old one."
          : "This app can keep your conversations outside the browser, where the system won't " +
            "erase them. The move registers a new device and removes this one: your " +
            "conversations are rejoined from scratch and history is reloaded from the backup. " +
            "Your contacts will see a device change."}
      </p>

      {step ? (
        // The step name alone left the banner looking identical between two phases that can each
        // take several seconds. The spinner is the part that says the wait is still ours rather
        // than a screen that has stopped.
        //
        // No `role="status"` here: the banner itself already is one for this tone, and a live
        // region nested inside a live region gets the change announced twice.
        <p className="mt-snug flex items-center gap-snug">
          <Spinner size="sm" />
          {step}
        </p>
      ) : (
        <div className="mt-snug flex flex-wrap items-center gap-snug">
          <Button variant="primary" size="sm" onClick={() => void run()}>
            {migration.resume ? "Resume" : "Switch to app storage"}
          </Button>
          {/* Dismissed for this session only: the offer comes back on the next start, because a
              refusal today is not a permanent refusal — and because nothing tells the two
              apart. */}
          <Button variant="quiet" size="sm" onClick={() => setDismissed(true)}>
            Later
          </Button>
        </div>
      )}
    </Banner>
  );
}
