import { nameOf } from "@/lib/naming";
import { useNames } from "@/state/names";
import { Avatar } from "@/ui/Avatar";
import { Button } from "@/ui/Button";
import { Icon } from "@/ui/Icon";
import { ProofStrip } from "@/ui/ProofStrip";
import { Fingerprint } from "@/components/Fingerprint";
import { useSession } from "@/state/SessionProvider";
import { useNavigate } from "@/routes/Router";
import { WebClientWarning } from "./WebClientWarning";

/**
 * The centre column with no conversation open — a screen, not a placeholder.
 *
 * # Why it is worth designing at all
 *
 * It is the first thing seen on every cold start, because no conversation is open by default.
 * The old shell put a grey sentence there ("No conversations. Start one with someone's handle.")
 * on the assumption that nobody would look at it for long. They look at it every morning.
 *
 * So it does the one job the rest of the interface deliberately refuses to do: it states, once,
 * in a place with room for it, **who this device says you are**. The handle, the device
 * identifier, the fingerprint and its proof strip at full width. Everywhere else the crypto is
 * kept out of the way; here there is nothing in the way.
 *
 * # The one use of `--text-display`
 *
 * The token exists for exactly this line, as its own comment in `index.css` says. A messenger
 * has no headline anywhere else — a conversation title competing at 1.5rem with the messages
 * under it would be a poster, not a thread.
 */
export function EmptyCenter() {
  const session = useSession();
  const navigate = useNavigate();
  const fingerprint = session.accountFingerprint();
  // The same function every other person on screen goes through: `useNames` folds this account's
  // display name into `profiles` under its own handle, so there is no self case to keep in step.
  const names = useNames();
  const self = nameOf(session.handle, names);

  return (
    <div className="safe-bottom flex min-h-0 flex-1 items-center justify-center overflow-y-auto p-pane">
      <div className="flex w-full max-w-md flex-col items-center gap-pane py-section text-center">
        <Avatar seed={fingerprint} label={self.primary} size="lg" />

        <div>
          {/*
            The name in the display size, the handle immediately under it. This screen exists to
            state who this device says you are, and a name you typed is not that: it is the label
            you chose for other people's screens. The handle is what identifies the account, so it
            keeps its place here rather than being replaced by the friendlier string above it.
          */}
          <h1 className="text-display font-medium">{self.primary}</h1>
          {self.secondary !== null && (
            <p className="mt-tight text-body text-(--color-ink-muted)">{self.secondary}</p>
          )}
          {/* The device identifier is evidence, not prose: it is compared character by character
              against what another device shows during pairing. Hence the monospace token, whose
              whole reason for existing is that a shared metric makes that comparison possible. */}
          <p className="mt-tight font-evidence text-caption text-(--color-ink-muted)">
            {session.deviceId.slice(session.handle.length + 1)}
          </p>
        </div>

        <div className="w-full">
          <ProofStrip fingerprint={fingerprint} scale="detail" />
          <div className="mt-snug font-evidence">
            <Fingerprint value={fingerprint} />
          </div>
        </div>

        <p className="text-body text-(--color-ink-muted)">Pick a conversation, or start one.</p>

        <Button
          variant="primary"
          icon={<Icon name="add" />}
          onClick={() => navigate({ kind: "new" })}
        >
          Start a conversation
        </Button>

        <WebClientWarning className="text-left" />
      </div>
    </div>
  );
}
