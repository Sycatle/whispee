import { type ReactNode, useState } from "react";

import { PresenceBadge, PresenceLine } from "@/components/Presence";
import { formatHandle, nameOf } from "@/lib/naming";
import type { ConversationView } from "@/lib/session";
import { useNavigate } from "@/routes/Router";
import { useNames } from "@/state/names";
import { useSession } from "@/state/SessionProvider";
import { Avatar } from "@/ui/Avatar";
import { Button } from "@/ui/Button";
import { Popover } from "@/ui/Popover";

/**
 * Who somebody is, without leaving what you were reading.
 *
 * # Why a card and not the detail column
 *
 * Clicking a name used to replace the whole detail column with that person's verification panel.
 * That is the right destination for verifying a key and the wrong one for the question people
 * actually ask when they click a name mid-conversation — *who is this, and are they around* —
 * because answering it cost the reader the column they had open and a trip back.
 *
 * The card answers that in place. The column is still one press away, from the card itself, so
 * nothing is lost: the small answer is free and the large one is where it always was.
 *
 * # Our own face is not excluded
 *
 * The card opens on ourselves too, with different contents: there is no key of ours to verify
 * and no verification to reach, so it offers the profile settings instead. Excluding ourselves
 * would make one face in every group behave unlike the others for a reason the reader cannot
 * see — and "why does clicking me do nothing" is a worse question than any this card answers.
 *
 * What this does not solve: the fingerprint is not here. It is the one thing that must be
 * compared rather than glanced at, and putting it in a card that closes when the pointer moves
 * would teach people to treat it as a glance. It stays in the column, behind the button below.
 */
export function MiniProfile({
  handle,
  view,
  children,
}: {
  handle: string;
  /** The conversation the card is opened from — the detail route hangs off it. */
  view: ConversationView;
  /** The face or the name that opens it. Cloned by Radix, so it must forward its ref. */
  children: ReactNode;
}) {
  const session = useSession();
  const names = useNames();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const name = nameOf(handle, names);
  const mine = handle === session.handle;
  const seed = mine
    ? session.accountFingerprint()
    : view.accounts.find((account) => account.handle === handle)?.fingerprint;

  return (
    <Popover
      open={open}
      onOpenChange={setOpen}
      label={`Profile of ${formatHandle(handle)}`}
      side="top"
      trigger={children}
    >
      <div className="flex w-64 max-w-full flex-col items-start gap-snug">
        <div className="flex items-center gap-snug">
          <PresenceBadge session={session} handle={handle}>
            <Avatar seed={seed} label={name.primary} size="lg" className="shrink-0" />
          </PresenceBadge>
          <div className="flex min-w-0 flex-col">
            <span className="truncate text-prose font-medium">{name.primary}</span>
            {/* The handle always, even when it is what the name already shows. It is the anchor
                the display name is not, and a card about identity that omits it is decoration. */}
            <span className="truncate font-evidence text-caption text-(--color-ink-muted)">
              {formatHandle(handle)}
            </span>
            <PresenceLine session={session} handle={handle} />
          </div>
        </div>

        {mine ? (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              setOpen(false);
              navigate({ kind: "settings", section: "profile" });
            }}
          >
            Edit your profile
          </Button>
        ) : (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              setOpen(false);
              navigate({ kind: "conversation", key: view.key, detail: { handle } });
            }}
          >
            View full profile
          </Button>
        )}
      </div>
    </Popover>
  );
}
