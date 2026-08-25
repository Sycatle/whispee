import { type ReactNode, useState } from "react";

import { PresenceBadge } from "@/components/Presence";
import { nameOf } from "@/lib/naming";
import { identicon } from "@/lib/proofstrip";
import { useNavigate } from "@/routes/Router";
import { useNames } from "@/state/names";
import { useSession } from "@/state/SessionProvider";
import { Avatar } from "@/ui/Avatar";
import { cn } from "@/ui/cn";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Tooltip } from "@/ui/Tooltip";

/**
 * Who is answering, at the top of the rail.
 *
 * # The banner takes its colour from the face under it
 *
 * `lib/proofstrip.ts` derives a hue from the account fingerprint and `ui/Avatar.tsx` paints the
 * identicon with it. The banner reads the same hue from the same function, so the block is one
 * object rather than a coloured strip that happens to sit above a picture — and the colour still
 * means what it meant: *this* account, not a decoration somebody chose.
 *
 * Lightness and chroma are fixed here as they are there, and for the same reason that file gives:
 * a derived lightness would sooner or later produce something unreadable, and a derived chroma
 * something garish. Only the hue moves.
 *
 * # The whole block is the way into the profile
 *
 * Clicking it opens `#/settings/profile`, where the display name and the handle are already
 * editable. No new screen, and no pencil icon competing with the gear beside it — `ui/Icon.tsx`
 * is a closed inventory and adding to it is a deliberate act, not something a layout tweak does
 * on the way past.
 *
 * # The microphone and the headphones do not mute anything yet
 *
 * They are here because the layout is being built ahead of the calls that will use them, and
 * somebody else is building those. **Nothing is captured and nothing is muted**: the state is
 * local to this component and no audio path reads it.
 *
 * That is worth stating plainly rather than leaving to be discovered, because a muted-microphone
 * icon is a claim about privacy — on an application whose whole argument is that you can check
 * what it does. Whoever wires the call layer should lift this state to wherever the media stream
 * lives, not read it from here.
 */
export function AccountCard({ menu }: {
  /**
   * The gear and everything behind it, passed in rather than built here.
   *
   * That menu is the rail's — theme, lock, devices, pairing, erase — and it reaches into
   * `onLock` and `onForget`, which are the shell's. Rebuilding it here would mean threading both
   * through a component whose subject is an account rather than a session.
   */
  menu: ReactNode;
}) {
  const session = useSession();
  const names = useNames();
  const navigate = useNavigate();

  // Local, and deliberately going no further. See the note above.
  const [muted, setMuted] = useState(false);
  const [deafened, setDeafened] = useState(false);

  const fingerprint = session.accountFingerprint();
  const self = nameOf(session.accountId, names);
  const { hue } = identicon(fingerprint);

  return (
    <div className="border-b border-(--color-border-subtle)">
      {/* Edge to edge, and not an image.
 
          It is flush with the column because it *is* the top of the column — a banner inset from
          the sides would be a card inside a card, which is what this looked like when it still
          sat inside the old header bar's padding.
 
          No photograph, and the height is chosen accordingly: an avatar here is derived from a
          key rather than uploaded, so there is nothing to fit. Sixty-four pixels is enough for
          the colour to read as a surface of its own rather than as a rule under the edge. */}
      <div
        aria-hidden="true"
        className="h-16 w-full"
        style={{
          background: `linear-gradient(to bottom right, oklch(0.62 0.12 ${hue}), oklch(0.52 0.09 ${(hue + 40) % 360}))`,
        }}
      />

      {/* A row, and the face on the seam.
 
          A column was tried and reads as a profile page rather than as the top of a list: it
          spends three lines and a lot of height on what a rail states in one. The row keeps the
          name and the handle stacked — they are one label, not two — and puts the controls where
          the eye already goes for controls.
 
          `ring` in the surface colour rather than a border: the face is half on the banner and
          half off it, and a ring separates it from both without drawing a line that belongs to
          neither. */}
      <div className="flex items-end gap-snug px-gutter pb-snug">
        <button
          type="button"
          onClick={() => navigate({ kind: "settings", section: "profile" })}
          aria-label="Edit your profile"
          // `-mt-5` on a 40px face: half of it sits on the banner and half below. Four pixels of
          // overlap read as neither — the face looked pushed against an edge rather than placed
          // on it — and half is the amount that makes the seam deliberate.
          //
          // Only the face crosses it. The row is `items-end`, so the name and the controls stay
          // on the surface: raised with it, they sat on the colour and became unreadable.
          className="-mt-5 shrink-0 rounded-pill ring-4 ring-(--color-surface) focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent)"
        >
          <PresenceBadge session={session} handle={session.accountId}>
            {/* `ml`, the 40px step this card is the reason for adding — see `ui/Avatar.tsx`. */}
            <Avatar seed={fingerprint} label={session.accountId} size="ml" />
          </PresenceBadge>
        </button>

        <button
          type="button"
          onClick={() => navigate({ kind: "settings", section: "profile" })}
          className="min-w-0 flex-1 text-left"
        >
          <span className="block truncate text-body font-medium">{self.primary}</span>
          {/* The handle, or whatever `nameOf` decided is the anchor under the name. It is drawn
              even when the name above already looks like it — see `lib/naming.ts`: a display name
              is self-asserted and not unique, and this is the part that is neither. */}
          {self.secondary !== null && (
            <span className="block truncate font-evidence text-caption text-(--color-ink-muted)">
              {self.secondary}
            </span>
          )}
        </button>

        {/* The gear last: the two before it are states of this device, and it is a way out of
            this column. Grouping by what they do is what keeps a settings menu from reading as a
            third toggle. */}
        <div className="flex shrink-0 items-center gap-tight">
          <Tooltip label={muted ? "Unmute microphone" : "Mute microphone"}>
            <IconButton
              label={muted ? "Unmute microphone" : "Mute microphone"}
              aria-pressed={muted}
              onClick={() => setMuted((on) => !on)}
              icon={
                <Icon
                  name={muted ? "micOff" : "mic"}
                  size={18}
                  className={cn(muted && "text-(--color-danger)")}
                />
              }
            />
          </Tooltip>

          <Tooltip label={deafened ? "Undeafen" : "Deafen"}>
            <IconButton
              label={deafened ? "Undeafen" : "Deafen"}
              aria-pressed={deafened}
              onClick={() => setDeafened((on) => !on)}
              icon={
                <Icon
                  name={deafened ? "headphonesOff" : "headphones"}
                  size={18}
                  className={cn(deafened && "text-(--color-danger)")}
                />
              }
            />
          </Tooltip>

          {menu}
        </div>
      </div>
    </div>
  );
}
