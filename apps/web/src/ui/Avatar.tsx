import { GRID_SIZE, identicon } from "@/lib/proofstrip";
import type { VerificationState } from "@/lib/session";
import { ProofStrip } from "@/ui/ProofStrip";

/**
 * A deterministic identicon, derived from the fingerprint and never uploaded.
 *
 * # Why the fingerprint and not the handle
 *
 * The fingerprint is a derivative of the identity key, so the drawing moves **if and only if the
 * account key moves** — the same signal as `VerificationState.changed`, obtained for free and
 * carried by something the eye is looking at anyway. Seeding from the handle would give a
 * picture that is stable across a key substitution, which is worse than no picture: it would
 * quietly vouch for the thing that just changed.
 *
 * # Why an upload is refused
 *
 * A user-supplied avatar would be a cleartext object, one per account, stored on and served by
 * the server. That is a new identifier the server can correlate on and a new leak on a client
 * whose entire premise is that the server learns as little as possible — paid for a decoration.
 * Refused, and the identicon is what stands in its place.
 *
 * # Why the placeholder is neutral, and this is the decision that matters here
 *
 * `view.accounts` is empty at startup until the first poll returns, so for the first moment
 * there is no fingerprint to draw from. The tempting fix is to seed from the handle in the
 * meantime. It must not be done: the user would watch one identicon turn into a *different*
 * identicon, several times a day, and would learn that this drawing changes on its own. That
 * lesson destroys exactly the signal built above — on the day the drawing changes because the
 * key changed, it would mean nothing.
 *
 * So the loading state is a **neutral placeholder**: an initial on a muted surface, with no
 * derived hue and no grid. A placeholder that fills in teaches nothing; an identicon that
 * mutates teaches the wrong thing.
 *
 * # What this is not
 *
 * **Visual collisions exist.** Twenty-five mirrored cells and one hue are a handful of bits;
 * two accounts can produce drawings the eye confuses, and an attacker who picks their own key
 * can aim for one. This is not a means of verification — `Fingerprint.tsx` remains the only one.
 *
 * A group has no fingerprint, so it is seeded from `view.key`, the hex of the group id: stable,
 * and available from restore rather than from the first poll, so groups never show the
 * placeholder at all.
 */

export type AvatarSize = "micro" | "sm" | "md" | "lg";

/** Pixel sizes, and whether the box is tall enough for a 24 px strip to sit under it. */
const SIZES: Record<AvatarSize, { box: number; strip: boolean; text: string }> = {
  micro: { box: 20, strip: false, text: "text-[0.6rem]" },
  sm: { box: 24, strip: false, text: "text-[0.65rem]" },
  md: { box: 32, strip: true, text: "text-xs" },
  lg: { box: 64, strip: true, text: "text-xl" },
};

/**
 * The initial, from whatever the caller displays as the name.
 *
 * `codePointAt` rather than `[0]`: a handle can start with an astral character, and slicing a
 * surrogate pair in half renders a replacement glyph — a lozenge in the one place meant to be
 * recognisable at a glance.
 */
function initialOf(label: string): string {
  const trimmed = label.trim();
  if (trimmed.length === 0) return "?";
  const code = trimmed.codePointAt(0);
  return code === undefined ? "?" : String.fromCodePoint(code).toUpperCase();
}

function Identicon({ seed, box }: { seed: string; box: number }) {
  const { cells, hue } = identicon(seed);
  /**
   * Lightness and chroma are fixed, only the hue is derived. A derived lightness would sooner or
   * later land on a value that vanishes into one of the two themes, and an avatar that is
   * invisible in dark mode is an avatar that is absent. L 0.6 clears both surfaces.
   *
   * Chroma is 0.08 rather than 0.12. At full strength, a column of these in the rail read as a
   * row of small bright signs competing with the names beside them — the drawing is meant to be
   * recognised, not looked at. Lowering it costs nothing that matters: hue is what tells two
   * accounts apart at a glance, and hue survives desaturation.
   */
  const ink = `oklch(0.6 0.08 ${hue})`;
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox={`0 0 ${GRID_SIZE} ${GRID_SIZE}`}
      width={box}
      height={box}
      /*
       * A rounded square, not a disc, and this is what the identicon actually needed.
       *
       * The grid is five cells across. Clipped to a circle, the cells around the edge were cut
       * into arcs of varying size — so a shape built to be read as one object arrived as a
       * jagged rim, different on every account for reasons that had nothing to do with the
       * fingerprint. That is the noise: not the colour, the cropping. In a rounded square every
       * cell is a whole cell and the mirror symmetry is visible, which is the property the grid
       * was designed around.
       *
       * It is also why GitHub's identicons are squares.
       */
      className="rounded-control bg-(--color-surface-sunken)"
    >
      {cells.map((filled, index) =>
        filled ? (
          <rect
            // The index is the cell: position is the whole identity of a grid square.
            key={index}
            x={index % GRID_SIZE}
            y={Math.floor(index / GRID_SIZE)}
            width={1}
            height={1}
            fill={ink}
          />
        ) : null,
      )}
    </svg>
  );
}

export function Avatar({
  seed,
  label,
  size = "md",
  proof,
  rejected = false,
  className,
}: {
  /**
   * The account fingerprint, or a group's hex key. `undefined` while the account has not been
   * resolved yet, which renders the neutral placeholder rather than a guess.
   */
  seed?: string;
  /** What the caller displays as the name: supplies the initial and labels the image. */
  label: string;
  size?: AvatarSize;
  /** Drives the micro strip's colour, and is reported as `data-verification`. */
  proof?: VerificationState;
  /** True when the account presented a device whose attestation did not verify. */
  rejected?: boolean;
  className?: string;
}) {
  const { box, strip, text } = SIZES[size];
  const verification = rejected ? "unattested" : (proof?.status ?? "unverified");

  return (
    <span
      data-verification={verification}
      className={`inline-flex flex-col items-center gap-0.5${className ? ` ${className}` : ""}`}
    >
      <span role="img" aria-label={label} className="block">
        {seed === undefined ? (
          <span
            // No derived hue here, deliberately: the placeholder must not look like a drawing
            // that is about to be corrected, or it becomes the mutating identicon this component
            // exists to avoid.
            aria-hidden="true"
            style={{ width: box, height: box }}
            // The same silhouette as the identicon it is standing in for: a placeholder that
            // changed shape when the first poll landed would be a second thing moving on screen,
            // and the whole point of this placeholder is that it never becomes another drawing.
            className={`flex items-center justify-center rounded-control bg-(--color-surface-sunken) font-medium text-(--color-ink-muted) ${text}`}
          >
            {initialOf(label)}
          </span>
        ) : (
          <Identicon seed={seed} box={box} />
        )}
      </span>
      {/*
        The strip rides under the avatar wherever there is room for 24 px. At `micro` and `sm` the
        avatar is already narrower than the strip, and a strip wider than the thing it belongs to
        would read as a separate element rather than as an underline.

        It is skipped entirely while the seed is unknown: a strip drawn from a placeholder would
        be a pattern derived from nothing, and it would change once the real fingerprint arrived —
        the very mutation the placeholder exists to prevent.
      */}
      {strip && seed !== undefined && (
        <ProofStrip fingerprint={seed} scale="micro" verification={proof} rejected={rejected} />
      )}
    </span>
  );
}
