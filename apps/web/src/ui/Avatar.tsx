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

export type AvatarSize = "micro" | "sm" | "md" | "ml" | "lg";

/** Pixel sizes, and whether the box is tall enough for a 24 px strip to sit under it. */
const SIZES: Record<AvatarSize, { box: number; strip: boolean; text: string }> = {
  micro: { box: 20, strip: false, text: "text-[0.6rem]" },
  sm: { box: 24, strip: false, text: "text-[0.65rem]" },
  md: { box: 32, strip: true, text: "text-xs" },
  /**
   * The step between "an icon beside a name" and "a portrait".
   *
   * `md` at 32px reads as a mark next to something else; `lg` at 64px dominates a 288px column.
   * 40 is the size `components/Messages.tsx` has been faking from a call site since the thread
   * gained one avatar per author — its comment says plainly that adding a step here is the right
   * fix, and this is that step. That override can go the next time somebody is in the file.
   *
   * `strip: false`, unlike `md` and `lg`. The proof strip belongs where verification is the
   * subject; under a face in a row of names it is a pattern nobody reads, and it is the reason
   * `Messages.tsx` reached for `sm` and resized it rather than taking `md`.
   */
  ml: { box: 40, strip: false, text: "text-sm" },
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
      /*
       * The grid inset inside the disc rather than filling it, which is what makes a round
       * identicon legible.
       *
       * Drawn edge to edge and then clipped to a circle, the cells around the rim were cut into
       * arcs of varying size: a shape built to be taken in as one object arrived as a jagged
       * border, different on every account for reasons having nothing to do with the fingerprint.
       * That was the noise — the cropping, not the colour. It also destroyed the mirror symmetry
       * `lib/proofstrip.ts` goes out of its way to produce, on the grounds that "an asymmetric
       * scatter reads as noise, whereas a symmetric one reads as a shape".
       *
       * A square fits inside a circle at 1/√2 of its diameter, so a 5×5 grid needs a viewBox of
       * 5√2 ≈ 7.07 to clear the rim. 7.4 rounds that up with a hair to spare, leaving a ring of
       * plain surface around a grid where every cell is whole.
       */
      viewBox={`${-(7.4 - GRID_SIZE) / 2} ${-(7.4 - GRID_SIZE) / 2} 7.4 7.4`}
      width={box}
      height={box}
      className="rounded-(--radius-pill) bg-(--color-surface-sunken)"
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

/**
 * A group, as the faces in it.
 *
 * # Tiles and not a merged drawing
 *
 * A group used to be one identicon seeded from its id: a shape that identified the room and said
 * nothing about who was in it. Reading a rail is mostly asking "who is this with", and a picture
 * that cannot answer makes the name below it do all the work.
 *
 * # Flat hue per tile, and why the grid is dropped here
 *
 * At `md` the avatar is 32px, so a quarter is 16px, and a 5×5 grid inside that is roughly three
 * pixels a cell — which is the mush this component just spent a change getting rid of. Each tile
 * is therefore the member's derived hue as a plain field. The hue is what separates two accounts
 * at a glance anyway; the grid is what separates two accounts *on inspection*, and a quarter of a
 * 32px circle is not a place anybody inspects.
 *
 * # Order is the caller's
 *
 * Whatever order it is handed, it draws — so the caller can put the reader's own face first and
 * still guarantee stability by sorting the rest. Sorting here would have buried that choice, and
 * leaving it to the poll would let the tiles rearrange between two renders of an unchanged group.
 *
 * What this does not solve: the drawing changes when the membership does, and it changes once
 * more on the first poll after a cold start, when the members arrive and the seeded fallback
 * gives way to them. `Avatar`'s note argues that a mutating identicon teaches the reader that
 * these drawings move on their own, which is true and is why a *person's* never does. A group has
 * no key of its own to vouch for, so the lesson has nothing here to spoil.
 */
function Mosaic({ members, box }: { members: readonly string[]; box: number }) {
  const shown = members.slice(0, 4);
  const extra = members.length - shown.length;

  // Two members split the circle vertically; three give the first half and stack the other two.
  // Anything more is a quarter each. Expressed as grid areas so the SVG stays one shape.
  const half = box / 2;

  /**
   * The seam between tiles, and it is not decoration.
   *
   * Hues are derived from fingerprints and land anywhere on the circle, so two members routinely
   * come out a few degrees apart — the first group this was tried on gave 246° and 220°, two
   * blues, and the mosaic rendered as one flat disc. A gap separates the tiles whatever colours
   * they happen to be, which a border tinted from the fill could not.
   *
   * It shows the SVG's own `surface-sunken` background rather than a painted line, so the seam
   * stays right against a hovered row and a selected one without knowing what it sits on.
   */
  const seam = Math.max(1, box * 0.06);

  const inset = (x: number, y: number, w: number, h: number, fill: string) => ({
    fill,
    x: x + (x > 0 ? seam / 2 : 0),
    y: y + (y > 0 ? seam / 2 : 0),
    w: w - (x > 0 ? seam / 2 : 0) - (x + w < box ? seam / 2 : 0),
    h: h - (y > 0 ? seam / 2 : 0) - (y + h < box ? seam / 2 : 0),
  });

  const tiles = shown.map((seed, index) => {
    const { cells, hue } = identicon(seed);
    const fill = `oklch(0.6 0.08 ${hue})`;

    const box2 =
      shown.length === 2
        ? inset(index * half, 0, half, box, fill)
        : shown.length === 3
          ? index === 0
            ? inset(0, 0, half, box, fill)
            : inset(half, (index - 1) * half, half, half, fill)
          : inset((index % 2) * half, Math.floor(index / 2) * half, half, half, fill);

    return { ...box2, cells };
  });

  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox={`0 0 ${box} ${box}`}
      width={box}
      height={box}
      className="rounded-(--radius-pill) bg-(--color-surface-sunken)"
    >
      {tiles.map((tile, index) => {
        /*
         * Each tile carries the member's own drawing, not a flat swatch of their colour: the
         * point of showing four faces is that they are the faces, and a mosaic of plain fields
         * identifies the room without saying who is in it — which is the defect this replaced.
         *
         * The grid is inset inside its tile for the same reason it is inset inside a whole
         * avatar: a tile's outer corner is cut by the disc, and cells clipped into arcs are what
         * made these read as noise. The margin is proportional, so the drawing shrinks with the
         * tile instead of losing its rim.
         */
        const margin = Math.min(tile.w, tile.h) * 0.12;
        const cell = Math.min(tile.w - margin * 2, tile.h - margin * 2) / GRID_SIZE;
        const originX = tile.x + (tile.w - cell * GRID_SIZE) / 2;
        const originY = tile.y + (tile.h - cell * GRID_SIZE) / 2;

        return (
          <g key={index}>
            <rect x={tile.x} y={tile.y} width={tile.w} height={tile.h} fill="var(--color-surface-sunken)" />
            {tile.cells.map((filled, at) =>
              filled ? (
                <rect
                  key={at}
                  x={originX + (at % GRID_SIZE) * cell}
                  y={originY + Math.floor(at / GRID_SIZE) * cell}
                  width={cell}
                  height={cell}
                  fill={tile.fill}
                />
              ) : null,
            )}
          </g>
        );
      })}

      {/* The count of everybody the four tiles do not show. Only where it can be read: at 20 and
          24 pixels a quarter is eight pixels tall, and a numeral in it is a smudge that costs
          more legibility than the fact is worth. */}
      {extra > 0 && box >= 32 && (
        <>
          <rect
            x={half + seam / 2}
            y={half + seam / 2}
            width={half - seam / 2}
            height={half - seam / 2}
            fill="var(--color-surface-sunken)"
          />
          <text
            x={half + half / 2}
            y={half + half / 2}
            textAnchor="middle"
            dominantBaseline="central"
            fontSize={half * 0.55}
            fill="var(--color-ink-muted)"
          >
            +{extra}
          </text>
        </>
      )}
    </svg>
  );
}

export function Avatar({
  seed,
  members,
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
  /**
   * The fingerprints of a group's members, when the caller has them.
   *
   * Two or more draws the mosaic and `seed` is ignored. Fewer falls through to `seed`, which
   * covers both a one-to-one and a group whose members have not arrived yet.
   */
  members?: readonly string[];
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
        {members !== undefined && members.length > 1 ? (
          <Mosaic members={members} box={box} />
        ) : seed === undefined ? (
          <span
            // No derived hue here, deliberately: the placeholder must not look like a drawing
            // that is about to be corrected, or it becomes the mutating identicon this component
            // exists to avoid.
            aria-hidden="true"
            style={{ width: box, height: box }}
            // The same silhouette as the identicon it is standing in for: a placeholder that
            // changed shape when the first poll landed would be a second thing moving on screen,
            // and the whole point of this placeholder is that it never becomes another drawing.
            className={`flex items-center justify-center rounded-(--radius-pill) bg-(--color-surface-sunken) font-medium text-(--color-ink-muted) ${text}`}
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
