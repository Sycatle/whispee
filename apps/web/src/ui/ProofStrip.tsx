import { marks, MARK_COUNT } from "@/lib/proofstrip";
import type { VerificationState } from "@/lib/session";

/**
 * The proof strip: the account fingerprint, drawn.
 *
 * Read the header of `lib/proofstrip.ts` before touching this file. The short version: twelve
 * marks are ~19 bits, so **this is a change detector, not a verification device**, and the real
 * comparison stays the hexadecimal one in the detail panel.
 *
 * # Why it is `aria-hidden`
 *
 * Because it is redundant by construction. Every place that shows a strip also shows the handle,
 * and the states the strip encodes — verified, changed, an unattested device — are stated in
 * words next to it by `Verification.tsx`. Announcing "a bar chart of twelve values" to a screen
 * reader would add noise and no information. That redundancy is the only acceptable condition
 * for encoding information visually, and it is a constraint on the *callers*: a strip that ends
 * up somewhere with no text beside it is a bug in that screen, not in this component.
 *
 * # Why an inline SVG and not a canvas or a background image
 *
 * A canvas would need a device-pixel-ratio dance to stay crisp at 2 px tall, and would be blank
 * in a screenshot taken before paint. A background image would mean a `data:` URI built by
 * string concatenation, which is the shape of an injection waiting to happen. Inline `<rect>`s
 * are the boring answer and cost nothing.
 */

/** Marks are 2 units wide with a 1-unit gutter: a fixed pitch, so the eye compares positions. */
const MARK_WIDTH = 2;
const MARK_GUTTER = 1;
const STRIP_WIDTH = MARK_COUNT * MARK_WIDTH + (MARK_COUNT - 1) * MARK_GUTTER;

/**
 * Vertical units. Ten rather than three, so a level is a proportion rather than a pixel count
 * and the same numbers survive being drawn 2 px tall and 24 px tall.
 */
const STRIP_HEIGHT = 10;
const LEVEL_HEIGHTS = [3, 6, STRIP_HEIGHT];

export type ProofScale = "micro" | "inline" | "detail";

/**
 * The three scales, and what each is for.
 *
 * - `micro` (24x2) sits under every avatar and says nothing in the nominal case: it reads as an
 *   underline. It is the one that makes the strip ambient rather than a feature.
 * - `inline` (48x8) sits in the conversation header beside the handle and says "this identity
 *   has a shape".
 * - `detail` (full width x 24) sits in the right-hand panel above the hex, where the pattern and
 *   the digits are read together during a manual comparison.
 */
const SCALES: Record<ProofScale, { width: string; height: number }> = {
  micro: { width: "24px", height: 2 },
  inline: { width: "48px", height: 8 },
  detail: { width: "100%", height: 24 },
};

/**
 * The palette, and the one colour that is missing from it on purpose.
 *
 * `accent` is not here. It is rationed to selection, focus and "you are here"; spending it on an
 * ornament that appears next to every single name would spend the whole budget in one screen and
 * leave nothing to mean "this is the thing you are pointing at".
 */
type ProofTone = "attested" | "verified" | "changed" | "unattested";

const TONES: Record<ProofTone, string> = {
  /** Automatically attested, nothing to say. Subtle enough to be taken for a rule. */
  attested: "text-(--color-border-subtle)",
  /** Compared by hand, out of band. The only state that earns a colour for good news. */
  verified: "text-(--color-ok)",
  /** The fingerprint moved. Same colour, same moment, in all three scales at once. */
  changed: "text-(--color-danger)",
  /** An unattested device was presented, which is not a subtlety. */
  unattested: "text-(--color-danger)",
};

function toneOf(verification: VerificationState | undefined, rejected: boolean): ProofTone {
  // A rejected device outranks everything else: the fingerprint can be perfectly stable while
  // the account serves a device whose attestation does not check out.
  if (rejected) return "unattested";
  if (verification?.status === "changed") return "changed";
  if (verification?.status === "verified") return "verified";
  return "attested";
}

function Marks({
  fingerprint,
  top,
  height,
  full,
}: {
  fingerprint: string;
  top: number;
  height: number;
  full: boolean;
}) {
  const levels = marks(fingerprint);
  return (
    <>
      {levels.map((level, index) => {
        // `full` flattens every mark to full height. That is the unattested case: the strip stops
        // being a pattern and becomes a solid block, which is the visual equivalent of raising
        // one's voice.
        const fraction = full ? 1 : LEVEL_HEIGHTS[level] / STRIP_HEIGHT;
        const drawn = Math.max(height * fraction, 1);
        return (
          <rect
            // The index is the identity here: a mark *is* its position in the strip, and two
            // marks at the same position are the same mark whatever their level.
            key={index}
            x={index * (MARK_WIDTH + MARK_GUTTER)}
            y={top + height - drawn}
            width={MARK_WIDTH}
            height={drawn}
            fill="currentColor"
          />
        );
      })}
    </>
  );
}

export function ProofStrip({
  fingerprint,
  scale = "micro",
  verification,
  rejected = false,
  className,
}: {
  /** The account fingerprint, as produced by `crypto.accountFingerprint`. */
  fingerprint: string;
  scale?: ProofScale;
  verification?: VerificationState;
  /** True when the account presented a device whose attestation did not verify. */
  rejected?: boolean;
  className?: string;
}) {
  const tone = toneOf(verification, rejected);
  const { width, height } = SCALES[scale];
  const previous = verification?.status === "changed" ? verification.previous : null;

  /**
   * The changed case stacks both patterns: the old one struck through above, the new one solid
   * below. That is what makes the change *comparable* rather than merely announced — you can see
   * that the shape is genuinely different and not just recoloured.
   *
   * It is skipped at `micro`, where the box is two pixels tall and two stacked one-pixel rows
   * would be a smudge. There the colour alone carries it, and the rail row that shows the strip
   * also shows the warning `Verification.tsx` renders.
   */
  const stacked = previous !== null && scale !== "micro";
  const band = stacked ? (STRIP_HEIGHT - 2) / 2 : STRIP_HEIGHT;

  return (
    <svg
      aria-hidden="true"
      focusable="false"
      data-verification={tone}
      viewBox={`0 0 ${STRIP_WIDTH} ${STRIP_HEIGHT}`}
      // Non-uniform: the box is imposed by the layout, not by the strip's natural ratio. Every
      // mark and every gutter stretches by the same factor, so the pitch stays even, which is the
      // only property the reading depends on.
      preserveAspectRatio="none"
      style={{ width, height: `${height}px` }}
      className={`${TONES[tone]} shrink-0${className ? ` ${className}` : ""}`}
    >
      {stacked && previous !== null && (
        <>
          <g opacity="0.55">
            <Marks fingerprint={previous} top={0} height={band} full={false} />
          </g>
          <rect x={0} y={band / 2 - 0.4} width={STRIP_WIDTH} height={0.8} fill="currentColor" />
        </>
      )}
      <Marks
        fingerprint={fingerprint}
        top={stacked ? STRIP_HEIGHT - band : 0}
        height={band}
        full={tone === "unattested"}
      />
    </svg>
  );
}
