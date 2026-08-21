import { useState } from "react";

import { fileOf, onlyEmoji, segment } from "@/lib/emoji";
import { cn } from "@/ui/cn";

/**
 * The one place in the tree that knows an emoji is a picture.
 *
 * Everything upstream — `Messages`, `Rail`, the picker — hands over a string and gets back
 * something to render. `lib/emoji.ts` carries the argument for why these are images and not a
 * font; the short version is that no colour font format renders Fluent on WebKitGTK, which is
 * the engine behind our own Linux build.
 *
 * # Why the fallback is per-image rather than per-catalogue
 *
 * Fluent draws 1,595 emoji and Unicode defines more, so some strings have no artwork. The
 * obvious design consults the catalogue before rendering — and it is wrong twice: the catalogue
 * is 185 kB loaded asynchronously, so a bubble would flash unstyled text on every mount, and a
 * copy of the coverage list in code would drift from the generated tree the day someone bumps
 * the pinned commit.
 *
 * `onError` answers the same question from the only source that cannot be stale: whether the
 * file is there. The cost is one failed request per uncovered emoji per session, and the answer
 * is cached in `MISSING` so it is not paid twice.
 *
 * # What this does not solve
 *
 * **Country flags.** Microsoft ships none: `🇫🇷` finds no artwork and falls back to the platform,
 * which on Windows draws the letters "FR". Nothing here can fix that — it needs artwork from
 * somewhere, which is a decision about mixing two emoji sets, not a rendering detail.
 */

/**
 * Sequences that have already 404'd this session.
 *
 * Module scope rather than state: a thread of two hundred messages can mention the same
 * uncovered emoji thirty times, and thirty failed requests for one answer is thirty too many.
 * Never invalidated, because the generated tree cannot change while the page is open.
 */
const MISSING = new Set<string>();

export function Emoji({ char, className }: { char: string; className?: string }) {
  // The failing character rather than a boolean: React reuses this component across renders when
  // it keeps its position in a list, so a message whose text changed would inherit the previous
  // emoji's verdict and refuse to draw artwork that exists.
  const [failed, setFailed] = useState<string | null>(null);

  // The raw character, drawn by whatever font the platform has. Not a great outcome, but the
  // only honest one: a placeholder box would hide that something was said.
  if (failed === char || MISSING.has(char)) return <span className={className}>{char}</span>;

  return (
    <img
      src={fileOf(char)}
      // The character itself, so that selecting a bubble and copying it yields the emoji rather
      // than a shortcode or a gap — and so a screen reader announces something a person can
      // repeat. This is the whole reason the substitution stays invisible to the user.
      alt={char}
      draggable={false}
      loading="lazy"
      onError={() => {
        MISSING.add(char);
        setFailed(char);
      }}
      className={cn(
        // Sized in `em` and not in pixels: an emoji inside a caption should be caption-sized, and
        // the same component serves the bubble, the reply quote and the rail preview. The
        // negative baseline shift is what stops it sitting on top of the line rather than in it.
        "inline-block h-[1.25em] w-[1.25em] align-[-0.25em]",
        className,
      )}
    />
  );
}

/**
 * A message, with its emoji drawn.
 *
 * The prose stays as text nodes, which is what keeps `whitespace-pre-wrap` and `wrap-anywhere`
 * working on the bubble: wrapping each run in a `<span>` would make every run an unbreakable
 * inline box, and a long word would overflow instead of breaking.
 *
 * `big` renders a message made of nothing but emoji at three times the size. Every messenger
 * does it, and the reason is legible: an emoji sent as a whole reply is the reply, and at body
 * size it reads as a typo.
 */
export function EmojiText({ text, big = false }: { text: string; big?: boolean }) {
  const large = big && onlyEmoji(text);

  return (
    <span className={cn(large && "text-[2.5em] leading-tight")}>
      {segment(text).map((run, index) =>
        "emoji" in run ? (
          // The index is the position in the run list, which is derived from the text: two
          // identical emoji in one message are genuinely two different runs, and nothing in a
          // run list is reordered.
          <Emoji key={index} char={run.emoji} />
        ) : (
          run.text
        ),
      )}
    </span>
  );
}
