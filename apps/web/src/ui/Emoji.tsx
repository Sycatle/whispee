import { useSyncExternalStore } from "react";

import { onlyEmoji, segment } from "@/lib/emoji";
import { revision, symbolOf } from "@/lib/emoji-sprite";
import { cn } from "@/ui/cn";

/**
 * The one place in the tree that knows an emoji is a picture.
 *
 * Everything upstream — `Messages`, `Rail`, the picker — hands over a string and gets back
 * something to render. `lib/emoji.ts` carries the argument for why these are pictures and not a
 * font; `lib/emoji-sprite.ts` carries the argument for why they arrive in seven sheets rather
 * than four thousand files.
 *
 * # There is no fallback to the platform font, and that is the point
 *
 * The previous version rendered `<img src="/emoji/1f600.svg">` and fell back to `<span>{char}</span>`
 * when the file 404'd. Falling back meant the system font, which is exactly what this feature
 * exists to stop using: tofu on a Linux build with no emoji font, three different pictures on
 * three platforms, and the letters "FR" where a peer had sent `🇫🇷`.
 *
 * Two things replace it. The generator refuses to emit a catalogue entry it has no artwork for,
 * so the coverage question is settled at build time instead of being asked of the network. And
 * anything that still escapes — a Unicode release newer than the pinned tag — draws the sheet's
 * neutral placeholder. Never the raw character.
 *
 * # Why the character is still in the DOM
 *
 * `<use>` copies as nothing and announces as nothing. The old `<img alt={char}>` gave us both for
 * free, and losing them would have been the silent cost of this change: selecting a bubble and
 * copying it would have yielded the prose with holes in it, and a screen reader would have read
 * a sentence with the emoji missing.
 *
 * So the character sits beside the drawing in an `sr-only` span. It is clipped, not hidden — it
 * stays in the selection range, so copy works, and it stays in the accessibility tree, so the
 * announcement works. That span is load-bearing; it is not decoration.
 */

export function Emoji({ char, className }: { char: string; className?: string }) {
  // Redraw when a sheet lands. `symbolOf` returns null until then, so without this subscription
  // an emoji that mounted before its sheet arrived would stay an empty box for the rest of the
  // session — the picker's tone sheets being the obvious case.
  useSyncExternalStore(revision.subscribe, revision.getSnapshot);

  const symbol = symbolOf(char);

  return (
    <span
      className={cn(
        // Sized in `em` and not in pixels: an emoji inside a caption should be caption-sized, and
        // the same component serves the bubble, the reply quote and the rail preview. The
        // negative baseline shift is what stops it sitting on top of the line rather than in it.
        "inline-block h-[1.25em] w-[1.25em] align-[-0.25em]",
        className,
      )}
    >
      {/*
        Drawn even while `symbol` is null: the box is already at its final size, so the drawing
        appears in place rather than pushing the rest of the line sideways when the sheet lands.
      */}
      <svg viewBox="0 0 36 36" aria-hidden="true" className="h-full w-full">
        {symbol && <use href={`#${symbol}`} />}
      </svg>
      <span className="sr-only">{char}</span>
    </span>
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
