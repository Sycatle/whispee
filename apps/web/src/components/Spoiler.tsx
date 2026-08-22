import { type ReactNode, useState } from "react";

import { cn } from "@/ui/cn";

/**
 * Text somebody chose to hide until it is asked for.
 *
 * # Hidden means absent, not painted over
 *
 * The obvious implementation is `color: transparent` or a block laid on top, and both are
 * theatre: the words stay in the accessibility tree, a screen reader announces them, and a
 * drag-select copies them out. Whoever wrote `||…||` did not ask for the text to be hard to read.
 *
 * So the children are simply not rendered while it is closed. What stands in for them is a run of
 * blocks of **fixed** length, and the fixed part is the point: a mask that matched the text would
 * say how long the hidden sentence is, which is a fact about the content and not about the
 * control. Most products leak it. There is no reason to.
 *
 * What it costs: the message reflows when the spoiler opens, because six blocks are rarely the
 * width of what they were covering. A jump on a deliberate click is a smaller price than telling
 * everybody who did not click how much there was to read.
 *
 * # A button, redressed to `inline`
 *
 * A user agent makes `<button>` an `inline-block`, and `components/RichText.tsx` explains what
 * that costs: an atomic inline box cannot be broken across lines, so a spoiler holding a sentence
 * would push its whole width to the next line rather than wrapping inside the column. `inline`
 * puts it back in the text flow.
 *
 * A real `<button>` and not a `<span role="button">` for what comes with it and would otherwise
 * have to be written by hand: focus, Enter and Space, and a name in the accessibility tree.
 *
 * # It is a tab stop, unlike the mention chip beside it
 *
 * `MentionText` deliberately keeps its chips out of the tab order, because the profile card they
 * open is reachable from the author's face and from the member list. A spoiler has no second
 * route: not reaching it from the keyboard means not reading the message. The cost is that a
 * message with three spoilers adds three stops to a list whose roving tabindex exists to have
 * one — and that is the right way round.
 *
 * # There is no closing it again
 *
 * Deliberate, and the reason is that the text has been read. A control that re-hides what its
 * owner has already seen is tidying, not privacy, and it invites a second click that undoes
 * nothing.
 */

/** The block that stands in for a hidden character. Full block, so the run reads as one bar. */
const MASK = "█";

export function Spoiler({ children }: { children: ReactNode }) {
  const [shown, setShown] = useState(false);

  if (shown) return <>{children}</>;

  return (
    <button
      type="button"
      onClick={() => setShown(true)}
      aria-expanded={false}
      aria-label="Spoiler, activate to reveal"
      className={cn(
        // `inline` and not the user agent's `inline-block` — see the note above.
        "inline cursor-pointer rounded-[0.25rem] align-baseline",
        "bg-(--color-ink)/15 text-transparent select-none",
        "hover:bg-(--color-ink)/20",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent)",
        "transition-colors duration-(--duration-quick) ease-out motion-reduce:transition-none",
      )}
    >
      {/* `aria-hidden` because the button already has a name, and the blocks would otherwise be
          announced as a wall of glyphs. `text-transparent` on top of that so the mask does not
          have to be a colour anybody chose — the background is the whole of what is seen. */}
      <span aria-hidden="true">{MASK.repeat(6)}</span>
    </button>
  );
}
