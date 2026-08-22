import { cn } from "./cn.ts";

/**
 * Three dots that say somebody is typing.
 *
 * # Why this is a picture and not a sentence
 *
 * It used to be "Alice is typing…", written twice — once under the thread and once under the
 * title in the header. Prose costs a line, has to be pluralised, has to be truncated when four
 * people are at it, and reads as a message in a thread made of messages. Beside an avatar, three
 * dots say the same thing in the width of a word and belong to the person rather than to the
 * conversation.
 *
 * # It says nothing to a screen reader, so something else has to
 *
 * An animation has no accessible name and no role. Everything here is `aria-hidden`, and every
 * caller is expected to carry the sentence separately in text — `sr-only` inside a live region
 * for the thread, and a plain caption in the header. That is not a nicety: the dots are the
 * *only* signal a sighted reader gets, so dropping the text would remove the feature entirely
 * for everybody else.
 *
 * # Reduced motion stops the dots and keeps them
 *
 * `motion-reduce:animate-none` leaves three still dots, which read as "typing" beside an avatar
 * and occupy the same box. Hiding them would take the information from the people who asked for
 * less movement rather than less content.
 *
 * The keyframe lives in `index.css` and is the only one in this project; its own comment argues
 * why a transition could not do this job.
 */

/** Delay per dot, staggering the rise into a beat rather than a blink. */
const STAGGER = [0, 160, 320] as const;

export function Typing({
  size = "sm",
  className,
}: {
  /** `sm` beside a name or inside a badge, `md` beside a full-size avatar under a thread. */
  size?: "sm" | "md";
  className?: string;
}) {
  const dot = size === "md" ? "size-1.5" : "size-1";

  return (
    <span
      // Nothing here is announced. The caller owns the words — see the note above.
      aria-hidden="true"
      className={cn("inline-flex items-center", size === "md" ? "gap-1" : "gap-0.5", className)}
    >
      {STAGGER.map((delay) => (
        <span
          key={delay}
          style={{ animationDelay: `${delay}ms` }}
          className={cn(
            dot,
            "rounded-pill bg-current",
            // Written out rather than through a `duration-*` utility: this is an animation, and
            // the tokens in `index.css` are transition durations. The note there explains why
            // this one is allowed its own timing.
            "animate-[typing-dot_1.2s_ease-in-out_infinite] motion-reduce:animate-none",
          )}
        />
      ))}
    </span>
  );
}
