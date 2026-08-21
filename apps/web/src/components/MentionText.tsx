import { Fragment } from "react";

import { MiniProfile } from "@/components/MiniProfile";
import { runs } from "@/lib/mention";
import { compactNameOf, formatHandle } from "@/lib/naming";
import type { ConversationView } from "@/lib/session";
import { useNames } from "@/state/names";
import { useSession } from "@/state/SessionProvider";
import { cn } from "@/ui/cn";
import { EmojiText } from "@/ui/Emoji";

/**
 * A message, with the people it addresses drawn as people.
 *
 * # Why this wraps `EmojiText` rather than replacing it
 *
 * `EmojiText` states the constraint it lives under: prose stays in text nodes, because wrapping
 * each run in a `<span>` makes every run an unbreakable inline box and a long word then overflows
 * instead of breaking. That is still true, so the prose between two mentions goes through it
 * untouched and keeps `whitespace-pre-wrap` and `wrap-anywhere` working.
 *
 * A mention is the exception that costs nothing: `@charlie8295` is one token, and a token that
 * refuses to break in the middle is the correct rendering of a name anyway.
 *
 * # It resolves, it does not substitute
 *
 * The text on the wire says `@charlie8295`. What is drawn is `@Charlie`, through the same
 * `compactNameOf` every other name on the screen goes through — so a display name that could be
 * mistaken for another member's collapses back to the handle here exactly as it does above a
 * bubble. A mention is a claim about *who*, and it is the one place where getting the wrong
 * person would matter most.
 *
 * The resolution happens at render, which is what keeps an old message correct after its subject
 * renames themselves — and what makes an `@handle` naming nobody in this room stay as prose,
 * since `lib/mention.ts` only matches against the members it is given.
 */
export function MentionText({
  text,
  among,
  view,
  big = false,
}: {
  text: string;
  /** The handles this thread can address. Anything else in the text stays prose. */
  among: readonly string[];
  /** The conversation the profile card hangs off. */
  view: ConversationView;
  big?: boolean;
}) {
  const session = useSession();
  const names = useNames();

  const parts = runs(text, among);

  // Nothing addressed: hand the whole string over unchanged. Not merely an optimisation — `big`
  // asks `EmojiText` whether the message is *only* emoji, and a message split into runs would
  // answer that question one fragment at a time and enlarge the fragments individually.
  if (parts.length === 1 && "text" in parts[0]!) {
    return <EmojiText text={text} big={big} />;
  }

  return (
    <>
      {parts.map((run, index) => (
        <Fragment key={index}>
          {"text" in run ? (
            <EmojiText text={run.text} />
          ) : (
            <MiniProfile handle={run.handle} view={view}>
              <button
                type="button"
                // Out of the tab order on purpose. The row is one stop of the thread's roving
                // tabindex, and a message addressing four people would otherwise be five stops —
                // the exact cost that roving exists to remove. The card is reachable from the
                // author's face and from the member list, which are the deliberate routes to it.
                tabIndex={-1}
                className={cn(
                  "rounded-[0.25rem] px-[0.15em] font-medium hover:underline",
                  run.handle === session.handle
                    ? // Addressed to us: a fill, so it can be found by scanning rather than by
                      // reading. The row carries its own mark as well — see `Messages.tsx` — and
                      // the two say different things: the row says this message is for you, the
                      // chip says which word in it is your name.
                      "bg-(--color-accent)/20 text-(--color-accent)"
                    : "text-(--color-accent)",
                )}
              >
                {/* Through `formatHandle`, which is the one place in the tree that writes the
                    sigil — the resolved name is stripped of a leading one first, since
                    `compactNameOf` returns the handle already sigilled when it decides a display
                    name is not safe to show. */}
                {formatHandle(stripSigil(compactNameOf(run.handle, names, among)))}
              </button>
            </MiniProfile>
          )}
        </Fragment>
      ))}
    </>
  );
}

/** Drops a leading `@`, so that re-applying the sigil cannot produce `@@charlie8295`. */
function stripSigil(name: string): string {
  return name.startsWith("@") ? name.slice(1) : name;
}
