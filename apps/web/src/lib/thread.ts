/**
 * The shape of a thread, resolved before anything is drawn.
 *
 * # Why this left the component
 *
 * `Messages.tsx` used to decide, in the middle of its own render, whether a message opened a day,
 * continued the previous turn, or sat just past the unread boundary. Each answer was read off
 * `visible[index - 1]`, which is correct for exactly as long as the component renders the whole
 * list from the top. The comment at the top of that file says virtualisation is deliberately not
 * there yet, and that windowing "belongs in a module of its own alongside the grouping rules it
 * has to respect" — this is that module, arriving first. A windowed thread hands `layout` the
 * whole list and renders a slice of what comes back; the grouping stays right because it was
 * never computed from what happened to be on screen.
 *
 * The second reason is that a rule computed during a render can only be checked by rendering.
 * These are the rules that decide whether a thread reads as a conversation or as a log, and they
 * are quietly wrong at a day boundary or at the top of a thread if nobody checks. Here they are
 * an array in, an array out, and `node --test` can ask them anything.
 *
 * # What it deliberately does not do
 *
 * It does not sort, and it does not filter. Ordering is `seq` and is decided in `session.ts`;
 * reactions are annotations on other messages rather than lines of their own, and folding them
 * away needs the reaction map the caller is already building. Doing either here would mean this
 * module had an opinion about what a message *is*, and it only has an opinion about where the
 * seams between them fall.
 *
 * It also does not know about the outbox. A pending message has no `seq` — that is the whole
 * reason it is kept apart — so it cannot be positioned relative to a boundary expressed as one.
 */
import { continues, opensDay } from "./datetime.ts";
import type { Content } from "./content.ts";

/**
 * The little a thread needs to know about a message in order to place it.
 *
 * Structural rather than an import of `Message`: this module is pure, and typing it against the
 * session's shape would drag the whole conversation graph into a test that wants three objects.
 */
export interface Placed {
  seq: number;
  sentAt?: number;
  mine: boolean;
}

/** One line of the thread, with every seam already decided. */
export interface Row<M extends Placed> {
  /**
   * The React key for this line.
   *
   * Derived from `seq` and never from the message object. The session mutates its message list in
   * place — the same array grows and the same objects are rewritten as receipts arrive — so a key
   * taken from a reference, or from a position in the array, names a slot rather than a message.
   * `seq` is assigned by the server, never reused within a conversation, and never rewritten,
   * which makes it the only stable name a line has. It is prefixed rather than used bare so that
   * nothing downstream is tempted to parse a key back into a number.
   */
  key: string;
  message: M;
  /**
   * The stamp this line's date heading should be drawn from, or `undefined` for no heading.
   *
   * The stamp rather than a boolean, because the caller needs the value to label the heading with
   * and reaching back into the message for it is how the two get out of step.
   */
  opensDay: number | undefined;
  /** True when this line is a continuation of the turn above: same author, same day, close by. */
  continues: boolean;
  /** True when the "new messages" rule belongs immediately above this line. */
  opensUnread: boolean;
}

export interface Seams<M extends Placed> {
  /**
   * The author, as grouping understands identity.
   *
   * A function rather than a field on the message, because the caller's notion of identity is not
   * the envelope's: `Messages.tsx` folds all of our own devices onto one handle, so that a phone
   * and a laptop do not announce themselves to each other down our own thread.
   */
  authorOf: (message: M) => string | null;
  /**
   * The last sequence number the reader had already seen when they arrived.
   *
   * Passed in rather than read from the view, because the caller freezes it on open: the cursor
   * moves to the end the moment the thread is on screen, and a line drawn from the live value
   * would appear and vanish in the same frame.
   */
  readCursor: number;
}

/**
 * Resolve every seam in a thread, in one pass over the whole list.
 *
 * The messages are expected in `seq` order with reactions already folded away — see above for why
 * neither is done here.
 */
export function layout<M extends Placed>(messages: readonly M[], seams: Seams<M>): Row<M>[] {
  return messages.map((message, index) => {
    const before = index === 0 ? undefined : messages[index - 1];

    return {
      key: `seq:${message.seq}`,
      message,
      opensDay: opensDay(message.sentAt, before?.sentAt) ? message.sentAt : undefined,
      continues:
        before !== undefined &&
        continues(
          seams.authorOf(message),
          message.sentAt,
          seams.authorOf(before),
          before.sentAt,
        ),
      /**
       * The first message past the boundary, and only if something precedes it.
       *
       * Three conditions and each one earns its place. `!mine`, because a rule announcing that we
       * have not read our own message is nonsense. `before !== undefined`, because a line above
       * the very first message of a thread marks nothing — there is no "before" for it to
       * separate from. And the pair of comparisons rather than a single one, so that the rule
       * lands on the *boundary* and not on every message above the cursor.
       */
      opensUnread:
        !message.mine &&
        before !== undefined &&
        message.seq > seams.readCursor &&
        before.seq <= seams.readCursor,
    };
  });
}

/** The little `textOf` needs: a number to look up and a body to summarise. */
export interface Quotable {
  seq: number;
  content: Content;
}

/**
 * What a quote shows of the message it points at.
 *
 * The text for anything textual, the file name for an attachment, an ellipsis for a body that has
 * no reading — control traffic that reached a quote is a bug elsewhere, and printing its shape
 * would be worse than saying nothing. A sequence number that matches nothing we hold says so in
 * words: a message far up an unhydrated history is genuinely unavailable, and a blank would read
 * as an empty message rather than as a missing one.
 *
 * `Conversation.tsx` holds a second copy of this rule under the name `excerptOf`, with a comment
 * arguing that the two live on opposite sides of the thread. That argument was about a helper
 * closed over one component's message list; this one takes the list as an argument, so the reply
 * banner can import it instead. That change belongs to whoever next opens that file.
 */
export function textOf(messages: readonly Quotable[], seq: number): string {
  const target = messages.find((message) => message.seq === seq);
  if (!target) return "message unavailable";

  const { content } = target;
  if (content.kind === "text" || content.kind === "reply") return content.text;
  if (content.kind === "attachment") return content.ref.name;
  return "…";
}
