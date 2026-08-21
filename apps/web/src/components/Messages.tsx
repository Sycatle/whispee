/**
 * Message thread: lines, folded reactions, quotes, read state.
 *
 * Split out of `page.tsx` once reactions turned a flat list into a tree: a reaction is not a
 * line, it is an annotation on another line, and the same goes for the quote in a reply.
 * Keeping that logic in the page render mixed the app layout with the shape of a conversation.
 *
 * # Lines rather than bubbles, and what that costs
 *
 * The thread used to align our own messages right and everybody else's left, inside bubbles
 * capped at 75% of the pane. Alignment is a cheap way to say who is speaking and an expensive way
 * to lay out text: it spends a quarter of the width on nothing, it ragged-edges every paragraph
 * against a different margin, and it gives a group thread two columns for however many people are
 * in it. So authorship moved off the axis and onto the line itself — a fixed lane on the left
 * holding the avatar, the name and the hour spelled out at the top of each turn, and the text
 * running the full width underneath.
 *
 * What that costs is the instant read of "mine" that alignment gave for free, and it is not paid
 * back. A tint over our own rows was tried and removed: at rest it striped the conversation into
 * bands, and a column of text asks to be read, not parsed. The avatar and the name identify every
 * turn including ours, which is the same answer everybody else's messages get.
 *
 * No row carries a fill at rest. One appears under the pointer, where it has something to say —
 * it is the line the buttons in the corner belong to.
 *
 * # It reads the session rather than receiving it
 *
 * `session`, `onChanged` and `onError` used to arrive as props. They are now `useSession()`,
 * `useBump()` and `useReport()` — the rule at the top of `state/SessionProvider.tsx` and the
 * reason for it: a mutable object handed down a prop is only as fresh as its parent's render
 * schedule. `view` stays a prop because the shell decides which conversation this is, and
 * `onReplyTo` stays a prop because the composer that answers it lives in the parent.
 *
 * # What is deliberately not here
 *
 * Virtualisation. Every message in the thread is in the DOM, and a thread of ten thousand is
 * ten thousand nodes. The windowing belongs in a module of its own alongside the grouping rules
 * it has to respect; anticipating it here would only produce a shape to undo. Half of that module
 * now exists: `lib/thread.ts` resolves the day headings, the grouping and the unread line over the
 * whole list before anything is drawn, so a window that renders a slice would still get them
 * right. What is left is the scrolling.
 */
import { Fragment, useEffect, useRef, useState } from "react";

import { Attachment } from "@/components/Attachment";
import { EmojiDrawer } from "@/components/EmojiPicker";
import { dayLabel, timeOf } from "@/lib/datetime";
import { COMPOSER_ID } from "@/components/ids";
import { compactNameOf } from "@/lib/naming";
import type { ConversationView } from "@/lib/session";
import { nextExpiry } from "@/lib/signals";
import { layout, textOf } from "@/lib/thread";
import { useRoving } from "@/lib/useRoving";
import { useNames } from "@/state/names";
import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { Avatar } from "@/ui/Avatar";
import { Banner } from "@/ui/Banner";
import { cn } from "@/ui/cn";
import { Emoji, EmojiText } from "@/ui/Emoji";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Menu } from "@/ui/Menu";
import { Spinner } from "@/ui/Spinner";
import { Tooltip } from "@/ui/Tooltip";

/**
 * The palette offered on hover, before this account has a history of its own.
 *
 * Five and not more: the bar hangs off the corner of a line and every extra button pushes the
 * overflow menu further from the thumb. Once somebody has reacted a few times these are replaced
 * by `preferences.recentEmojis`, which is the same idea with the choosing done by the person
 * using it rather than by us. The full set is a keypress away in the picker beside them.
 *
 * Two of these carry an invisible `FE0F` and it is not an accident: `👍️` and `❤️` have a text
 * presentation as well as an emoji one, so the catalogue spells them fully qualified. Writing the
 * bare codepoint here would make `withoutTone("👍")` and `withoutTone("👍️")` two different
 * entries in the recents list — the same emoji, remembered twice, one from this row and one from
 * the picker.
 */
const EMOJIS = ["👍️", "❤️", "😂", "😮", "🙏"];

/**
 * The lane on the left of every line: the avatar at the top of a turn, the hour under it.
 *
 * 56px is 40 for the avatar plus 16 of air, and it is the one measurement the whole thread is
 * built on — the name, the text, the quote and the reactions all start at its right edge, so a
 * line that got it wrong would step sideways out of the column.
 *
 * **This should be a `--spacing-lane` token in `index.css`,** and it is written as a scale value
 * here only because that file is not this change's to edit. Whoever adds the token has to bring
 * three things onto it at the same time: this lane, the avatar size below, and the reply banner
 * in `Conversation.tsx`, whose quote should line up with the quotes inside the thread rather than
 * with the composer.
 */
const LANE = "w-14 shrink-0";

/**
 * How the avatar is made to measure 40px.
 *
 * `ui/Avatar.tsx` offers 20, 24, 32 and 64, and 40 is not among them. Adding a step is the right
 * fix and belongs in that file; until then this is a call-site override, and it overrides two
 * different things because the component sizes its two states differently — the identicon by SVG
 * `width`/`height` attributes, which any class beats, and the neutral placeholder by an inline
 * `style`, which nothing beats without `!`. Both carry `aria-hidden`, which is what makes one
 * selector enough.
 *
 * `sm` and not `md` is still a decision and not a leftover: the proof strip rides under an `md`
 * avatar, and the argument against putting it in the thread is the one written beside the avatar
 * below.
 */
const AVATAR_40 = "[&_[aria-hidden]]:size-10! [&_[aria-hidden]]:text-body";

export function Messages({
  view,
  onReplyTo,
}: {
  view: ConversationView;
  onReplyTo: (seq: number) => void;
}) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const names = useNames();
  const bottom = useRef<HTMLDivElement>(null);

  /**
   * Whether the reader is at the live end of the thread.
   *
   * Kept from the scroll event rather than measured when a message arrives, and the difference
   * matters: by the time the effect runs, the new line is already in the DOM and has pushed the
   * bottom further away, so a measurement taken then cannot tell "was at the end" from "is one
   * message behind". Read at the moment the user last moved, the answer is about them.
   */
  const stuck = useRef(true);

  const messages = view.messages.slice().sort((a, b) => a.seq - b.seq);

  // Reactions are pulled out of the thread and attached to their target. An empty emoji removes
  // its author's reaction: the last state is what counts, not the accumulation.
  const reactions = new Map<number, Map<string, string>>();
  for (const message of messages) {
    if (message.content.kind !== "reaction") continue;
    const author = message.mine ? session.handle : (message.sender ?? "unknown");
    const target = reactions.get(message.content.target) ?? new Map<string, string>();
    if (message.content.emoji) target.set(author, message.content.emoji);
    else target.delete(author);
    reactions.set(message.content.target, target);
  }

  const visible = messages.filter((message) => message.content.kind !== "reaction");

  /**
   * The author, as grouping understands it.
   *
   * Our own messages all share one identity whatever device sent them: seeing your own phone and
   * your own laptop announce themselves to each other in your own thread is noise, and the
   * distinction is available in the receipts anyway.
   */
  const authorOf = (message: (typeof visible)[number]) =>
    message.mine ? session.handle : message.sender;

  /**
   * Everybody a line in this thread can be attributed to.
   *
   * `accounts` and `peers` both: `peers` is restored with the conversation while `accounts` waits
   * for the first poll, and somebody who has since been removed is still the author of what they
   * said. This is the `among` every compact name below is checked against, and a rival missing
   * from it is an ambiguity that goes unnoticed.
   */
  const members = [
    ...new Set([...view.accounts.map((a) => a.handle), ...view.peers.map((p) => p.name)]),
  ];

  /**
   * What to call the author of a line, on the one line a turn gives it.
   *
   * This is the site the compact form was written for. The name sits on a single row beside the
   * hour, with no second line to carry a handle underneath, and it is read at a glance rather than
   * studied — so a self-asserted name that another member could be mistaken for is not shown here
   * at all, and both of them fall back to their handle. See the argument at the top of
   * `lib/naming.ts`.
   *
   * A message with no sender keeps "unknown" rather than being given a name: the absence is a
   * fact about the envelope, and there is nobody to name.
   */
  const nameOfAuthor = (handle: string | null) =>
    handle === null ? "unknown" : compactNameOf(handle, names, members);

  /**
   * The fingerprint the author's avatar is drawn from, or `undefined`.
   *
   * `undefined` is a supported answer, not a failure: `Avatar` then draws the neutral
   * placeholder rather than guessing from the handle, which is the whole argument in that file.
   */
  const seedOf = (handle: string | null) => {
    if (handle === null) return undefined;
    // Our own account is not in `view.accounts` — that list is the people on the other side — so
    // the lookup below would miss it and every message we sent would draw the neutral
    // placeholder. It went unnoticed while bubbles put our messages on the right with no avatar
    // at all; one column per author is what made the gap visible.
    if (handle === session.handle) return session.accountFingerprint();
    return view.accounts.find((a) => a.handle === handle)?.fingerprint;
  };

  // Read once for the whole render: `dayLabel` compares calendar days, and asking the clock again
  // per message would let a thread rendered across midnight label two neighbours inconsistently.
  const now = Date.now();

  /**
   * Where the "new messages" line goes, frozen when the conversation opens.
   *
   * Read from a ref rather than from `view.readCursor`, because the effect below moves that
   * cursor to the end the moment the thread is on screen — so a line drawn from the live value
   * would appear and vanish in the same frame. What the reader wants is the boundary as it was
   * when they arrived, staying put while they scroll up to it.
   */
  const boundary = useRef(view.readCursor);
  useEffect(() => {
    boundary.current = view.readCursor;
    // Deliberately keyed on the conversation and nothing else: re-running it when the cursor
    // moves is exactly the disappearing line described above.
  }, [view.key]);

  /**
   * Every seam in the thread, decided in one pass before a single line is drawn.
   *
   * Not a `useMemo`, and that is the rule at the top of `state/SessionProvider.tsx` rather than an
   * oversight: `visible` is rebuilt from a mutating graph on every render, so memoising this would
   * need `useRevision()` in the dependency list to be correct at all — and would be silently
   * wrong the day somebody trimmed the list.
   */
  const rows = layout(visible, { authorOf, readCursor: boundary.current });

  /**
   * The thread as one tab stop.
   *
   * It was eight per message — five quick reactions, the emoji drawer, Reply, and the overflow
   * menu — so crossing twenty messages with Tab took about a hundred and sixty presses. Reaching
   * the fourth message from the top was not hard, it was unreasonable, and the skip link the
   * shell grew only helps whoever wants to leave the list.
   *
   * The message is the unit now: Up and Down move between messages, Right steps into the row of
   * actions, Left or Escape steps back out, Escape again returns to the composer.
   *
   * Where Tab lands is the newest message rather than the oldest, because that is the one on
   * screen — entering the list should not scroll it. The separators (day headings, the "New
   * messages" line) carry no `data-row` and are skipped: they are not places, they are seams.
   *
   * The outbox is deliberately outside the ring. Those lines have no `seq`, which is the whole
   * reason they are kept apart, and their only controls appear when a send has failed. Leaving
   * them out is also what removes the one case where a focused row could vanish underneath the
   * focus: the protocol has no deletion, so a message that is in the ring stays in it.
   */
  const thread = useRoving<HTMLOListElement>(
    rows.map((row) => row.key),
    rows.length === 0 ? null : rows[rows.length - 1].key,
  );

  // The outbox counts: a message the user just wrote appears there first, and not scrolling to it
  // would hide the very thing they are waiting to see.
  //
  // The smooth scroll asks the system first. `prefers-reduced-motion` is set by people for whom
  // motion is a symptom, not a preference, and a thread that slides on every arrival is the most
  // frequent motion in the whole application. Jumping is not a degraded version of it — for them
  // it is the correct one.
  //
  // It follows the arrival only when the reader is at the live end of the thread, or when the
  // arrival is their own. Scrolling unconditionally is what a thread can do while it is only ever
  // read from the bottom; it stops being acceptable the moment the list can hold the focus, since
  // a message from somebody else would then carry the focused line off screen mid-sentence — and
  // it was already wrong for anyone reading back through history with a conversation still
  // running.
  const sent = useRef(view.outbox.length);

  useEffect(() => {
    const mine = view.outbox.length > sent.current;
    sent.current = view.outbox.length;

    if (!mine && !stuck.current) return;

    const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    bottom.current?.scrollIntoView({ behavior: still ? "auto" : "smooth" });
  }, [visible.length, view.outbox.length]);

  // "Read" means **shown to someone**. So it is decided here, in the component that renders the
  // thread — not in the poll loop, which runs even with the window closed.
  //
  // Tab visibility is part of that: a thread rendered in a background tab was delivered, not
  // read. The browser already throttles hidden tabs, which roughly produces the right behaviour
  // — but leaning on that side effect would make a privacy rule depend on a battery-saving
  // heuristic.
  //
  // It fires on mount and on `visibilitychange`, and deliberately **not** on the visibility of
  // individual lines. An `IntersectionObserver` would make a read receipt report *which*
  // message the reader looked at and for how long — a change to what a receipt discloses,
  // dressed up as an optimisation.
  useEffect(() => {
    const mark = () => {
      if (document.visibilityState === "visible") {
        session.markRead(view);
        bump();
      }
    };

    mark();
    document.addEventListener("visibilitychange", mark);
    return () => document.removeEventListener("visibilitychange", mark);
  }, [session, view, view.contentCursor, bump]);

  const react = (seq: number, emoji: string) => {
    session
      .reactTo(view, seq, emoji)
      // Remembered on the way out rather than inside `reactTo`: an emoji chosen from the picker
      // and an emoji chosen from the shortcut row are the same gesture, and the shortcut row is
      // built from this list — so a reaction that failed to send should still count as a choice.
      .then(() => session.noteEmojiUse(emoji))
      .then(bump)
      .catch((e: unknown) => {
        report.error(e instanceof Error ? e.message : String(e));
      });
  };

  /**
   * Take a message's own words out of the thread.
   *
   * The confirmation is a toast rather than a label that flips to "Copied", for the reason
   * `Pairing.tsx` gives at its own copy button: a flipped label says nothing on the second copy
   * and nothing at all to a screen reader.
   *
   * What this does not solve: a clipboard write the browser refuses rejects silently. There is
   * nothing useful to say about it — the text is on screen and can be selected — and an error
   * banner for a permission the user just declined would be noise.
   */
  const copy = (text: string) => {
    void navigator.clipboard.writeText(text).then(() => report.done("Message copied"));
  };

  /**
   * The five shortcuts, which are the five most recently used once there are five.
   *
   * Topped up from the defaults rather than shown short: a bar that grows from one button to
   * five over a week moves the overflow menu under the reader's thumb a little further every day.
   */
  const quick = [
    ...session.preferences.recentEmojis,
    ...EMOJIS.filter((emoji) => !session.preferences.recentEmojis.includes(emoji)),
  ].slice(0, 5);

  const isTyping = session.typingIn(view);

  // Wake-up on expiry.
  //
  // `typingIn` filters out stale indicators, but it only runs on render — and once the peer
  // stops typing, nothing triggers a render: no signal arrives, and the periodic poll only comes
  // back thirty seconds later. The indicator stayed painted on screen long after it stopped
  // being true.
  //
  // This timer adds no data: it only asks for a render at the moment the filter changes its
  // mind. `tick` is never read, only its change matters.
  const [, setTick] = useState(0);
  useEffect(() => {
    const delay = nextExpiry(view.typing, Date.now());
    if (delay === undefined) return;

    const timer = setTimeout(() => setTick((n) => n + 1), delay);
    return () => clearTimeout(timer);
  });

  return (
    <>
      {/*
        The severed ratchet, said out loud.

        Until now `view.stale` stopped the polling and rendered nothing, so the conversation
        simply went quiet — the doc comment on the flag calls that the lesser of two wrongs and
        still a wrong. This is the sentence that was owed.

        Above the list rather than inside it, and not dismissible: the condition is still true,
        and a banner waved away would leave a thread that looks alive and is not. It promises no
        recovery, because none is implemented.
      */}
      {view.stale === true && (
        <div className="p-pane pb-0">
          <Banner tone="danger" title="This conversation stops here on this device">
            Messages waiting on the server were deleted before this device could fetch them, and
            they are part of what decrypts everything sent afterwards. Nothing further will arrive
            in this thread here. What is already on screen stays readable, and the conversation
            keeps working on your other devices and for the people you were talking to.
          </Banner>
        </div>
      )}

      {/*
        No vertical rhythm on the list itself. A run of lines from one person is one paragraph and
        wants no gap at all; the air belongs between turns, which is a property of each line rather
        than of the space between any two of them.
      */}
      {/* `role="list"` restates what `<ol>` already says, and it is needed anyway: Tailwind's
          preflight sets `list-style: none`, and WebKit reads a list with no marker as one the
          author no longer means — VoiceOver stops saying "list, 20 items". The name matters as
          much: this was the one scrolling region in the application with nothing to call it. */}
      {/* Said once for the list, rather than as a description on every row: repeated on each
          message it would be read out twenty times and would treble the length of every line a
          screen reader announces. */}
      <p className="sr-only">
        Use the up and down arrows to move between messages, the right arrow to reach a message’s
        actions, and Escape to return to the composer.
      </p>

      {/* The listener is on the list rather than on every row: the event bubbles from whichever
          row holds the focus, so one handler does what N would. */}
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions */}
      <ol
        ref={thread.list}
        role="list"
        aria-label="Messages"
        onScroll={() => {
          const el = thread.list.current;
          if (el === null) return;

          // The 64 pixels are a tolerance, not a measurement: a thread scrolled to within a line
          // of the end is one the reader is following, and browsers land a pixel or two short of
          // `scrollHeight` often enough that an exact test would report "not at the end" for a
          // list that visibly is.
          stuck.current = el.scrollHeight - el.scrollTop - el.clientHeight < 64;
        }}
        onFocus={thread.onFocus}
        onKeyDown={(event) => {
          const row = (event.target as HTMLElement).closest<HTMLElement>("[data-row]");

          // Right steps down a level, into the actions belonging to the focused message. Only
          // from the row itself: inside the bar, Left and Right belong to the bar.
          if (event.key === "ArrowRight" && event.target === row) {
            const first = row?.querySelector<HTMLElement>("[data-actions] button");
            if (first === null || first === undefined) return;

            event.preventDefault();
            first.focus();
            return;
          }

          // And back up. Escape does the same from inside the bar, then leaves the thread
          // entirely on a second press — which is the one gesture that has to work when somebody
          // has arrowed into a message and wants to go back to writing.
          if ((event.key === "ArrowLeft" || event.key === "Escape") && event.target !== row) {
            if (row === null) return;

            event.preventDefault();
            // `stopPropagation` for the same reason the rail's filter does it: `DetailPanel`
            // listens for Escape on `window`, and stepping out of an action bar is not a request
            // to close the details column.
            event.stopPropagation();
            row.focus();
            return;
          }

          if (event.key === "Escape" && event.target === row) {
            event.preventDefault();
            event.stopPropagation();
            document.getElementById(COMPOSER_ID)?.focus();
            return;
          }

          thread.onKeyDown(event);
        }}
        // Anchored to the bottom, the way every thread anybody has used is: a conversation grows
        // downwards, so a short one belongs against the composer rather than stranded at the top
        // of a screen of empty ground.
        //
        // `mt-auto` on the first child rather than `justify-end` on the list. They look identical
        // when the content is short, and they differ in the case that matters: with
        // `justify-content: flex-end` on a scrolling box, content that overflows runs off the top
        // and several engines refuse to scroll back to it, so the oldest messages become
        // unreachable. An automatic margin absorbs the free space when there is some and resolves
        // to zero when there is none, which is exactly the behaviour wanted and needs no special
        // case.
        //
        // `shrink-0` on the rows because a flex column will otherwise compress its items to fit
        // rather than overflow, which would squash the messages instead of scrolling them.
        className="flex min-h-0 flex-1 flex-col overflow-y-auto py-pane [&>*:first-child]:mt-auto [&>li]:shrink-0"
      >
        {rows.map(({ key, message, opensDay, continues, opensUnread }) => {
          // Extracted before the JSX: type narrowing is lost inside a closure, and working
          // around it inline made the render unreadable.
          const attachment = message.content.kind === "attachment" ? message.content.ref : null;
          const cite = message.content.kind === "reply" ? message.content.target : null;
          const spoken =
            message.content.kind === "text" || message.content.kind === "reply"
              ? message.content.text
              : null;
          const emojis = [...(reactions.get(message.seq)?.values() ?? [])];
          const mineAlready = reactions.get(message.seq)?.get(session.handle);

          return (
            <Fragment key={key}>
              {/*
                One heading per day, and none at all for a thread nobody stamped: a date on
                screen that no message carries would be an invention.

                `role="separator"` rather than a heading level: it divides the list, it does not
                introduce a section a reader would want to navigate to.
              */}
              {opensUnread && (
                <li
                  role="separator"
                  className="flex items-center gap-snug px-pane py-snug text-caption text-(--color-accent)"
                >
                  <span className="h-px flex-1 bg-(--color-accent)/40" />
                  New messages
                  <span className="h-px flex-1 bg-(--color-accent)/40" />
                </li>
              )}

              {opensDay !== undefined && (
                <li role="separator" className="px-pane py-snug text-center">
                  <span className="rounded-(--radius-pill) bg-(--color-surface-raised) px-gutter py-tight text-caption text-(--color-ink-muted)">
                    {dayLabel(opensDay, now)}
                  </span>
                </li>
              )}

              <li
                data-row={key}
                // The roving tabindex: one row of the thread is reachable with Tab, and which one
                // it is follows wherever the reader last was.
                tabIndex={thread.at === key ? 0 : -1}
                className={cn(
                  // The row is focusable now, so it needs to say when it is focused. Inset, like
                  // the rail's rows, because an outline drawn outside a full-width row is clipped
                  // by the scrolling list.
                  "focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent)",
                  // `relative` is load-bearing: the action bar is absolutely positioned against
                  // this row so that it can overlap the row's top edge without reserving height
                  // inside it. Revealing it by reflow made the thread jump under the pointer.
                  "group relative flex px-pane py-tight",
                  // The air goes above the first line of a turn, so a burst of three sentences
                  // reads as one paragraph and the next speaker is visibly a new one.
                  !continues && "mt-snug",
                  // No fill at rest, on any row. A thread is a column of text and every band of
                  // tint laid under it is one more edge the eye has to sort out before it can
                  // read; a tint on every one of our own turns striped the whole conversation.
                  // The row lights up under the pointer instead, which is the moment the fill is
                  // actually saying something — this is the line the buttons in the corner
                  // belong to.
                  //
                  // Derived from the ink rather than written as a colour, which is what makes it
                  // behave in both themes for free: the ink is dark over a light ground and light
                  // over a dark one, so a few percent of it darkens the row in one theme and
                  // lifts it in the other, by the same amount.
                  //
                  // What this does not solve: with the fill gone, nothing distinguishes our own
                  // messages at rest. The avatar and the name do it now, as they do for everybody
                  // else, and the alignment that used to say it was dropped with the bubbles.
                  // `hover:` and not `group-hover:`: this element *is* the group, and
                  // `group-hover:` only ever matches a descendant of one. Written the other way
                  // it compiles to a selector nothing satisfies — no error, no warning, just a
                  // row that never lights up.
                  "rounded-control hover:bg-(--color-ink)/5",
                )}
              >
                {/*
                  The lane: the author's face at the top of each turn, the hour under it.

                  The avatar is drawn for everybody now, ours included, and on every turn rather
                  than only in group threads. Alignment used to answer "who said this" and the
                  avatar was spent only where alignment could not — in a group. With the thread in
                  one column the avatar *is* the answer, in a one-to-one as much as in a group, and
                  an anchor that appeared and disappeared depending on how many people were in the
                  room would make the column ragged for no gain.

                  `sm` and not `md`: the proof strip rides under an `md` avatar, and repeating a
                  verification pattern on every message would turn evidence into wallpaper. It
                  belongs in the detail column, once.
                */}
                <div className={cn(LANE, "flex flex-col items-start")}>
                  {continues ? (
                    /*
                      The hour of a continuation line, in the lane, on hover.

                      Faded rather than absent, so it stays in the accessibility tree: a screen
                      reader still reads a stamp on every line, exactly as it did when the hour sat
                      under each bubble. Only the eye is spared the column of repeated numbers.
                    */
                    message.sentAt !== undefined && (
                      <time
                        dateTime={new Date(message.sentAt).toISOString()}
                        title={new Date(message.sentAt).toLocaleString()}
                        className="pt-0.5 text-[0.6875rem] leading-5 text-(--color-ink-muted) opacity-0 transition-opacity duration-(--duration-quick) ease-out group-hover:opacity-100 motion-reduce:transition-none"
                      >
                        {timeOf(message.sentAt)}
                      </time>
                    )
                  ) : (
                    <Avatar
                      seed={seedOf(authorOf(message))}
                      label={nameOfAuthor(authorOf(message))}
                      size="sm"
                      className={AVATAR_40}
                    />
                  )}
                </div>

                {/* `max-w-measure`: the lane holds the text, and text has a width past which it
                    stops being comfortable to read. See `--container-measure` in `index.css`.
                    On the lane rather than on the paragraph, so the name, the hour, the quoted
                    reply and the reactions all stop at the same edge — a column, not a ragged
                    stack of differently-bounded pieces. */}
                <div className="min-w-0 max-w-measure flex-1">
                  {/* The name is announced once per turn, not once per line: a burst of three
                      sentences is one person speaking, not three announcements. */}
                  {!continues && (
                    <div className="flex items-baseline gap-snug">
                      <span className="truncate text-body font-medium">
                        {nameOfAuthor(authorOf(message))}
                      </span>
                      {/*
                        `<time>` with a machine-readable `dateTime`, so a screen reader announces
                        the full date rather than reading "14:02" as two numbers, and the tooltip
                        carries the day a line in the middle of a thread does not repeat.

                        Nothing is shown when the sender did not stamp. An empty slot is honest; a
                        guessed hour is not.
                      */}
                      {message.sentAt !== undefined && (
                        <time
                          dateTime={new Date(message.sentAt).toISOString()}
                          title={new Date(message.sentAt).toLocaleString()}
                          className="shrink-0 text-caption text-(--color-ink-muted)"
                        >
                          {timeOf(message.sentAt)}
                        </time>
                      )}
                    </div>
                  )}

                  {cite !== null && (
                    <span
                      // A real hairline token now that there is no accent ground to survive.
                      // The rule used to be `border-current/40`, which was the only colour that
                      // worked on both the accent bubble and the raised one; with every line on
                      // the same surface, the border colour can say what it means.
                      className="mb-tight block border-l-2 border-(--color-border-strong) pl-snug text-caption text-(--color-ink-muted)"
                    >
                      <EmojiText text={textOf(messages, cite)} />
                    </span>
                  )}

                  <div className="flex items-end gap-snug">
                    <div
                      // `whitespace-pre-wrap`: the composer accepts line breaks, and HTML collapses
                      // them. Without this a message written as a list arrives as one run-on
                      // sentence — the text is intact on the wire and mangled only on screen, which
                      // is the kind of loss nobody thinks to check.
                      className="min-w-0 flex-1 whitespace-pre-wrap wrap-anywhere text-left text-body"
                    >
                      {attachment ? (
                        <Attachment
                          attachment={attachment}
                          onOpen={() => session.openAttachment(view, attachment)}
                        />
                      ) : spoken !== null ? (
                        <EmojiText text={spoken} big />
                      ) : null}
                    </div>

                    {/*
                      The receipt at the end of the line rather than under the text: with the
                      bubble gone there is no box for it to sit inside, and a line of its own for
                      two ticks would double the height of every message we send.

                      What this does not solve: on a single-line message the action bar overlaps
                      this corner while the pointer is over the row, so the ticks are hidden for
                      exactly as long as somebody is reaching for a reaction. The state is not
                      urgent and comes back the moment the pointer leaves.
                    */}
                    {message.mine && (
                      <span className="shrink-0 text-caption text-(--color-ink-muted)">
                        <Status state={session.statusOf(view, message.seq)} />
                      </span>
                    )}
                  </div>

                  {emojis.length > 0 && (
                    // A list, not a named `<div>`: the name was on a generic element and went
                    // unread, and what is here really is a list of things. `role="list"` is
                    // explicit because Tailwind's preflight sets `list-style: none`, which is
                    // enough for WebKit to stop calling it a list at all.
                    <ul
                      role="list"
                      aria-label="Reactions"
                      className="mt-tight flex flex-wrap gap-tight text-caption"
                    >
                      {emojis.map((emoji, at) => (
                        <li
                          // Two people can send the same emoji, so the emoji is not a key. The
                          // position in an already-deduplicated list is.
                          key={at}
                          className="rounded-(--radius-pill) border border-(--color-border-subtle) bg-(--color-surface-raised) px-tight"
                        >
                          <Emoji char={emoji} />
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                {/*
                  Reactions and Reply used to be `hidden group-hover:flex`, which put them out of
                  reach of everyone without a mouse: `display: none` takes an element out of the tab
                  order, and a finger has no hover to give. They were, in practice, features only
                  some people had.

                  Faded rather than hidden, so the buttons stay focusable and the row keeps its
                  height — revealing them by reflow made the thread jump under the pointer. They
                  come back on hover, on keyboard focus anywhere inside the row, and unconditionally
                  on a touch device, where there is no other way to ask for them.

                  `group-focus-within:` and not `focus-within:`, which is the difference between
                  "the focus is inside this bar" and "the focus is inside this row". The row is
                  what carries the roving tabindex, so with the old rule pressing Right on a
                  focused message stepped into a bar that was still at zero opacity: the buttons
                  were reachable and invisible, which is worse than either.

                  Anchored over the row's top edge rather than laid out under the text: a bar in
                  the flow claimed a line of height on every message whether or not it was wanted,
                  and it put the controls of the message above within a few pixels of the text of
                  the one below. `z-index-sticky` because it overlaps the previous row, which is
                  painted after it in document order.
                */}
                <div
                  // `has-[[data-state=open]]` is the one addition to that rule, and it is the
                  // menu's fault: Radix portals its content and takes focus with it, so a bar
                  // holding an open picker or an open menu is neither hovered nor focus-within,
                  // and it faded out from under the surface it had just opened. The trigger keeps
                  // `data-state="open"` for as long as the panel is up, which is exactly the
                  // condition wanted.
                  className="absolute -top-3 right-pane z-(--z-index-sticky) flex items-center gap-tight rounded-control border border-(--color-border-subtle) bg-(--color-surface-raised) p-tight text-body shadow-menu opacity-0 transition-opacity duration-(--duration-quick) ease-out group-focus-within:opacity-100 group-hover:opacity-100 has-[[data-state=open]]:opacity-100 motion-reduce:transition-none touch:opacity-100"
                  data-actions
                >
                  {quick.map((emoji) => (
                    // The label is a node and not a string so the emoji in it is artwork like
                    // every other emoji on screen. Interpolated into a template literal it was
                    // the last glyph in the application still drawn by the platform font.
                    <Tooltip
                      key={emoji}
                      label={
                        <>
                          React with <Emoji char={emoji} />
                        </>
                      }
                    >
                      <IconButton
                        label={`React with ${emoji}`}
                        icon={<Emoji char={emoji} />}
                        size="sm"
                        onClick={() => react(message.seq, emoji)}
                      />
                    </Tooltip>
                  ))}

                  {/* Everything the five shortcuts are not. `side="top"` because the bar sits at
                      the top of a line and a panel opening downwards would cover the message it
                      belongs to; Radix flips it anyway when there is no room above. */}
                  <EmojiDrawer
                    label="React with another emoji"
                    size="sm"
                    side="top"
                    align="end"
                    onPick={(emoji) => react(message.seq, emoji)}
                  />

                  {/*
                    Reply, as a glyph at last. The note this replaces said `ui/Icon.tsx` was a
                    closed inventory holding no reply arrow and that widening it for one call site
                    was the growth that file exists to prevent. The inventory has since been
                    widened on purpose, `reply` is in it, and the word can go: a bar of five emoji
                    and two glyphs has no room for a piece of prose, and the label survives as the
                    accessible name and as the tooltip.
                  */}
                  <Tooltip label="Reply">
                    <IconButton
                      label="Reply"
                      icon={<Icon name="reply" />}
                      size="sm"
                      onClick={() => onReplyTo(message.seq)}
                    />
                  </Tooltip>

                  {/*
                    The overflow, and the short list of things that are really in it.

                    There is no delete, no edit and no pin here because there is none in the
                    protocol: `lib/content.ts` has no content type for any of the three and
                    `Session` has no method that would send one. An item that greyed out, or one
                    that removed a message from this screen and from nowhere else, would be a lie
                    about what this application can do — and the one lie a messenger cannot afford
                    is "that message is gone".

                    So: copying the words, which is a browser capability and needs no protocol at
                    all, and taking back a reaction, which `reactTo` has always supported with an
                    empty emoji and which the thread until now had no way to ask for — tapping the
                    same emoji again simply sent it a second time.
                  */}
                  <Menu
                    align="end"
                    trigger={
                      <IconButton label="More actions" icon={<Icon name="more" />} size="sm" />
                    }
                  >
                    <Menu.Item
                      icon="copy"
                      // An attachment has a name and no words. Copying the file name under a label
                      // that promises the message would be the wrong thing quietly.
                      disabled={spoken === null}
                      onSelect={() => copy(spoken ?? "")}
                    >
                      Copy text
                    </Menu.Item>
                    <Menu.Item
                      icon="close"
                      disabled={mineAlready === undefined}
                      onSelect={() => react(message.seq, "")}
                    >
                      Remove my reaction
                    </Menu.Item>
                  </Menu>
                </div>
              </li>
            </Fragment>
          );
        })}

        {/*
          Written, not yet accepted. Rendered after the thread and never inside it: these have no
          sequence number, and the whole reason they are kept apart is that nothing downstream can
          mistake one for a message the server has numbered.

          Which is also why they are never grouped with the line above: grouping is decided in
          `lib/thread.ts` from a `seq` and a boundary expressed as one, and a pending message has
          neither. It gets its own lane with its own hour, and repeats the anchor rather than
          guessing that the turn above was ours.
        */}
        {view.outbox.map((entry) => (
          <li key={entry.localId} className="mt-snug flex rounded-control bg-(--color-ink)/5 px-pane py-tight">
            <div className={LANE}>
              <time
                dateTime={new Date(entry.sentAt).toISOString()}
                title={new Date(entry.sentAt).toLocaleString()}
                className="pt-0.5 text-[0.6875rem] leading-5 text-(--color-ink-muted)"
              >
                {timeOf(entry.sentAt)}
              </time>
            </div>

            <div
              className={cn(
                "min-w-0 flex-1 whitespace-pre-wrap wrap-anywhere text-left text-body",
                entry.state === "failed"
                  ? "text-(--color-danger)"
                  : // The fade is the message: this one is not acquired yet. Not a muted ink —
                    // an ink says what something is, and this says how far along it is.
                    "opacity-60",
              )}
            >
              <EmojiText text={entry.text} big />
              <span className="mt-tight flex items-center gap-snug text-caption">
                {entry.state === "sending" ? (
                  <Spinner size="sm" label="sending" />
                ) : (
                  <>
                    {/* Named next to the message rather than in a banner: a banner at the bottom
                        of the application says something failed without saying which. */}
                    <span>not sent</span>
                    <button
                      type="button"
                      onClick={() => void session.retry(view, entry.localId).then(bump)}
                      className="underline"
                    >
                      Retry
                    </button>
                    <button
                      type="button"
                      onClick={() => void session.discard(view, entry.localId).then(bump)}
                      className="underline"
                    >
                      Discard
                    </button>
                  </>
                )}
              </span>
            </div>
          </li>
        ))}

        <div ref={bottom} />
      </ol>

      {/*
        Activity line. It goes out in two ways, neither depending on a "stopped typing" signal —
        such a signal can be lost and would leave the indicator lit forever.

        Immediately when a message from that author arrives: sending proves they are done, and
        that proof cannot go missing since we never wait for it. Otherwise, by local expiry,
        woken by the timer above.
      */}
      {isTyping.length > 0 && (
        <p className="px-pane pb-tight text-caption text-(--color-ink-muted)" aria-live="polite">
          {isTyping.map((handle) => compactNameOf(handle, names, members)).join(", ")}{" "}
          {isTyping.length > 1 ? "are typing" : "is typing"}…
        </p>
      )}
    </>
  );
}

/**
 * State of a message we sent.
 *
 * Three states and not two: "sent" means the server accepted it, "delivered" that a device
 * picked it up, "read" that a person had it on screen. Conflating them would pass a powered-on
 * phone off as human attention.
 *
 * The three used to be told apart by opacity, which is the thing this pass is removing from
 * text: dimmed 12px ink was under 3:1, so the distinction was invisible to exactly the readers it
 * was meant for. Weight replaces it.
 *
 * What that does not solve: `delivered` and `read` still share the `✓✓` glyph and now differ
 * only by a stroke. The accessible name and `title` carry the difference in full, and there is
 * no colour to spend on it — the accent is rationed elsewhere and a receipt is not a state the
 * reader has to act on.
 */
function Status({ state }: { state: "sent" | "delivered" | "read" }) {
  const label = { sent: "sent", delivered: "delivered", read: "read" }[state];
  const mark = { sent: "✓", delivered: "✓✓", read: "✓✓" }[state];

  return (
    <span
      // No margin of its own: it now sits in the flex row that carries the text, which spaces it.
      className={state === "read" ? "font-medium" : undefined}
      // `role="img"` rather than a bare `aria-label`: a name on a generic element is ignored,
      // and here that silence hid the whole distinction — `delivered` and `read` share the glyph
      // and differ only in weight, so the word is the only thing that tells them apart.
      role="img"
      title={label}
      aria-label={label}
      data-receipt={state}
    >
      {mark}
    </span>
  );
}
