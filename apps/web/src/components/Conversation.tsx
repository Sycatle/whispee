import { useEffect, useRef, useState } from "react";

import { EmojiDrawer } from "@/components/EmojiPicker";
import { ShortcodeMenu, LISTBOX_ID, useShortcodes } from "@/components/Shortcodes";
import { Messages } from "@/components/Messages";
import { PresenceLine } from "@/components/Presence";
import { Verification } from "@/components/Verification";
import { DETAIL_PANEL_ID, INFO_TOGGLE_ID } from "@/app/DetailPanel";
import { useDuo } from "@/lib/duo";
import { compactNameOf, type NameSources } from "@/lib/naming";
import type { ConversationView } from "@/lib/session";
import { useShortcut } from "@/lib/shortcuts";
import { useOcclusion } from "@/lib/viewport";
import { EmojiText } from "@/ui/Emoji";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Spinner } from "@/ui/Spinner";
import { Tooltip } from "@/ui/Tooltip";
import { useNames } from "@/state/names";
import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { useNavigate, useRoute } from "@/routes/Router";

/** The id the skip link aims at, so tabbing can jump the rail and the whole message list. */
export const COMPOSER_ID = "conversation-composer";

/**
 * Everybody this thread can attribute something to.
 *
 * `accounts` and `peers` both, because they answer at different moments and neither is a superset
 * of the other: `peers` is restored with the conversation, `accounts` arrives with the first
 * poll, and somebody removed from the group is still the author of what they said. The union is
 * what the ambiguity check in `compactNameOf` has to compare against — a rival left out of it is
 * a fallback that does not happen.
 */
function membersOf(view: ConversationView): string[] {
  return [
    ...new Set([...view.accounts.map((a) => a.handle), ...view.peers.map((p) => p.name)]),
  ];
}

/**
 * What a screen reader should hear when a message lands in the thread already on screen.
 *
 * Reactions are left out for the same reason the rail's preview leaves them out: "👍" announced
 * on its own says nothing, and a busy thread would read a string of them over whatever the user
 * was doing.
 */
function spoken(view: ConversationView, names: NameSources): string | null {
  const last = view.messages.at(-1);
  if (!last || last.mine) return null;

  // The compact form: a spoken sentence has no second line, and reading out both strings for
  // every arrival would double the length of the one announcement people are trying to hear
  // over whatever else they are doing.
  const who =
    last.sender === null ? "Someone" : compactNameOf(last.sender, names, membersOf(view));
  const { content } = last;
  if (content.kind === "text" || content.kind === "reply") return `${who}: ${content.text}`;
  if (content.kind === "attachment") return `${who} sent ${content.ref.name}`;
  return null;
}

/**
 * What the reply banner shows of the message being answered.
 *
 * The same rule as the quote inside a bubble in `Messages.tsx`: the text for anything textual,
 * the file name for an attachment, and a placeholder when the sequence number points at nothing
 * we hold. It is duplicated rather than shared because the two live on opposite sides of the
 * thread — one renders inside a bubble that already knows its own message, this one starts from
 * a bare number the reply bar was handed — and a shared helper would have to take the message
 * list from one and the number from the other to say the same three lines.
 *
 * What this does not solve: a message that has not been hydrated yet is genuinely unavailable
 * here, so replying to something far up an unloaded history shows the placeholder until the
 * archive comes back.
 */
function excerptOf(view: ConversationView, seq: number): string {
  const target = view.messages.find((message) => message.seq === seq);
  if (!target) return "message unavailable";
  const { content } = target;
  if (content.kind === "text" || content.kind === "reply") return content.text;
  if (content.kind === "attachment") return content.ref.name;
  return "…";
}

/**
 * A byte count a person can read.
 *
 * Deliberately a second copy of the one in `Attachment.tsx` rather than an import. That one
 * belongs to a received attachment and is not exported; exporting it would make a component
 * module a utility module, and the rule it encodes — three ranges, no decimals below a megabyte
 * — is four lines. The duplication is cheap; the coupling would not be.
 */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function Conversation({ view }: { view: ConversationView }) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const route = useRoute();
  const navigate = useNavigate();
  const duo = useDuo();
  const names = useNames();
  // Seeded from the session, which is what makes a half-written message survive a look at
  // another conversation. Keyed on the view, so switching remounts with the right draft.
  const [text, setText] = useState(() => session.draftIn(view));
  const [sending, setSending] = useState(false);
  const [replyTo, setReplyTo] = useState<number | null>(null);
  /**
   * A file that has been chosen and not yet sent.
   *
   * Picking a file used to *be* sending it: the `change` event went straight to
   * `session.sendAttachment`, so the wrong file left the device before its name was ever on
   * screen, and nothing in an end-to-end encrypted thread takes a message back. Holding it here
   * until submit costs one extra gesture and turns an irreversible mistake into a removable
   * chip.
   *
   * Not folded into the draft: `session.setDraft` stores a string, and a `File` is a handle to
   * bytes the page cannot serialise. So this one does not survive switching conversations, which
   * is a real limit and the honest one — a pending file that reappeared in a thread it was never
   * chosen for would be worse than losing it.
   */
  const [pending, setPending] = useState<File | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const composer = useRef<HTMLTextAreaElement>(null);
  const occlusion = useOcclusion();

  const detailOpen = route.kind === "conversation" && route.detail !== undefined;

  const toggleDetail = () => {
    if (detailOpen) {
      navigate({ kind: "conversation", key: view.key });
      return;
    }
    navigate({ kind: "conversation", key: view.key, detail: {} });
  };

  // The keyboard route into the detail column. It is a navigation like the button, so it lands
  // in history and the back gesture closes the panel.
  useShortcut("mod+i", toggleDetail);

  /**
   * Announces arrivals to a screen reader that is already on this conversation.
   *
   * The notifications in `App.tsx` fire for a thread the user is *not* looking at; on the open
   * one they deliberately do not. Which left the case where nothing announced anything at all: a
   * reader parked in the thread heard the message list grow in silence.
   *
   * `polite` and not `assertive`: an incoming message is not worth interrupting a sentence
   * somebody is in the middle of hearing. What this does not solve — two messages arriving
   * within one announcement means the first is skipped, because the region reports its current
   * contents rather than a queue.
   */
  const [announcement, setAnnouncement] = useState("");
  const announced = useRef<number | null>(null);

  // No dependency array: the trigger is a cursor inside a mutating object, which no dependency
  // list can name. Same reasoning as the arrival detection in `App.tsx`.
  useEffect(() => {
    const last = view.messages.at(-1);
    if (!last) return;

    // The first sight of a conversation is not an arrival: opening a thread with a hundred
    // messages in it must not read the hundredth out loud.
    if (announced.current === null) {
      announced.current = last.seq;
      return;
    }
    if (last.seq <= announced.current) return;
    announced.current = last.seq;

    const line = spoken(view, names);
    if (line !== null) setAnnouncement(line);
  });

  // Pulls the archived history back in when the conversation opens.
  //
  // Lazy and non-blocking: the conversation shows immediately, the past fills in behind it.
  // `hydrate` only does the work once per session, so re-running this effect when the view
  // changes identity is harmless.
  useEffect(() => {
    session
      .hydrate(view)
      .then((restored) => {
        if (restored > 0) bump();
      })
      .catch((e: unknown) => report.error(e instanceof Error ? e.message : String(e)));
  }, [session, view, bump, report]);

  /**
   * Sends whatever the composer is holding: the text, the pending file, or both.
   *
   * # The text goes first, the file second
   *
   * They are two messages on the wire — there is no caption on an attachment — so the order is a
   * choice, and it is made for the text. `session.send` queues locally and returns: the bubble
   * appears at once and a failure is reported on the bubble itself. `sendAttachment` encrypts and
   * uploads bytes, which for anything sizeable is seconds. Sending the file first would hold the
   * typed sentence behind an upload for no reason and leave the composer looking stuck at the
   * moment the user expects it to empty.
   *
   * What this does not solve: the two land in the thread in that order, so a message written to
   * introduce the file reads correctly and one written to comment on it does not. There is no way
   * to say which was meant, and the reading order of a chat is the more common intent.
   *
   * # A failed upload keeps the file
   *
   * `pending` is cleared only after `sendAttachment` resolves. A network failure therefore leaves
   * the chip in place and the user presses send again, which is the whole point of holding the
   * file in the first place — nothing about a failure should look like a delivery.
   */
  const send = async (event: { preventDefault: () => void }) => {
    event.preventDefault();
    const body = text.trim();
    const file = pending;
    if (!body && !file) return;

    const cite = replyTo;
    if (body) {
      setText("");
      session.setDraft(view, "");
      setReplyTo(null);
    }

    setSending(true);
    try {
      if (body) {
        // A plain message cannot fail here any more: `send` queues it, shows it, and reports a
        // failure on the bubble itself. A reply still can — it points at a sequence number, which
        // is exactly what a queued message has not got — so that one keeps the banner.
        if (cite === null) {
          await session.send(view, body);
          bump();
        } else {
          try {
            await session.replyTo(view, cite, body);
            bump();
          } catch (e) {
            report.error(e instanceof Error ? e.message : String(e));
          }
        }
      }

      if (file) {
        try {
          await session.sendAttachment(view, file);
          setPending(null);
          bump();
        } catch (e) {
          report.error(e instanceof Error ? e.message : String(e));
        }
      }
    } finally {
      setSending(false);
    }
  };

  /**
   * Reports typing on every keystroke — the debounce lives in `Session`.
   *
   * Putting it here would force every caller to redo it, and it is the kind of guard that gets
   * forgotten: one network post per key pressed.
   */
  const typing = (value: string) => {
    setText(value);
    session.setDraft(view, value);
    if (value) void session.notifyTyping(view).catch(() => {});
  };

  /**
   * The caret, mirrored into state so the completion menu can see it.
   *
   * A `<textarea>` reports its caret on the element and never in a render, so nothing derived
   * from it updates on its own. Mirroring on every event that can move it — typing, clicking,
   * arrowing — is what lets `useShortcodes` tell a caret still inside the `:word` being completed
   * from one that has been moved away from it.
   */
  const [caret, setCaret] = useState(0);

  /**
   * Overwrites a span of the draft and leaves the caret after what replaced it.
   *
   * The one edit the composer performs on its own behalf, and both callers need exactly it: the
   * picker replaces the selection (or nothing, at the caret), a completion replaces the `:word`
   * that was being typed.
   *
   * The caret is restored in a microtask rather than immediately, because React has not written
   * the new value into the DOM at this point and setting `selectionStart` against the old one
   * would land in the wrong place. Focus goes back to the field either way: the picker took it,
   * and a composer you have to click again to keep typing in is a composer that interrupts.
   */
  const replace = (at: number, to: number, insertion: string) => {
    const field = composer.current;

    typing(`${text.slice(0, at)}${insertion}${text.slice(to)}`);

    queueMicrotask(() => {
      const after = at + insertion.length;
      field?.focus();
      field?.setSelectionRange(after, after);
      setCaret(after);
    });
  };

  /**
   * Drops an emoji where the caret is, not at the end of the field.
   *
   * Appending would be simpler and wrong: somebody who moved the caret back to fix a word and
   * then reached for the picker gets their emoji at the end of a sentence they were not looking
   * at. `selectionStart`/`selectionEnd` also cover a selection, which is replaced — the same
   * thing typing a character does.
   */
  const insert = (emoji: string) => {
    const field = composer.current;
    replace(field?.selectionStart ?? text.length, field?.selectionEnd ?? text.length, emoji);
  };

  const shortcodes = useShortcodes({ text, caret, replace });

  /**
   * Takes the chosen file and stops there.
   *
   * Choosing is not sending any more — see `pending` above. One file at a time, because
   * `sendAttachment` takes one and a queue of them would need its own per-file progress and per
   * file failure; a second pick replaces the first, which is what "the wrong file" usually means.
   */
  const attach = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    // The input is reset right away: without it, picking the same file twice would not fire a
    // second `change`. It matters more now than it did — removing a file and picking it again is
    // an ordinary correction rather than an accident.
    event.target.value = "";
    if (!file) return;
    setPending(file);
    // The field takes focus back, so Enter sends what was just attached without a trip to the
    // mouse. The picker took focus to the button that opened it, and leaving it there would put
    // the next keystroke on a paperclip.
    composer.current?.focus();
  };

  const isTyping = session.typingIn(view);

  /*
    One line and no room for a second: the line under this one belongs to the typing indicator
    and the presence line, both of which say something the title cannot. So the compact form,
    which falls back to handles rather than showing a name it cannot tell apart from another
    member's. The full two-line form is in the detail column, which is where somebody goes when
    they want to know exactly who is in the room.
  */
  const members = membersOf(view);
  const title =
    view.accounts.map((a) => compactNameOf(a.handle, names, members)).join(", ") ||
    [...new Set(view.peers.map((p) => p.name))]
      .map((n) => compactNameOf(n, names, members))
      .join(", ") ||
    "empty conversation";

  /*
    Who is being answered, and what they said.

    The bar used to read "Replying to message 41". The sequence number is a protocol coordinate:
    it is not written on any bubble, so there is nothing on screen to match it against, and the
    one question the bar has to answer — did I hit reply on the right message — was the one thing
    it could not answer.

    The author is resolved the way `Messages.tsx` resolves it for grouping: our own messages
    answer with our own handle whatever device sent them, and a message with no sender at all is
    "Someone" rather than a blank. The name goes through `compactNameOf` against the same member
    list as the title, so the bar and the header call the same person the same thing.
  */
  const cited = replyTo === null ? undefined : view.messages.find((m) => m.seq === replyTo);
  const citedAuthor = cited === undefined ? null : cited.mine ? session.handle : cited.sender;
  const citedName = citedAuthor === null ? "Someone" : compactNameOf(citedAuthor, names, members);

  // Nothing to send is not a state the button should look available in. `send` has always
  // returned early on an empty body; it did so silently, from a control that looked live.
  const nothingToSend = text.trim() === "" && pending === null;

  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col bg-(--color-surface)">
      <header className="safe-top flex items-center justify-between gap-pane border-b border-(--color-border-subtle) px-pane py-snug">
        {/* Only where the list is not beside us. It undoes the navigation that opened this
            conversation rather than going to `#/`, so a round trip between the list and a thread
            does not stack one history entry per visit — see the rule in `routes/Router.tsx`. */}
        {!duo && (
          <IconButton
            label="Back to conversations"
            icon={<Icon name="back" size={20} />}
            onClick={() => history.back()}
            className="-ml-tight shrink-0"
          />
        )}
        {/*
          The epoch is not displayed — it is a protocol detail that teaches the user nothing.
          It is exposed as an attribute because two members on different epochs can no longer
          read each other at all: it is the first thing to check when a message fails to
          arrive, and finding it any other way means instrumenting the WebAssembly module.
        */}
        <div className="min-w-0 flex-1">
          <h2 className="truncate text-body font-medium" data-epoch={String(view.epoch)}>
            {title}
          </h2>
          {/*
            "is typing…" wins over presence: typing implies being online, and showing both adds
            noise without adding information. One-to-one only — in a group, "online" would not
            say who it is talking about.
          */}
          {isTyping.length > 0 ? (
            <span className="text-caption text-(--color-ink-muted)">
              {isTyping.map((handle) => compactNameOf(handle, names, members)).join(", ")}{" "}
              {isTyping.length > 1 ? "are typing" : "is typing"}…
            </span>
          ) : (
            view.accounts.length === 1 && (
              <PresenceLine session={session} handle={view.accounts[0].handle} />
            )
          )}
        </div>

        <Tooltip label="Conversation details">
          <IconButton
            id={INFO_TOGGLE_ID}
            label="Conversation details"
            icon={<Icon name="info" size={18} />}
            aria-expanded={detailOpen}
            aria-controls={DETAIL_PANEL_ID}
            onClick={toggleDetail}
            className="shrink-0"
          />
        </Tooltip>
      </header>

      {/*
        Warns only when a fingerprint changes. In the nominal case this component renders
        nothing: a permanent warning teaches people to ignore it, and would make this one
        inaudible on the day it matters.

        It stays at the level of the conversation and does **not** move into the detail column.
        The column is closed by default and is reference material one goes looking for; this is an
        alert, and an alert nobody opened the drawer for is an alert that was never raised.
      */}
      {view.accounts.map((account) => (
        <Verification
          key={account.handle}
          account={account}
          state={session.verificationOf(account)}
        />
      ))}

      {/* No `session`, no `onChanged`, no `onError`: the thread reaches all three through the
          hooks now. What is left is what this component genuinely decides — which conversation
          is on screen, and where a reply goes once one is asked for. */}
      <Messages view={view} onReplyTo={setReplyTo} />

      {/* Off screen, never empty of purpose: it exists so that a reader already in this thread is
          told when it grows. */}
      <p aria-live="polite" aria-atomic="true" className="sr-only">
        {announcement}
      </p>

      <form
        onSubmit={send}
        // The software keyboard does not resize the window on iOS: it slides under the page
        // without firing any media query. Without this inset, the field that just took focus
        // ends up hidden by the keyboard that opened it.
        //
        // `safe-bottom` on top: the two never overlap — the gesture bar is there when the keyboard
        // is closed, and the keyboard replaces it when it opens.
        style={{ paddingBottom: occlusion || undefined }}
        className="safe-bottom safe-sides p-gutter"
      >
        {/*
          One surface, not two boxes.

          The form used to carry a top border and the field inside it carried a border, a fill and
          a radius of its own — a box drawn inside a box, which is two silhouettes competing to be
          the thing you type into. The fill and the corner now belong to this element, the buttons
          sit inside it, and the textarea is transparent within it. What the eye reads as "the
          composer" and what the DOM calls the composer are finally the same rectangle.

          The focus ring is `focus-within` rather than the textarea's own `focus-visible` for the
          same reason: focus is on the surface as far as anyone looking at it is concerned, and a
          ring drawn around a transparent textarea inside a filled block would outline a shape
          that is not there. The textarea therefore suppresses the base ring from `index.css`
          explicitly — that rule is a floor, and an element that opts out has to say so.

          What this does not solve: `focus-within` also fires for the paperclip and the emoji
          button, so the whole block rings when a keyboard user tabs onto them. Those two keep
          their own ring underneath, which is what says which of the three has focus.

          `relative` because the shortcode menu anchors here and not on the textarea. The menu is
          `left-0 w-full`, so anchoring it on the field would start it to the right of the
          paperclip and the emoji button — indented from the composer by two controls, against a
          suggestion list whose whole job is to sit under what is being typed. Edge to edge with
          the surface is also what Discord does, where the completion popover measures the full
          width of the composer rather than of the input inside it.
        */}
        <div className="relative flex flex-col rounded-surface bg-(--color-surface-raised) focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-(--color-accent)">
          {/* Opens upwards, from the top of the surface: the composer is at the bottom of the
              pane and there is nothing below it but the software keyboard. */}
          <ShortcodeMenu rows={shortcodes.rows} active={shortcodes.active} onPick={shortcodes.accept} />
          {/*
            The reply bar and the attachment chip share one strip welded to the top of the field:
            same width, radius on the top corners only, no gap. Both describe what pressing send
            is about to do, so they belong to the field rather than floating above it — and they
            can be on screen together, because replying to a message with a file is an ordinary
            thing to do.
          */}
          {(replyTo !== null || pending !== null) && (
            <div className="flex flex-col gap-tight rounded-t-surface border-b border-(--color-border-subtle) bg-(--color-surface-sunken) px-gutter py-tight text-caption text-(--color-ink-muted)">
              {replyTo !== null && (
                <div className="flex items-center justify-between gap-snug">
                  <span className="flex min-w-0 items-baseline gap-tight">
                    <span className="shrink-0 font-medium text-(--color-ink)">{citedName}</span>
                    <span className="truncate">
                      <EmojiText text={excerptOf(view, replyTo)} />
                    </span>
                  </span>
                  <IconButton
                    label="Cancel reply"
                    icon={<Icon name="close" size={16} />}
                    size="sm"
                    onClick={() => setReplyTo(null)}
                    className="shrink-0"
                  />
                </div>
              )}

              {pending !== null && (
                <div className="flex items-center justify-between gap-snug">
                  <span className="flex min-w-0 items-center gap-tight">
                    <Icon name="attach" size={14} className="shrink-0" />
                    {/* The name comes from the file system and is shown as text, never read as a
                        path — the same rule `Attachment.tsx` applies to a sender's file name. */}
                    <span className="truncate text-(--color-ink)">{pending.name}</span>
                    <span className="shrink-0">{formatSize(pending.size)}</span>
                  </span>
                  <IconButton
                    label="Remove the attachment"
                    icon={<Icon name="close" size={16} />}
                    size="sm"
                    onClick={() => setPending(null)}
                    disabled={sending}
                    className="shrink-0"
                  />
                </div>
              )}
            </div>
          )}

          <div className="flex items-end gap-gap p-gap">
            <input ref={fileInput} type="file" onChange={attach} className="hidden" />
            <IconButton
              label="Attach a file"
              icon={<Icon name="attach" size={18} />}
              onClick={() => fileInput.current?.click()}
              disabled={sending}
            />
            {/* Between the paperclip and the field, which is where every messenger puts it: the
                two things you attach to a message, in the order you reach for them. `side="top"`
                — the composer is at the bottom of the pane and there is nowhere else to open. */}
            <EmojiDrawer label="Insert an emoji" side="top" align="start" onPick={insert} />

            {/*
              A textarea, not an input. A messenger that cannot hold a line break refuses
              paragraphs, pasted addresses and anything with a list in it.

              Enter still sends, because that is what everyone's hands expect; Shift+Enter breaks
              the line. On a touch device Enter does **not** send — the on-screen keyboard's
              return key is how people write a second line, and hijacking it would make multi-line
              messages impossible on precisely the device where they are hardest to retype.

              The height follows the content up to a ceiling, past which it scrolls: a composer
              that grows without limit eats the conversation it belongs to.
            */}
            <textarea
              ref={composer}
              id={COMPOSER_ID}
              value={text}
              onChange={(e) => {
                const at = e.target.selectionStart;
                setCaret(at);
                // The closing colon first: `:joy:` becomes the emoji whether or not the menu was
                // ever opened, and `settle` says whether it took the change so this does not
                // write it twice.
                if (shortcodes.settle(e.target.value, at)) return;
                typing(e.target.value);
              }}
              // Clicking and arrowing move the caret without changing the value, and both can
              // carry it out of the `:word` the menu is completing. Without this the menu would
              // keep offering suggestions for a token the caret has left.
              onSelect={(e) => setCaret(e.currentTarget.selectionStart)}
              onBlur={shortcodes.dismiss}
              onKeyDown={(e) => {
                // The menu takes Up, Down, Enter, Tab and Escape while it is open — Enter above
                // all, which would otherwise send a message the writer was still naming an emoji
                // in.
                if (shortcodes.onKeyDown(e)) return;
                if (e.key !== "Enter" || e.shiftKey) return;
                if (matchMedia("(pointer: coarse)").matches) return;
                e.preventDefault();
                void send(e);
              }}
              rows={1}
              role="combobox"
              aria-expanded={shortcodes.open}
              aria-controls={LISTBOX_ID}
              aria-autocomplete="list"
              aria-activedescendant={shortcodes.activeId}
              aria-label={replyTo === null ? "Message" : "Reply"}
              placeholder={replyTo === null ? "Message" : "Reply"}
              // `text-base` on purpose: below 16 pixels, iOS zooms into the field on focus and
              // does not zoom back out on blur. Fixing that by forbidding zoom would strip a
              // fallback from the people who need it; fixing it by font size costs nothing.
              //
              // No fill, no border, no radius and no ring: the surface around it owns all four.
              className="max-h-32 min-w-0 flex-1 resize-none bg-transparent px-tight py-snug text-base field-sizing-content focus-visible:outline-none touch:min-h-11"
            />

            {/*
              The send button stays, and it is not negotiable.

              Under a coarse pointer Enter deliberately does not send — see the `keydown` above —
              so on a phone this button is the *only* way to send anything. Removing it because a
              desktop chat client does without one would leave every touch user with a composer
              they cannot submit. Icon only, with the name kept in `label` for the tooltip and the
              screen reader: the word disappears, the affordance does not.
            */}
            <Tooltip label="Send">
              <IconButton
                type="submit"
                label="Send"
                variant="primary"
                icon={sending ? <Spinner size="sm" /> : <Icon name="send" size={18} />}
                // Empty means nothing to do. `send` still returns early, but a control that looks
                // pressable and answers with silence is the defect this replaces.
                disabled={sending || nothingToSend}
                aria-busy={sending}
              />
            </Tooltip>
          </div>
        </div>
      </form>
    </section>
  );
}
