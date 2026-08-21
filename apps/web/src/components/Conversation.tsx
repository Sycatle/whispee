import { useEffect, useRef, useState } from "react";

import { Messages } from "@/components/Messages";
import { PresenceLine } from "@/components/Presence";
import { Verification } from "@/components/Verification";
import { DETAIL_PANEL_ID, INFO_TOGGLE_ID } from "@/app/DetailPanel";
import { useDuo } from "@/lib/duo";
import { compactNameOf, type NameSources } from "@/lib/naming";
import type { ConversationView } from "@/lib/session";
import { useShortcut } from "@/lib/shortcuts";
import { useOcclusion } from "@/lib/viewport";
import { Button } from "@/ui/Button";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
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
  const fileInput = useRef<HTMLInputElement>(null);
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

  const send = async (event: { preventDefault: () => void }) => {
    event.preventDefault();
    const body = text.trim();
    if (!body) return;
    setText("");
    session.setDraft(view, "");
    const cite = replyTo;
    setReplyTo(null);

    // A plain message cannot fail here any more: `send` queues it, shows it, and reports a
    // failure on the bubble itself. A reply still can — it points at a sequence number, which is
    // exactly what a queued message has not got — so that one keeps the banner.
    if (cite === null) {
      await session.send(view, body);
      bump();
      return;
    }

    try {
      await session.replyTo(view, cite, body);
      bump();
    } catch (e) {
      report.error(e instanceof Error ? e.message : String(e));
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

  const attach = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    // The input is reset right away: without it, picking the same file twice would not fire a
    // second `change`.
    event.target.value = "";
    if (!file) return;

    setSending(true);
    try {
      await session.sendAttachment(view, file);
      bump();
    } catch (e) {
      report.error(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
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

      {replyTo !== null && (
        <div className="flex items-center justify-between gap-snug border-t border-(--color-border-subtle) px-pane py-tight text-caption text-(--color-ink-muted)">
          <span className="truncate">Replying to message {replyTo}</span>
          <Button variant="quiet" size="sm" onClick={() => setReplyTo(null)} className="shrink-0">
            Cancel
          </Button>
        </div>
      )}

      <form
        onSubmit={send}
        // The software keyboard does not resize the window on iOS: it slides under the page
        // without firing any media query. Without this inset, the field that just took focus
        // ends up hidden by the keyboard that opened it.
        //
        // `safe-bottom` on top: the two never overlap — the gesture bar is there when the keyboard
        // is closed, and the keyboard replaces it when it opens.
        style={{ paddingBottom: occlusion || undefined }}
        className="safe-bottom safe-sides flex items-center gap-snug border-t border-(--color-border-subtle) p-gutter"
      >
        <input ref={fileInput} type="file" onChange={attach} className="hidden" />
        <IconButton
          label="Attach a file"
          icon={<Icon name="attach" size={18} />}
          variant="secondary"
          onClick={() => fileInput.current?.click()}
          disabled={sending}
        />
        {/*
          A textarea, not an input. A messenger that cannot hold a line break refuses paragraphs,
          pasted addresses and anything with a list in it.

          Enter still sends, because that is what everyone's hands expect; Shift+Enter breaks the
          line. On a touch device Enter does **not** send — the on-screen keyboard's return key is
          how people write a second line, and hijacking it would make multi-line messages
          impossible on precisely the device where they are hardest to retype.

          The height follows the content up to a ceiling, past which it scrolls: a composer that
          grows without limit eats the conversation it belongs to.
        */}
        <textarea
          id={COMPOSER_ID}
          value={text}
          onChange={(e) => typing(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== "Enter" || e.shiftKey) return;
            if (matchMedia("(pointer: coarse)").matches) return;
            e.preventDefault();
            void send(e);
          }}
          rows={1}
          aria-label={replyTo === null ? "Message" : "Reply"}
          placeholder={replyTo === null ? "Message" : "Reply"}
          // `text-base` on purpose: below 16 pixels, iOS zooms into the field on focus and does
          // not zoom back out on blur. Fixing that by forbidding zoom would strip a fallback
          // from the people who need it; fixing it by font size costs nothing.
          className="max-h-32 min-w-0 flex-1 resize-none rounded-control border border-(--color-border-subtle) bg-(--color-surface-raised) px-gutter py-snug text-base field-sizing-content focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-accent) touch:min-h-11"
        />
        <Button type="submit" variant="primary" icon={<Icon name="send" size={16} />}>
          Send
        </Button>
      </form>
    </section>
  );
}
