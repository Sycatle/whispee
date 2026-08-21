import { useEffect, useRef, useState } from "react";
import { useOcclusion } from "@/lib/viewport";
import { GroupPanel, GroupToggle } from "@/components/Group";
import { Messages } from "@/components/Messages";
import { PresenceLine } from "@/components/Presence";
import { Verification, VerificationPanel, VerificationToggle } from "@/components/Verification";
import { type ConversationView, Session } from "@/lib/session";

export function Conversation({
  session,
  view,
  onChanged,
  onError,
  onBack,
}: {
  session: Session;
  view: ConversationView;
  onChanged: () => void;
  onError: (message: string) => void;
  /**
   * Back to the list, when the list is not shown alongside.
   *
   * Absent in the two-pane layout: a back button there would point at an already visible screen.
   * Its presence is therefore what tells this component it owns the whole screen.
   */
  onBack?: () => void;
}) {
  const [text, setText] = useState("");
  const [verifying, setVerifying] = useState<string | null>(null);
  const [group, setGroup] = useState(false);
  const [sending, setSending] = useState(false);
  const [replyTo, setReplyTo] = useState<number | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const occlusion = useOcclusion();

  // Pulls the archived history back in when the conversation opens.
  //
  // Lazy and non-blocking: the conversation shows immediately, the past fills in behind it.
  // `hydrate` only does the work once per session, so re-running this effect when the view
  // changes identity is harmless.
  useEffect(() => {
    session
      .hydrate(view)
      .then((restored) => {
        if (restored > 0) onChanged();
      })
      .catch((e: unknown) => onError(e instanceof Error ? e.message : String(e)));
  }, [session, view, onChanged, onError]);

  const send = async (event: React.FormEvent) => {
    event.preventDefault();
    const body = text.trim();
    if (!body) return;
    setText("");
    const cite = replyTo;
    setReplyTo(null);

    // A plain message cannot fail here any more: `send` queues it, shows it, and reports a
    // failure on the bubble itself. A reply still can — it points at a sequence number, which is
    // exactly what a queued message has not got — so that one keeps the banner.
    if (cite === null) {
      await session.send(view, body);
      onChanged();
      return;
    }

    try {
      await session.replyTo(view, cite, body);
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
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
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
  };

  const isTyping = session.typingIn(view);

  const title =
    view.accounts.map((a) => `@${a.handle}`).join(", ") ||
    [...new Set(view.peers.map((p) => p.name))].map((n) => `@${n}`).join(", ") ||
    "empty conversation";

  return (
    <section className="flex min-w-0 flex-1 flex-col">
      <header className="flex items-baseline justify-between gap-4 border-b border-(--color-border-subtle) px-4 py-2">
        {onBack && (
          <button
            type="button"
            onClick={onBack}
            aria-label="Back to conversations"
            className="-ml-2 shrink-0 self-center px-2 py-1 text-xl leading-none text-(--color-ink-muted) touch:min-h-11"
          >
            ‹
          </button>
        )}
        {/*
          The epoch is not displayed — it is a protocol detail that teaches the user nothing.
          It is exposed as an attribute because two members on different epochs can no longer
          read each other at all: it is the first thing to check when a message fails to
          arrive, and finding it any other way means instrumenting the WebAssembly module.
        */}
        <div className="min-w-0">
          <h2 className="truncate text-sm font-medium" data-epoch={String(view.epoch)}>
            {title}
          </h2>
          {/*
            "is typing…" wins over presence: typing implies being online, and showing both adds
            noise without adding information. One-to-one only — in a group, "online" would not
            say who it is talking about.
          */}
          {isTyping.length > 0 ? (
            <span className="text-xs text-(--color-ink-muted)">
              {isTyping.map((handle) => `@${handle}`).join(", ")}{" "}
              {isTyping.length > 1 ? "are typing" : "is typing"}…
            </span>
          ) : (
            view.accounts.length === 1 && (
              <PresenceLine session={session} handle={view.accounts[0].handle} />
            )
          )}
        </div>
        <div className="flex shrink-0 gap-3">
          {view.accounts.length > 1 && (
            <GroupToggle count={view.accounts.length} onClick={() => setGroup(!group)} />
          )}
          {view.accounts.map((account) => (
            <VerificationToggle
              key={account.handle}
              state={session.verificationOf(account)}
              onClick={() => setVerifying(verifying === account.handle ? null : account.handle)}
            />
          ))}
        </div>
      </header>

      {group && (
        <GroupPanel
          session={session}
          view={view}
          onError={onError}
          onChanged={onChanged}
          onClose={() => setGroup(false)}
        />
      )}

      {/*
        Warns only when a fingerprint changes. In the nominal case this component renders
        nothing: a permanent warning teaches people to ignore it, and would make this one
        inaudible on the day it matters.
      */}
      {view.accounts.map((account) => (
        <Verification
          key={account.handle}
          account={account}
          state={session.verificationOf(account)}
        />
      ))}

      {view.accounts
        .filter((account) => account.handle === verifying)
        .map((account) => (
          <VerificationPanel
            key={account.handle}
            account={account}
            state={session.verificationOf(account)}
            myName={`@${session.handle}`}
            myFingerprint={session.accountFingerprint()}
            onVerified={() => void session.markVerified(account).then(onChanged)}
            onClose={() => setVerifying(null)}
          />
        ))}

      <Messages
        session={session}
        view={view}
        onChanged={onChanged}
        onError={onError}
        onReplyTo={setReplyTo}
      />


      {replyTo !== null && (
        <div className="flex items-center justify-between gap-2 border-t border-(--color-border-subtle) px-4 py-1 text-xs opacity-70">
          <span className="truncate">Replying to message {replyTo}</span>
          <button type="button" onClick={() => setReplyTo(null)} className="shrink-0">
            cancel
          </button>
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
        className="safe-bottom flex items-center gap-2 border-t border-(--color-border-subtle) p-3"
      >
        <input ref={fileInput} type="file" onChange={attach} className="hidden" />
        <button
          type="button"
          onClick={() => fileInput.current?.click()}
          disabled={sending}
          title="Attach a file"
          className="rounded-md border border-(--color-border-subtle) px-3 py-2 text-sm touch:min-h-11 touch:min-w-11 disabled:opacity-50"
        >
          {sending ? "…" : "📎"}
        </button>
        <input
          value={text}
          onChange={(e) => typing(e.target.value)}
          placeholder={replyTo === null ? "Message" : "Reply"}
          // `text-base` on purpose: below 16 pixels, iOS zooms into the field on focus and does
          // not zoom back out on blur. Fixing that by forbidding zoom would strip a fallback
          // from the people who need it; fixing it by font size costs nothing.
          className="min-w-0 flex-1 rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-3 py-2 text-base touch:min-h-11"
        />
        <button
          type="submit"
          className="rounded-md bg-(--color-accent) px-4 py-2 text-sm font-medium text-white touch:min-h-11"
        >
          Send
        </button>
      </form>
    </section>
  );
}
