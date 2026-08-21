/**
 * Message thread: bubbles, folded reactions, quotes, read state.
 *
 * Split out of `page.tsx` once reactions turned a flat list into a tree: a reaction is not a
 * bubble, it is an annotation on another bubble, and the same goes for the quote in a reply.
 * Keeping that logic in the page render mixed the app layout with the shape of a conversation.
 */
import { useEffect, useRef, useState } from "react";

import { Attachment } from "@/components/Attachment";
import type { ConversationView, Session } from "@/lib/session";
import { nextExpiry } from "@/lib/signals";

/** Palette offered on hover. Deliberately short: a full picker is a different subject. */
const EMOJIS = ["👍", "❤️", "😂", "😮", "🙏"];

export function Messages({
  session,
  view,
  onChanged,
  onError,
  onReplyTo,
}: {
  session: Session;
  view: ConversationView;
  onChanged: () => void;
  onError: (message: string) => void;
  onReplyTo: (seq: number) => void;
}) {
  const bottom = useRef<HTMLDivElement>(null);

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

  const textOf = (seq: number): string => {
    const target = messages.find((message) => message.seq === seq);
    if (!target) return "message unavailable";
    if (target.content.kind === "text") return target.content.text;
    if (target.content.kind === "reply") return target.content.text;
    if (target.content.kind === "attachment") return target.content.ref.name;
    return "…";
  };

  const visible = messages.filter((message) => message.content.kind !== "reaction");

  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth" });
  }, [visible.length]);

  // "Read" means **shown to someone**. So it is decided here, in the component that renders the
  // thread — not in the poll loop, which runs even with the window closed.
  //
  // Tab visibility is part of that: a thread rendered in a background tab was delivered, not
  // read. The browser already throttles hidden tabs, which roughly produces the right behaviour
  // — but leaning on that side effect would make a privacy rule depend on a battery-saving
  // heuristic.
  useEffect(() => {
    const mark = () => {
      if (document.visibilityState === "visible") {
        session.markRead(view);
        onChanged();
      }
    };

    mark();
    document.addEventListener("visibilitychange", mark);
    return () => document.removeEventListener("visibilitychange", mark);
  }, [session, view, view.contentCursor, onChanged]);

  const react = (seq: number, emoji: string) => {
    session.reactTo(view, seq, emoji).then(onChanged).catch((e: unknown) => {
      onError(e instanceof Error ? e.message : String(e));
    });
  };

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
      <ol className="min-h-0 flex-1 space-y-2 overflow-y-auto p-4">
        {visible.map((message) => {
          // Extracted before the JSX: type narrowing is lost inside a closure, and working
          // around it inline made the render unreadable.
          const attachment = message.content.kind === "attachment" ? message.content.ref : null;
          const cite = message.content.kind === "reply" ? message.content.target : null;
          const emojis = [...(reactions.get(message.seq)?.values() ?? [])];

          return (
            <li key={message.seq} className={`group ${message.mine ? "text-right" : ""}`}>
              <div
                className={`inline-block max-w-[75%] wrap-anywhere rounded-lg px-3 py-2 text-left text-sm ${
                  message.mine
                    ? "bg-(--color-accent) text-white"
                    : "bg-(--color-surface-raised) border border-(--color-border-subtle)"
                }`}
              >
                {!message.mine && view.peers.length > 1 && (
                  <span className="block text-xs opacity-70">{message.sender ?? "unknown"}</span>
                )}

                {cite !== null && (
                  <span className="mb-1 block border-l-2 border-current/40 pl-2 text-xs opacity-70">
                    {textOf(cite)}
                  </span>
                )}

                {attachment ? (
                  <Attachment
                    attachment={attachment}
                    onOpen={() => session.openAttachment(view, attachment)}
                  />
                ) : message.content.kind === "text" ? (
                  message.content.text
                ) : message.content.kind === "reply" ? (
                  message.content.text
                ) : null}

                {message.mine && <Status state={session.statusOf(view, message.seq)} />}
              </div>

              {emojis.length > 0 && (
                <div className="mt-0.5 text-xs" aria-label="reactions">
                  {emojis.join(" ")}
                </div>
              )}

              <div className="mt-0.5 hidden gap-1 text-xs group-hover:flex" data-actions>
                {EMOJIS.map((emoji) => (
                  <button
                    key={emoji}
                    type="button"
                    onClick={() => react(message.seq, emoji)}
                    className="rounded px-1 hover:bg-(--color-surface-raised)"
                    title={`React ${emoji}`}
                  >
                    {emoji}
                  </button>
                ))}
                <button
                  type="button"
                  onClick={() => onReplyTo(message.seq)}
                  className="rounded px-1 opacity-70 hover:bg-(--color-surface-raised)"
                >
                  Reply
                </button>
              </div>
            </li>
          );
        })}
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
        <p className="px-4 pb-1 text-xs opacity-60" aria-live="polite">
          {isTyping.map((handle) => `@${handle}`).join(", ")}{" "}
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
 */
function Status({ state }: { state: "sent" | "delivered" | "read" }) {
  const label = { sent: "sent", delivered: "delivered", read: "read" }[state];
  const mark = { sent: "✓", delivered: "✓✓", read: "✓✓" }[state];

  return (
    <span
      className={`ml-2 align-bottom text-xs ${state === "read" ? "opacity-100" : "opacity-60"}`}
      title={label}
      aria-label={label}
      data-receipt={state}
    >
      {mark}
    </span>
  );
}
