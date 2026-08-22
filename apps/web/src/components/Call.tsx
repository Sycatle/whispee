/**
 * The two screens a call needs: the one that rings, and the one that is a call.
 *
 * # Why the ringing screen is a sheet and the live one is a bar
 *
 * A ringing call is a question, and a question that has to be answered before anything else can
 * happen — which is what a modal is for, and the one place in this application where interrupting
 * the reader is the correct behaviour rather than a lapse.
 *
 * A call in progress is the opposite: it is a state, not a question. It sits above the thread as
 * a bar so that the conversation stays readable underneath it, because people type while they
 * talk. Putting the live call in a modal would take the conversation away from the two people
 * having it.
 *
 * # What the participant list can and cannot say
 *
 * It shows how many people are in the room, and it names those it can. A participant's name in
 * a room is derived from the call key (see `identityFor` in `lib/call.ts`), so a member can work
 * out who is who — and a *member* can also take another member's name, which is the same forgery
 * the ephemeral channel allows. The count is therefore trustworthy and the attribution is not,
 * and the interface says the count.
 */
import { useEffect, useState } from "react";

import { Avatar } from "@/ui/Avatar";
import { Button } from "@/ui/Button";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Sheet } from "@/ui/Sheet";
import { Tooltip } from "@/ui/Tooltip";
import { nameOf } from "@/lib/naming";
import { useNames } from "@/state/names";
import { useBump, useSession } from "@/state/SessionProvider";

/**
 * The bar above the thread, while a call is happening.
 *
 * Renders nothing at all when there is no call: mounting it unconditionally at the top of the
 * shell is what lets a call survive moving to another conversation, which is what a call is
 * expected to do.
 */
export function CallBar() {
  const session = useSession();
  const bump = useBump();
  const names = useNames();
  const call = session.callState();
  const elapsed = useElapsed(call.connectedAt);
  const caller = nameOf(call.from, names).primary;

  if (call.phase === "idle" || call.phase === "incoming") return null;

  const ringing = call.phase !== "connected";

  return (
    <div
      className="flex items-center gap-gutter border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-pane py-snug"
      // A live call is a running state, not a message: announcing every change of it would talk
      // over whatever the reader is doing. The controls carry their own names.
      aria-label="Call in progress"
    >
      <Icon name="call" size={18} />

      <span className="text-body text-(--color-ink)">
        {ringing
          ? "Ringing…"
          : `${caller} · ${call.peers.length + 1} on the call`}
      </span>

      {/* The duration is the one number here worth a fixed width: without `tabular-nums` the
          whole line shuffles left and right once a second. */}
      {ringing ? null : (
        <span className="text-caption tabular-nums text-(--color-ink-muted)">{elapsed}</span>
      )}

      <div className="ml-auto flex items-center gap-snug">
        <Tooltip label={call.muted ? "Unmute" : "Mute"}>
          <IconButton
            label={call.muted ? "Unmute" : "Mute"}
            aria-pressed={call.muted}
            icon={<Icon name={call.muted ? "micOff" : "mic"} size={18} />}
            disabled={ringing}
            onClick={() => void session.muteCall(!call.muted).then(bump)}
          />
        </Tooltip>

        <Button
          variant="destructive"
          size="sm"
          onClick={() => void session.hangCall().then(bump)}
        >
          <Icon name="hang" size={16} />
          Hang up
        </Button>
      </div>
    </div>
  );
}

/**
 * The sheet that rings.
 *
 * Two actions and no third: answering and refusing are the whole of what a ringing call offers,
 * and a "remind me later" would be a promise this client cannot keep — nothing would be left to
 * remind it.
 */
export function IncomingCall() {
  const session = useSession();
  const bump = useBump();
  const names = useNames();
  const call = session.callState();
  const caller = nameOf(call.from, names).primary;
  const open = call.phase === "incoming";

  return (
    <Sheet
      open={open}
      // Deliberately not dismissible into nothing: closing this sheet *is* refusing the call, and
      // a call left ringing behind a dismissed dialog would keep this device in a state its owner
      // believes they left.
      onOpenChange={(next) => {
        if (!next) void session.hangCall().then(bump);
      }}
      title={`${caller} is calling`}
      description="Audio only. Nothing is recorded, here or on the server."
      actions={
        <>
          <Button variant="secondary" onClick={() => void session.hangCall().then(bump)}>
            <Icon name="hang" size={16} />
            Decline
          </Button>
          <Button variant="primary" onClick={() => void session.acceptCall().then(bump)}>
            <Icon name="call" size={16} />
            Answer
          </Button>
        </>
      }
    >
      <div className="flex items-center gap-gutter">
        <Avatar label={caller} seed={call.from} size="lg" />
        <span className="text-body text-(--color-ink-muted)">
          {caller} wants to talk.
        </span>
      </div>
    </Sheet>
  );
}

/**
 * The elapsed time, repainted once a second.
 *
 * Its own timer rather than the session's revision counter: a call that nobody speaks during
 * changes nothing in the session for minutes, and a duration that only advances when something
 * else happens is a duration that reads as frozen.
 */
function useElapsed(since: number): string {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (since === 0) return;

    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [since]);

  if (since === 0) return "";

  const seconds = Math.max(0, Math.floor((now - since) / 1000));
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}
