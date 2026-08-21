import { type ReactElement, useEffect, useRef, useState } from "react";

/**
 * Says out loud that the screen changed.
 *
 * # The problem a single page has and a document does not
 *
 * Following a link in a document reloads it, and a screen reader announces the new title without
 * being asked. Changing the hash does not: the DOM is rewritten in place and nothing is said, so
 * a reader who pressed Enter on a conversation is left listening to silence, with no way to tell
 * a slow network from a keystroke that did nothing. Every route in this shell had that hole —
 * conversations, settings, the new-conversation screen alike.
 *
 * # Why it is mounted once, and empty
 *
 * A live region is only announced when its contents *change* while it is being watched. Mounted
 * together with its text — the obvious way to write this — it says nothing at all, because from
 * the reader's point of view nothing changed: the region and the words appeared together. So it
 * is here, above the routes, empty until there is something to say. `ui/Toast.tsx` carries the
 * same note for the same reason.
 *
 * `polite` and never `assertive`: arriving on a screen the user asked for is not an interruption,
 * and cutting off whatever they were listening to in order to name it would be rude in exactly
 * the case where they already know what they did.
 *
 * # What it does not announce
 *
 * The first render. Loading the application and being told the name of the screen you are looking
 * at is noise; this exists for the transitions, which is where the silence was.
 *
 * It also does not move the focus, and that is a division of labour rather than an omission.
 * Opening a conversation puts the caret in the composer (`components/Conversation.tsx`), which a
 * screen reader announces on its own as it enters the field. The two say different things — this
 * one says *where you are*, the focus says *where the cursor is* — and a reader arriving in a
 * thread wants both. What would be wrong is two announcements of the same fact, which is why the
 * label here is the name of the screen and never a description of the field.
 */
export function RouteAnnouncer({ label }: { label: string }): ReactElement {
  const [said, setSaid] = useState("");
  const first = useRef(true);

  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }

    setSaid(label);
  }, [label]);

  return (
    <p aria-live="polite" aria-atomic="true" className="sr-only">
      {said}
    </p>
  );
}
