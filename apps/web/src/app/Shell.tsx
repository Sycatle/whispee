import { useEffect, useRef } from "react";

import { COMPOSER_ID, Conversation } from "@/components/Conversation";
import { useDuo, useTrio } from "@/lib/duo";
import { useRevision, useSession } from "@/state/SessionProvider";
import { useNavigate, useRoute } from "@/routes/Router";
import { DetailPanel } from "./DetailPanel";
import { EmptyCenter } from "./EmptyCenter";
import { NewConversation } from "./NewConversation";
import { Rail } from "./Rail";
import { SettingsScreen } from "./SettingsScreen";

/**
 * Three columns, one route, three renderings of it.
 *
 * # The shape
 *
 * A 288 pixel rail on `surface-sunken`, a centre that takes the rest on `surface`, a 320 pixel
 * detail column on `surface-sunken`. Two sunken edges around a raised middle is what says "the
 * conversation is the thing" without a shadow, a card or a border doing the talking.
 *
 * - **`trio` (≥ 64rem)** — all three side by side. Opening the detail column *shrinks* the
 *   conversation; nothing is covered, because there is room not to cover it.
 * - **`duo` (≥ 48rem)** — rail and centre. The detail column slides in **over the right hand
 *   side of the centre**, not over the window: `absolute inset-y-0 right-0 w-80` inside the
 *   centre, with a `shadow-overlay` and a `border-strong` hairline because in the dark palette
 *   the shadow does nothing on its own. `inset-y-0` and not the logical `inset-block-0`:
 *   Tailwind v4 already emits `inset-block` for the `-y-` utilities and has no class under the
 *   logical name, so the logical spelling would compile to nothing and the panel would collapse
 *   to the height of its content.
 *
 *   **It is deliberately not a modal dialog here.** A dialog would trap focus, mark the rest
 *   `inert` and dim it — which means covering the composer. Somebody who opens the details
 *   half way through writing a message is usually checking something *in order to finish
 *   writing it*, and taking the half-written sentence away to show them a fingerprint is the
 *   one thing this panel must not do. It stays a panel: the composer keeps focus if it had it,
 *   and a click outside dismisses.
 * - **below `duo`** — one panel mounted at a time. Not hidden: a hidden conversation would keep
 *   scrolling, keep polling and keep claiming keyboard focus.
 *
 * # What is not in here
 *
 * The Android back gesture. `App.tsx:196-221` used to push a synthetic history entry and track
 * it with a flag; that block is gone, and every guarantee it made is now a property of the hash
 * router — the doc comment at the top of `routes/Router.tsx` maps them one by one. Layout does
 * not navigate: widening the window changes which panes are mounted and never touches the
 * history stack, which is exactly the case the old effect got wrong.
 */
export function Shell({ onLock, onForget }: { onLock: () => void; onForget: () => void }) {
  const session = useSession();
  const revision = useRevision();
  const route = useRoute();
  const navigate = useNavigate();
  const duo = useDuo();
  const trio = useTrio();

  const view = route.kind === "conversation" ? (session.conversations.get(route.key) ?? null) : null;
  const detailOpen = route.kind === "conversation" && route.detail !== undefined && view !== null;

  /**
   * Opening the first conversation on a wide screen, once.
   *
   * This is `App.tsx:241-243` moved to the router, and it must **replace**: the selection is the
   * layout filling a void, not a destination anybody asked for. Pushed, it would sit in history
   * as an entry whose removal changes nothing on screen, so the user's first back press would
   * appear to do nothing at all.
   *
   * It fires **only on the first resolution**, which the old code got for free by living inside
   * the poll and testing `active ?? …`. That narrowness is the whole justification: the case it
   * serves is a freshly paired device that discovers its conversations during a poll and would
   * otherwise show a full list beside an empty panel, as if the messages were not arriving when
   * they are already decrypted. Running it on every visit to `#/` would instead make the home
   * route unreachable — every back press onto it would bounce forward again, which is the same
   * broken-back-button failure this batch removed the old block to avoid.
   *
   * What it does not solve: there is now a real screen at `#/` (`EmptyCenter`), so on a device
   * that already had conversations at startup the first thing seen is that screen and not a
   * thread. That is the intended behaviour and the reason the screen was designed.
   */
  const selected = useRef(false);

  useEffect(() => {
    if (!duo || selected.current) return;
    if (route.kind !== "home") return;

    const first = session.conversations.values().next().value;
    if (!first) return;

    selected.current = true;
    navigate({ kind: "conversation", key: first.key }, { replace: true });
    // `revision` is a dependency because the conversation map is mutated in place: without it
    // this effect would never re-run when the first poll fills the map.
  }, [duo, route, session, navigate, revision]);

  const centre = () => {
    switch (route.kind) {
      case "home":
        return <EmptyCenter />;
      case "new":
        return <NewConversation />;
      case "settings":
        return <SettingsScreen section={route.section} />;
      case "conversation":
        // A well-formed key that names nothing — a stale bookmark, or a thread this device has
        // not discovered yet. `parse` deliberately does not check existence, and redirecting
        // here would race the first poll and throw away a URL that is about to become valid.
        if (view === null) {
          return (
            <div className="flex min-h-0 flex-1 items-center justify-center p-pane text-center text-body text-(--color-ink-muted)">
              This device does not know that conversation. If it was just created elsewhere, the
              next poll will bring it in.
            </div>
          );
        }
        return <Conversation view={view} />;
    }
  };

  // One panel: exactly one of the four is mounted, and which one is a property of the route
  // alone.
  if (!duo) {
    return (
      <div className="flex min-h-0 flex-1">
        {route.kind === "home" ? (
          <Rail onLock={onLock} onForget={onForget} />
        ) : detailOpen && view !== null ? (
          <DetailPanel view={view} />
        ) : (
          centre()
        )}
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1">
      {/*
        First focusable thing in the shell. Three columns means tabbing from the rail to the
        composer crosses every conversation in the list, and there can be dozens.

        A button and not an `<a href="#…">`: the router lives in the fragment, so a hash link
        would navigate the application to whatever `#conversation-composer` parses as — home —
        while scrolling to the field. The one place where the ordinary implementation of a skip
        link is actively wrong.
      */}
      <button
        type="button"
        onClick={() => document.getElementById(COMPOSER_ID)?.focus()}
        className="sr-only rounded-control bg-(--color-accent) px-pane py-snug text-body font-medium text-(--color-accent-ink) focus:not-sr-only focus:absolute focus:top-snug focus:left-snug focus:z-(--z-index-overlay)"
      >
        Skip to conversation
      </button>

      <Rail onLock={onLock} onForget={onForget} />

      {/* `relative` so the two-pane detail column can be positioned against the centre rather
          than against the window: it must cover the thread and stop at the rail. */}
      <div className="relative flex min-h-0 min-w-0 flex-1">
        {centre()}

        {!trio && detailOpen && view !== null && (
          <div className="absolute inset-y-0 right-0 z-(--z-index-overlay) w-80 max-w-full border-l border-(--color-border-strong) bg-(--color-surface-sunken) shadow-overlay duration-(--duration-panel) ease-out starting:translate-x-full motion-safe:transition-transform">
            <DetailPanel view={view} />
          </div>
        )}
      </div>

      {trio && detailOpen && view !== null && (
        <div className="w-80 shrink-0 border-l border-(--color-border-subtle)">
          <DetailPanel view={view} />
        </div>
      )}
    </div>
  );
}
