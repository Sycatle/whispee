import { useEffect, useRef } from "react";

import { COMPOSER_ID, Conversation } from "@/components/Conversation";
import { useDuo, useTrio } from "@/lib/duo";
import { useRevision, useSession } from "@/state/SessionProvider";
import { useNavigate, useRoute } from "@/routes/Router";
import { ConversationHeader } from "./ConversationHeader";
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
 * The window is the sunken thing. `surface-sunken` runs edge to edge as the ground, and each
 * column — the 288 pixel rail, the centre, the 320 pixel detail column — is a `surface` laid on
 * top of it with `--radius-surface` corners and `--spacing-gap` of ground showing between them
 * and around them. One gutter value, everywhere, is the whole idea: what separates two panes is
 * the space between them, so no column needs a hairline to say where it ends. That is why every
 * `border-r`/`border-l` that used to divide the columns is gone rather than merely thinner.
 *
 * The gutter is conditioned on `duo` and deliberately absent below it. Below 48rem exactly one
 * pane is mounted and it is the window; eight pixels of ground on each side of a 390 pixel
 * screen is eight pixels taken from the text, and a card that fills the viewport exactly is a
 * card that does not read as floating at all. A rounded corner needs something visible behind it
 * to mean "detached", and on one column there is nothing behind it. So: `duo:gap-gap duo:p-gap`
 * on the container, `duo:rounded-surface` on the columns, square and flush otherwise.
 *
 * **What this does not solve.** In the light palette `surface-sunken` is `oklch(0.955 0.004 265)`
 * against `surface` at `oklch(0.985 0.003 265)` — three percent of lightness between the ground
 * and the things standing on it. That is comfortable in the dark palette, where the same pair is
 * 0.13 against 0.17 and the shadow has somewhere to fall; in daylight it may well be too little,
 * and the columns may read as one flat field with seams rather than as separate surfaces. If
 * that turns out to be the case the fix is to **darken the light `surface-sunken`** until the
 * ground reads as ground. It is not to put the border back: a border and a gutter doing the same
 * job at once is the muddle this batch exists to end.
 *
 * - **`trio` (≥ 64rem)** — all three side by side. Opening the detail column *shrinks* the
 *   conversation; nothing is covered, because there is room not to cover it.
 *
 *   The conversation bar is hoisted out of the centre here and spans the centre **and** the
 *   detail column: it is a surface of its own, laid across the top of the row, and both columns
 *   below start under it. The detail column consequently has **no header of its own** at this
 *   width — no title repeating the one above it, no `[✕]`, because the control that closes it is
 *   the `[ⓘ]` in the shared bar, which is already a toggle carrying `aria-expanded`.
 * - **`duo` (≥ 48rem)** — rail and centre. The bar stays inside the centre surface, and the
 *   detail panel **keeps its own header and its own `[✕]`**. That asymmetry with `trio` is not a
 *   corner cut: at this width the panel is an overlay, lifted off the thread and painting over
 *   the right hand side of it — including over any bar drawn there. Nothing can begin "under" a
 *   surface that covers it, so a shared bar would be a bar the panel hides half of, with the
 *   close control possibly among the hidden half. The panel is detached, so it carries its own
 *   chrome. A client whose right hand column is always in flow — Discord's is — never meets this
 *   case and never has to choose.
 *
 *   The detail column slides in **over the right hand
 *   side of the centre**, not over the window: `absolute inset-y-gap right-gap w-80` inside the
 *   centre, so it is inset by the same gutter as everything else and reads as a card lifted off
 *   the thread rather than a slab welded to its edge. It keeps `shadow-overlay` and drops the
 *   `border-strong` hairline: in the dark palette the shadow does little on its own, but the
 *   gutter and the corners now carry the separation that the hairline was compensating for.
 *   `inset-y-gap` and not the logical `inset-block-gap`: Tailwind v4 already emits `inset-block`
 *   for the `-y-` utilities and has no class under the logical name, so the logical spelling
 *   would compile to nothing and the panel would collapse to the height of its content.
 *
 *   **It is deliberately not a modal dialog here.** A dialog would trap focus, mark the rest
 *   `inert` and dim it — which means covering the composer. Somebody who opens the details
 *   half way through writing a message is usually checking something *in order to finish
 *   writing it*, and taking the half-written sentence away to show them a fingerprint is the
 *   one thing this panel must not do. It stays a panel: the composer keeps focus if it had it,
 *   and a click outside dismisses.
 * - **below `duo`** — one panel mounted at a time. Not hidden: a hidden conversation would keep
 *   scrolling, keep polling and keep claiming keyboard focus. The detail panel is the whole
 *   screen when it is up, so it keeps its header and its back chevron for the plainest of
 *   reasons: there is no other bar on screen to share one with.
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

  /**
   * The conversation bar, or nothing at all.
   *
   * It is mounted by the shell rather than by the thread because at `trio` it has to span two
   * columns, and a component cannot be wider than the column it lives in. Only the conversation
   * route has one: `EmptyCenter`, `NewConversation` and `SettingsScreen` each carry a header of
   * their own describing something that is not a conversation.
   */
  const header =
    route.kind === "conversation" && view !== null ? <ConversationHeader view={view} /> : null;

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
          // The bar and the thread are siblings in a column here, where they used to be parent
          // and child. Nothing about one panel changes: the bar is still directly above the
          // messages and still the full width of the screen.
          <main className="flex min-h-0 min-w-0 flex-1 flex-col">
            {header}
            {centre()}
          </main>
        )}
      </div>
    );
  }

  // The ground the columns stand on, and the only place the gutter is declared: one `gap-gap`
  // between the columns, one `p-gap` around them, so the distance from a column to its neighbour
  // and the distance from a column to the window edge are the same number by construction rather
  // than by two values that agree today.
  return (
    <div className="flex min-h-0 flex-1 bg-(--color-surface-sunken) duo:gap-gap duo:p-gap">
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

      {/* Everything to the right of the rail: at `trio` a detached bar above a row of two columns,
          below it a single column with the bar inside it. `gap-gap` is the same gutter as
          everywhere else and it is what separates the bar from what it covers — at `duo` this
          element has one child and the gap costs nothing. */}
      <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-gap">
        {trio && header}

        <div className="flex min-h-0 min-w-0 flex-1 gap-gap">
          {/* `relative` so the two-pane detail column can be positioned against the centre rather
              than against the window: it must cover the thread and stop at the rail.

              `overflow-hidden` is what makes the rounded corners real: the children — the bar, a
              scrolling thread, a composer — all paint their own backgrounds square, and without
              the clip they would fill the corners back in. It also clips the sliding detail
              panel at the centre's right edge, which is what makes it appear from under that edge
              instead of from off-window.

              `flex-col`, because the bar is now a sibling of the thread rather than its first
              child. The thread still owns its own scrolling: it is `min-h-0 flex-1` inside its
              own section and the column above it is `min-h-0` too, so nothing here gives the
              overflow somewhere else to go. */}
          {/* `<main>`, and it took until now to exist. Two `<aside>` landmarks stood on either
              side of a plain `<div>`, so the screen where the user spends every minute had a
              named margin on the left, a named margin on the right, and nothing in the middle —
              a reader jumping by landmark could reach both edges and not the content.

              What this does not solve: at one column on the home route the rail is the whole
              screen and is still an `<aside>`, because it is genuinely the margin at every other
              width and swapping its element by breakpoint would buy less than it costs to
              explain. */}
          <main className="relative flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden bg-(--color-surface) duo:rounded-surface">
            {!trio && header}
            {centre()}

            {!trio && detailOpen && view !== null && (
              <div className="absolute inset-y-gap right-gap z-(--z-index-overlay) w-80 max-w-full overflow-hidden rounded-surface bg-(--color-surface) shadow-overlay duration-(--duration-panel) ease-out starting:translate-x-full motion-safe:transition-transform">
                <DetailPanel view={view} />
              </div>
            )}
          </main>

          {trio && detailOpen && view !== null && (
            <div className="w-80 shrink-0 overflow-hidden bg-(--color-surface) duo:rounded-surface">
              <DetailPanel view={view} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
