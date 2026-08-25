# One floating channel for what just happened

## Context

Successes already land well: `ui/Toast.tsx` portals a small card into `#overlays`, animates it in,
announces it politely, and expires it from `state/report.ts` rather than from a timer inside the
component. Errors do not. They render as a `Banner` with `rounded-none border-x-0 border-b-0` at
`App.tsx:683` — a full-bleed strip that is a **flex child of the shell**, so it shrinks the
conversation to make room for itself. Up to four of those can stack (`offline`, `fallback`, the
key-log warning, and this one), each squaring off its own corners through a `className` that
`Banner.tsx:52-77` already calls a workaround pinned in place rather than fixed.

Two decisions frame the work, both taken deliberately:

- **An error stays until it is dismissed or replaced.** `report.ts:13-26` argues it and the
  argument holds — an error usually means something is still to be decided. Only the rendering
  moves; the lifetime does not.
- **A message may carry an action.** "Retry" on a failed send is worth more than a sentence about
  the failure. That is a new interactive surface inside a live region, which is the part that
  needs care rather than the part that needs code.

## What is built

### Radix Toast replaces the hand-rolled portal

`@radix-ui/react-toast` (1.2.23, peer-compatible with React 19) joins the seven Radix packages
already in `apps/web/package.json`. It is chosen for one reason: a toast that carries a button has
to be **reachable by keyboard after appearing unbidden, without stealing focus**, and Radix
implements that pattern — a recall hotkey, the viewport in the tab order, and `type` driving
whether the announcement interrupts.

That mapping is the existing rule, kept: `type="foreground"` for errors (assertive, interrupts) and
`type="background"` for successes (polite). It is the same distinction `Banner.tsx:132` draws
between `alert` and `status`, and `docs/ACCESSIBILITY.md:121-127` states.

What is gained beyond the button: an **exit** animation. `Overlays.tsx:110` records that
`useEntered` has none because Radix unmounts on close; Radix Toast keeps the node through
`data-state="closed"`, so a dismissed message fades instead of vanishing.

What is given up, and must be carried over rather than lost:

- the timer stays in `report.ts`, never in the component (`Toast.tsx:10-18`) — Radix's own
  `duration` is set to `Infinity` so that it never competes for ownership of expiry;
- the viewport still portals into `#overlays` with `useOverlayContainer()`, and still carries
  `safe-bottom safe-sides` itself (`Overlays.tsx:21-30`);
- `z-(--z-index-toast)` stays above dialogs, for the reason `index.css:241` gives: an action taken
  *inside* a confirmation still has to be able to report that it worked.

### `state/report.ts` gains an id and an optional action

`Toast` already has an `id`; the error does not, so two identical errors are indistinguishable and
nothing can key a re-entrance. Both become the same shape — `{ id, message, action? }` — with
`action = { label: string, run: () => void }`.

`Report.error(message, action?)` and `Report.done(message, action?)`. Every one of the 68 existing
call sites keeps working unchanged, because the parameter is optional.

**The one coupling that must not break**: `App.tsx:445-451` calls `dismissError()` when a poll
succeeds, so a passing incident does not leave a red strip on screen forever. The poll fails every
thirty seconds while a server is down (`POLL_MS`, `App.tsx:71`), and `Rail.tsx:769-799` can raise
three errors in a row. Nothing in `report.ts` coalesces; that stays true, and the replacement
behaviour — a second error overwrites the first — is what keeps a burst from becoming a wall.

### `App.tsx` loses one banner, keeps three

Only `reported.error` moves out of the flex column. `offline`, `fallback` and the key-log warning
are **standing conditions**, not events: they describe a state the user is in, and belong in the
layout. Removing them is not part of this.

## What is not touched

- `ui/Banner.tsx` keeps its full-bleed workaround, because three callers still need it. The prop
  it asks for in its own comment stays unwritten.
- Message quality. `Rail.tsx:769-799` renders `String(error)`, so a user reads
  "Error: Failed to fetch". That is a real defect and a separate one — fixing it means writing
  sentences at 40 call sites, not changing a channel.

## Verification

**Nothing here is unit-testable, and that is a constraint rather than a choice.**
`docs/ACCESSIBILITY.md:162-165`: `node --test` runs without a DOM and `--experimental-strip-types`
does not transform JSX, so no `.test.tsx` can run at all. There are no component tests in the
repository and this adds none. What holds is the typecheck, `pnpm lint` (which enforces the naming
rules `Field`/`IconButton` carry), and a pass by hand:

1. `pnpm run typecheck`, `pnpm test`, `pnpm run lint` — the suites that exist.
2. In the browser, against the dev server: raise a success (copy a handle) and confirm it floats,
   announces, and expires by itself.
3. Stop the server and let the poll fail: the error appears as a floating card, **does not**
   shrink the conversation, and stays. Restart the server: the next successful poll clears it.
4. Fail a send with an action attached: the toast carries "Retry", the button is reachable with
   the keyboard without focus having been stolen, and pressing it re-sends.
5. Open a dialog and raise a toast from inside it — it must still be legible above the scrim.
6. `prefers-reduced-motion: reduce` in the browser's rendering panel: entrance and exit collapse
   to 1 ms through the tokens, with nothing in the component reading the preference.

## Coordination

A peer session is turning settings into a modal and holds `app/SettingsScreen.tsx`,
`app/Shell.tsx` and `ui/Dialog.tsx`. This work holds `state/report.ts`, `ui/Toast.tsx` and
`apps/web/package.json` — disjoint. **`App.tsx` is the one file both could want**: this change
touches lines 683-692 and the `Toasts` mount at 694. Worth telling them before starting, and worth
keeping the edit to those two spots.
