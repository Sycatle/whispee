# Accessibility

This document exists because the rules it describes were real and unwritten. They lived in the
JSDoc of a dozen components, each correct, none discoverable from any other — so the only way to
learn that an icon button must carry a name was to open `ui/IconButton.tsx` and read it. That is
a workable arrangement for whoever wrote the file and no arrangement at all for anybody else.

It follows the house style of the rest of `docs/`: what was decided, why, and what it does not
solve. The last part is not optional here either. An accessibility claim that names only what it
covers teaches the next reader something false, and the gaps below are the ones that would be
found first by whoever depends on them.

## What holds the rules up

Three mechanisms, in decreasing order of how much they can be trusted.

### 1. The types, which cannot be argued with

`label` is a **required** `string` on `ui/Field.tsx` and `ui/IconButton.tsx`. An unnamed field or
an anonymous icon button is not a defect to be found in review — it does not compile. `ui/Menu.tsx`
takes a `BindingId` rather than a chord string, so a menu item cannot draw a shortcut that nothing
answers.

This is the only mechanism that has never failed, and the reason is that it does not depend on
anybody remembering anything. Prefer it whenever a rule can be expressed as a type.

What it does not solve: `ui/Field.tsx` hands its child an `id` and a `describedBy` and cannot
force the child to apply them. A caller that ignores both gets an orphaned label and nothing says
so.

### 2. The linter, for what the types cannot reach

`apps/web/eslint.config.js`, run in CI between the typecheck and the tests. It reads JSX
attributes and hand-written `role=`, which is exactly the surface where this project's defects
were found, and it knows nothing about the house components, which the compiler already holds.

Two rules from the recommended set are **off**, and the config argues both at length so that
nobody switches them back on hopefully. `control-has-associated-label` reported 27 times, every
one of them a correct `<IconButton label="…">`: the plugin sees a button and cannot see the prop
that names it, and a rule whose every finding is false teaches the reader to skim past the linter.
`prefer-tag-over-role` asked for an `<hr>` as a child of `<ol>`, an `<img>` in place of an inline
identicon, and `<output>` for a portalled toast container.

Where a rule is right in general and wrong at one site, the exemption is **local and commented**,
never a rule disabled across the tree. There are five, each naming the pattern it makes room for.

### 3. Discipline, for everything else

Which is to say: this document, and the JSDoc it points at. Everything below this line is held up
by somebody reading it.

## The rules

### Names

An `aria-label` on a `<span>` or a `<div>` names an element whose role is `generic`. ARIA forbids
it and most screen readers drop it, so the name is not weak — it is absent. Four controls had one
and were silent. Use `aria-hidden` on the mark and a `sr-only` sibling for the word, or `role="img"`
where the element genuinely is one.

An icon inside a button is decoration: the button's own name says what it does, and announcing
both reads the same thing twice. `ui/Icon.tsx` is `aria-hidden` by default for that reason.

### Lists

`role="list"` on `<ul>` and `<ol>` is redundant in the specification and required in practice.
Tailwind's preflight sets `list-style: none`, and WebKit reads a list with no marker as one the
author no longer means: VoiceOver stops saying "list, 20 items". Every list here is unstyled, so
every list here carries the role, and `jsx-a11y/no-redundant-roles` is off.

### Keyboard

**A list of interactive rows gets a roving tabindex.** The whole list is one tab stop and the
arrows move within it. A thread of twenty messages was about a hundred and sixty tab stops before
this, which is not an inaccessible interface — everything was reachable — but an unusable one, and
that distinction is invisible to an audit that only asks whether an element can be focused.

The arithmetic is in `lib/roving.ts`, pure and tested: the ends of the ring, the list that shrank
between two keystrokes, the ring of one where every move returns to where it started. Components
keep three gestures — read the rows, call it, focus what comes back. `lib/useRoving.ts` is the
hook both callers share.

Return `null` for "no move" and let the event through. An ArrowDown swallowed at the bottom of a
list is a page that can no longer be scrolled from inside it.

**Shortcuts are declared, never bound in place.** `lib/keymap.ts` is the list; components claim an
id through `app/Shortcuts.tsx`. A chord nobody claims is not listened for, so it reaches the
browser untouched, and the help screen is generated from what is actually mounted — it cannot
advertise a shortcut that does nothing on the screen the reader is looking at.

That last property is the whole point of the design. The prose list that preceded it named three
chords, two of which were never written; it read as documentation and was fiction for months.

**Anything revealed on hover must also be revealed on focus.** The action bar in `Messages.tsx`
was once `hidden group-hover:flex`: `display: none` takes an element out of the tab order, so
every per-message action was mouse-only while looking perfectly fine. It is faded rather than
hidden, and it comes back on hover, on `group-focus-within`, on an open Radix panel, and
unconditionally under a coarse pointer.

### Focus

**Radix owns the modal work.** Focus trap, `inert` on the rest, scroll lock, and the return of the
focus to whatever opened it — the last being the one nobody writes. Dialogs, sheets, menus,
popovers and tooltips all come from it. This is what `docs/THREAT-MODEL.md` bought with fifty
interface dependencies, and it is worth restating that the trade was made for exactly this.

**Hand-written focus is for the non-modal cases.** `app/DetailPanel.tsx` is deliberately not a
dialog — trapping the focus would take the half-written sentence away to show somebody a
fingerprint — so it moves the focus to its own heading and restores it to the toggle by id.

**`focus({ preventScroll: true })`, then `scrollIntoView({ block: "nearest" })`.** The browser's
own scrolling centres the element, which in a thread means arrowing up from the last message
jumps the list half a screen.

**Escape must not travel.** `app/DetailPanel.tsx` listens for Escape on `window` in the bubble
phase, so anything else that answers Escape calls `stopPropagation` — otherwise closing the rail's
filter also closes the details column, and one press dismisses two things when one was asked for.

### Announcements

A live region is announced when its contents **change** while it is being watched. Mounted
together with its text it says nothing, because from the reader's point of view nothing changed.
So every region here is mounted empty and filled later: `ui/Toast.tsx`, `app/RouteAnnouncer.tsx`,
and the new-message line in `components/Conversation.tsx`.

`polite` unless the message interrupts something the reader must stop for. `ui/Banner.tsx` is
`alert` for danger and warning, `status` for information, and the difference is whether it is
worth cutting somebody off mid-sentence.

### Motion

Durations are tokens, and `prefers-reduced-motion` sets them to 1ms in `index.css`. Anything
animated through `duration-(--duration-quick)` is covered by construction. Write
`duration-(--duration-quick)` and never `duration-quick`, which produces no rule at all and falls
back to 150ms without a warning.

### Colour

Contrast is computed, not judged by eye. The palette is OKLCH, whose lightness is not the
relative luminance WCAG asks for, so the two must be converted before any claim is made.

A border that carries meaning is a user interface component and owes 3:1 — the border of a text
field is what says where to type. `--color-border-strong` was at 2.48:1 light and 2.23:1 dark
while its own documentation called it "dark enough to be noticed"; it is now 3.11:1 and 3.01:1.
The menu highlight, the only thing telling a keyboard user which item the arrows have reached, was
at 1.14:1, which is not a faint highlight but no highlight.

Never distinguish two states by opacity alone at small sizes. The receipt marks in `Messages.tsx`
differ by weight because dimmed 12px ink measured under 3:1, and the word that tells `delivered`
from `read` is carried in full by the accessible name.

## What this does not solve

- **Screen-reader browse mode.** With NVDA and JAWS in their default mode the arrow keys belong
  to the reader, not to the page, so the roving tabindex serves sighted keyboard users and focus
  mode. For everyone else what matters is `role="list"` and the names on the buttons.
- **No component is tested.** `node --test` runs without a DOM, and `--experimental-strip-types`
  does not transform JSX, so a `.test.tsx` cannot run at all. The keyboard *logic* is tested
  because it was extracted into pure modules; that the components call those modules, and that
  `focus()` lands where it is meant to, is held by the typecheck, the linter and review.
- **No screen reader has run against this.** Every claim here is from reading specifications and
  code. Nothing in this repository has been exercised with VoiceOver, NVDA or Orca.
- **`<li role="separator">`** appears inside a `role="list"` in the thread. ARIA admits only
  `listitem` as a child, so the announced count is slightly wrong. The clean fix is a `<li>`
  wrapping the decorative element.
- **The rail is an `<aside>` even when it is the whole screen.** On one column at the home route
  it is the only thing mounted, and it is still marked as the margin.
- **The new-message live region drops rapid arrivals.** A region reports its contents, not a
  queue, so two messages inside one announcement window announce as one.
- **The interface is English**, with one exception: the membership notices in the thread go
  through `lib/i18n.ts` and exist in French. That module is a floor rather than a localisation —
  a place for strings to move to one key at a time. Everything else, including every explanation
  of what a security decision costs, is English written where it is used. Those paragraphs commit
  as much as the code does, so translating them is a piece of work with its own review rather
  than a mechanical pass.
