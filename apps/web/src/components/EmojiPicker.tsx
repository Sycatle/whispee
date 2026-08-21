import { useEffect, useMemo, useRef, useState } from "react";

import { useDuo } from "@/lib/duo";
import {
  type Catalogue,
  type Entry,
  TONE_SAMPLES,
  type Tone,
  applyTone,
  catalogue,
  search,
} from "@/lib/emoji";
import { useSession } from "@/state/SessionProvider";
import { cn } from "@/ui/cn";
import { Emoji } from "@/ui/Emoji";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Input } from "@/ui/Input";
import { Popover } from "@/ui/Popover";
import { Sheet } from "@/ui/Sheet";
import { Spinner } from "@/ui/Spinner";

/**
 * The grid of emoji, and the only place that enumerates them.
 *
 * # It reads the session rather than receiving it
 *
 * The recents list and the skin tone live in `Preferences`, and the rule at the top of
 * `state/SessionProvider.tsx` applies: a mutable object handed down a prop is only as fresh as
 * its parent's render schedule. `onPick` stays a prop because what a pick *means* — a reaction
 * here, an insertion there — is the caller's business and not this component's.
 *
 * # The catalogue arrives late, on purpose
 *
 * 238 kB of names and keywords, loaded by a dynamic import the first time a picker opens and
 * memoised in `lib/emoji.ts` for every one after. It is not needed to *render* an emoji —
 * `ui/Emoji.tsx` computes a sheet key from codepoints — only to list, name and search them. That
 * is why the initial bundle does not carry it and a message bubble never waits for it.
 *
 * # Why there is no virtualisation library, and no `content-visibility`
 *
 * The cost that used to matter here was the network: 1,595 cells meant 1,595 image requests, and
 * `loading="lazy"` was the whole strategy. That is gone. The artwork now arrives in one sheet and
 * every cell draws from it with no request of its own (`lib/emoji-sprite.ts`).
 *
 * `content-visibility: auto` per section was tried, twice, and is deliberately absent. The first
 * time it had to come out because it does not compose with `loading="lazy"`: images inside a
 * skipped subtree unload, and scrolling with the arrow keys left blank rows filling in behind the
 * cursor. That objection died with the images — but the remaining benefit is layout and paint for
 * sections nobody is looking at, which the browser is good at, against a real cost in scroll
 * jitter when `contain-intrinsic-size` guesses a section's height wrong. Adding it back would be
 * trading a measured annoyance for an unmeasured saving.
 *
 * What is left is 1,914 buttons in one tree, which is large and ordinary. If it ever measures
 * badly the answer is virtualising the rows, not a CSS property that only skips paint.
 *
 * # What this does not solve
 *
 * Nothing about coverage, any more. Twemoji draws every emoji the catalogue lists — flags,
 * keycaps, `©️` — and the generator refuses to emit an entry it has no artwork for.
 *
 * This is not the only way to reach an emoji, and deliberately not the fastest. Somebody who
 * knows a name types `:joy:` into the composer and never opens this panel at all — see
 * `components/Shortcodes.tsx`. A grid is for the case where you know roughly what you want and
 * not what it is called.
 */

/** The keyboard's idea of the grid. Twelve is what fits the popover at the width it opens. */
const COLUMNS = 12;

const TONE_NAMES = ["default", "light", "medium-light", "medium", "medium-dark", "dark"];

/** The label the recents section carries. Written once: two spellings would be two sections. */
const RECENTS = "Recently used";

/**
 * One emoji standing for each section, in the jump bar.
 *
 * Artwork and not `ui/Icon.tsx`, deliberately, and it is the one place in the application where
 * an emoji is chrome. The inventory in `Icon.tsx` is line art naming *actions*; there is no line
 * drawing of "food and drink" that reads at 18 px, and every other picker in existence uses the
 * emoji themselves — so a reader already knows what a bear at the top of a grid means.
 *
 * Keyed by label so a section without an icon simply gets none, rather than the wrong one: the
 * groups come from the generated catalogue, and a Unicode release that adds one must not silently
 * shift every icon by a position.
 */
const SECTION_ICONS: Record<string, string> = {
  [RECENTS]: "\u{1f558}",
  "Smileys & Emotion": "\u{1f600}",
  "People & Body": "\u{1f44b}",
  "Animals & Nature": "\u{1f43b}",
  "Food & Drink": "\u{1f34e}",
  "Travel & Places": "\u{1f697}",
  Activities: "\u26bd",
  Objects: "\u{1f4a1}",
  Symbols: "\u{1f523}",
  Flags: "\u{1f3c1}",
};

/** A category as the grid lays it out: a heading, and the emoji under it. */
interface Section {
  label: string;
  entries: Entry[];
}

/**
 * Cuts a category into rows of `COLUMNS`.
 *
 * ARIA's grid wants rows that contain cells. One `role="row"` holding two hundred `gridcell`s
 * would be announced as a single row two hundred columns wide, and a screen reader's own grid
 * navigation — which is not the arrow handling below, but its own layer on top — would move
 * through it in one dimension. The rows have to be real.
 */
function rowsOf(entries: Entry[]): Entry[][] {
  const rows: Entry[][] = [];
  for (let at = 0; at < entries.length; at += COLUMNS) rows.push(entries.slice(at, at + COLUMNS));
  return rows;
}

function sectionsOf(from: Catalogue, recents: Entry[]): Section[] {
  const groups = from.groups.map((label) => ({ label, entries: [] as Entry[] }));
  for (const entry of from.entries) groups[entry.group]?.entries.push(entry);

  return [
    // Recents first and only when there are any: an empty "Recently used" heading is a promise
    // the interface has not kept yet.
    ...(recents.length > 0 ? [{ label: RECENTS, entries: recents }] : []),
    ...groups.filter((group) => group.entries.length > 0),
  ];
}

export function EmojiPicker({ onPick }: { onPick: (emoji: string) => void }) {
  const session = useSession();
  const [loaded, setLoaded] = useState<Catalogue | null>(null);
  const [query, setQuery] = useState("");
  // The tone lives in `Preferences`, but a click has to repaint the grid now rather than after
  // the write reaches disk, so the chosen value is mirrored here.
  const [tone, setTone] = useState<Tone>(session.preferences.skinTone ?? 0);
  const grid = useRef<HTMLDivElement>(null);
  /** Index of the section the scroller is currently showing, for the jump bar's marker. */
  const [current, setCurrent] = useState(0);

  useEffect(() => {
    let live = true;
    void catalogue().then((value) => {
      if (live) setLoaded(value);
    });
    // The import is memoised, so an unmount mid-flight wastes nothing — this only stops a state
    // update on a component that is gone.
    return () => {
      live = false;
    };
  }, []);

  const sections = useMemo(() => {
    if (!loaded) return [];
    if (query.trim()) {
      // No section at all when nothing matches, rather than an empty one: a "Results" heading
      // above a blank panel reads as a grid that failed to load, and hides the message below
      // that says what actually happened.
      const found = search(loaded, query);
      return found.length > 0 ? [{ label: "Results", entries: found }] : [];
    }

    const known = new Map(loaded.entries.map((entry) => [entry.char, entry]));
    const recents = session.preferences.recentEmojis
      .map((char) => known.get(char))
      // An emoji remembered before a catalogue bump that dropped it would otherwise be a hole in
      // the first row.
      .filter((entry): entry is Entry => entry !== undefined);

    return sectionsOf(loaded, recents);
  }, [loaded, query, session.preferences.recentEmojis]);

  const pick = (entry: Entry) => {
    const char = applyTone(entry, tone);
    onPick(char);
    void session.noteEmojiUse(char);
  };

  /**
   * Scrolls a section to the top of the grid.
   *
   * Arithmetic on `scrollTop` rather than `scrollIntoView`, for two reasons. `scrollIntoView`
   * scrolls **every** ancestor that can scroll, so on a phone it drags the whole conversation
   * behind the sheet. And it has no notion of the sticky heading sitting at the top of this
   * scroller: aligning the section's own top with the viewport's puts the first row of emoji
   * underneath the heading of the section above it.
   */
  const jump = (index: number) => {
    const scroller = grid.current;
    const section = scroller?.querySelector<HTMLElement>(`[data-section="${index}"]`);
    if (!scroller || !section) return;

    scroller.scrollTop = section.offsetTop;
    setCurrent(index);
  };

  /**
   * Which section the reader is looking at.
   *
   * Read off `scrollTop` on every scroll rather than watched with an `IntersectionObserver`: the
   * sections are already in the DOM and their offsets are already computed, so this is a loop
   * over nine numbers against an observer with nine registrations and a callback that fires on
   * its own schedule. The `+ 1` absorbs the sub-pixel rounding that would otherwise leave the
   * marker one section behind after a jump.
   */
  const track = () => {
    const scroller = grid.current;
    if (!scroller) return;

    const sections = [...scroller.querySelectorAll<HTMLElement>("[data-section]")];
    const top = scroller.scrollTop + 1;

    let at = 0;
    for (const [index, section] of sections.entries()) {
      if (section.offsetTop <= top) at = index;
    }
    setCurrent(at);
  };

  const chooseTone = (next: Tone) => {
    setTone(next);
    void session.updatePreferences((preferences) => {
      preferences.skinTone = next;
    });
  };

  /**
   * Two-dimensional movement over what is, in the DOM, a flat list of buttons.
   *
   * Reading the cells back out of the DOM rather than tracking an index in state: the list
   * changes shape on every keystroke in the search field, and an index into a list that just got
   * shorter points at nothing. The DOM is the one description of the grid that cannot be stale.
   *
   * Down and up move by `COLUMNS`, which is right only because the grid is a fixed twelve columns
   * — the class list below and this constant have to agree, and there is no mechanism enforcing
   * that beyond both being in this file.
   */
  const navigate = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const moves: Record<string, number> = {
      ArrowRight: 1,
      ArrowLeft: -1,
      ArrowDown: COLUMNS,
      ArrowUp: -COLUMNS,
    };
    const step = moves[event.key];
    if (step === undefined) return;

    const cells = [...(grid.current?.querySelectorAll<HTMLButtonElement>("[data-cell]") ?? [])];
    const from = cells.indexOf(document.activeElement as HTMLButtonElement);
    if (from === -1) return;

    const to = from + step;
    if (to < 0 || to >= cells.length) return;

    // Only once a move is actually going to happen: swallowing ArrowUp at the top edge would
    // trap the caret in the grid instead of letting it back into the search field.
    event.preventDefault();
    cells[to].focus();
  };

  return (
    <div className="flex w-[22rem] max-w-full flex-col">
      <div className="p-snug">
        <Input
          type="search"
          aria-label="Search emoji"
          placeholder="Search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            // Down from the field enters the grid. Without it the only way in is Tab, which on a
            // grid of 1,914 roving-tabindex cells lands on exactly one of them anyway — but a
            // person who has just typed a query expects the arrow key to do this.
            if (event.key !== "ArrowDown") return;
            event.preventDefault();
            grid.current?.querySelector<HTMLButtonElement>("[data-cell]")?.focus();
          }}
        />
      </div>

      {/*
        The jump bar. Hidden while searching, because there is then exactly one section and a row
        of buttons that all scroll to the same place is a row of buttons that lies.

        Buttons and not tabs: a tab shows one panel and hides the others, and these scroll a single
        list. Announcing them as tabs would promise a reader that the grid changes when it only
        moves, and leave them wondering where the other nine panels went.
      */}
      {!query.trim() && sections.length > 1 && (
        <div
          role="group"
          aria-label="Jump to a category"
          className="flex items-center gap-tight border-b border-(--color-border-subtle) px-snug pb-tight"
        >
          {sections.map((section, index) => (
            <button
              key={section.label}
              type="button"
              aria-label={section.label}
              title={section.label}
              // The marker is a state, so it is announced and not only drawn. `aria-label` names
              // the section; this says whether it is the one on screen.
              aria-current={index === current ? "true" : undefined}
              onClick={() => jump(index)}
              className={cn(
                "relative flex flex-1 items-center justify-center rounded-control py-tight",
                "transition-colors duration-(--duration-quick) ease-out motion-reduce:transition-none",
                "hover:bg-(--color-surface-sunken)",
                "focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent)",
                // The underline rather than a filled pill: the icons are full-colour artwork, and
                // a tinted background behind one of them just makes it look broken.
                index === current &&
                  "after:absolute after:inset-x-1 after:bottom-0 after:h-px after:bg-(--color-accent)",
                index !== current && "opacity-60",
              )}
            >
              <Emoji char={SECTION_ICONS[section.label] ?? section.label.slice(0, 1)} />
            </button>
          ))}
        </div>
      )}

      {/* The rule wants the grid itself focusable. This one carries a roving tabindex instead
          (see the cells below): exactly one cell is a tab stop and the arrows move it, which is
          the pattern the grid role is defined around. Focusing the container as well would add a
          second tab stop that lands nowhere in particular. */}
      {/* eslint-disable-next-line jsx-a11y/interactive-supports-focus */}
      <div
        ref={grid}
        role="grid"
        aria-label="Emoji"
        onKeyDown={navigate}
        onScroll={track}
        // `relative` is load-bearing: `jump` reads `section.offsetTop`, which is measured from the
        // nearest positioned ancestor. Without it the offsets are relative to whatever the sheet
        // or the popover happens to position, and every jump lands somewhere else.
        className="relative h-72 overflow-y-auto px-snug"
      >
        {loaded === null ? (
          <div className="flex h-72 items-center justify-center">
            <Spinner label="Loading emoji" />
          </div>
        ) : sections.length === 0 ? (
          <p className="flex h-72 items-center justify-center px-pane text-center text-caption text-(--color-ink-muted)">
            {`No emoji matching “${query.trim()}”.`}
          </p>
        ) : (
          sections.map((section, index) => (
            <section key={section.label} data-section={index}>
              <h3 className="sticky top-0 z-(--z-index-sticky) bg-(--color-surface-raised) py-tight text-caption text-(--color-ink-muted)">
                {section.label}
              </h3>

              {rowsOf(section.entries).map((row, line) => (
                <div key={row[0].char} role="row" className="grid grid-cols-12">
                  {row.map((entry, column) => (
                    <button
                      // The character, not the position: the same emoji never appears twice in a
                      // section, and keying on position would re-key the whole grid on every
                      // keystroke in the search field.
                      key={entry.char}
                      type="button"
                      role="gridcell"
                      data-cell
                      // Roving tabindex: exactly one cell in the whole grid is reachable by Tab,
                      // and the arrow keys move between them. 1,914 tab stops is not a grid, it
                      // is a wall.
                      tabIndex={index === 0 && line === 0 && column === 0 ? 0 : -1}
                      aria-label={entry.label}
                      title={entry.label}
                      onClick={() => pick(entry)}
                      className={cn(
                        "flex aspect-square items-center justify-center rounded-control text-[1.4rem]",
                        "transition-colors duration-(--duration-quick) ease-out motion-reduce:transition-none",
                        "hover:bg-(--color-surface-sunken)",
                        "focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent)",
                      )}
                    >
                      <Emoji char={applyTone(entry, tone)} />
                    </button>
                  ))}
                </div>
              ))}
            </section>
          ))
        )}
      </div>

      <div
        role="radiogroup"
        aria-label="Skin tone"
        className="flex items-center gap-tight border-t border-(--color-border-subtle) p-snug"
      >
        {TONE_SAMPLES.map((sample, index) => (
          <button
            key={sample}
            type="button"
            role="radio"
            aria-checked={tone === index}
            aria-label={`Skin tone: ${TONE_NAMES[index]}`}
            onClick={() => chooseTone(index as Tone)}
            className={cn(
              "flex h-7 w-7 items-center justify-center rounded-control text-[1.1rem]",
              "focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent)",
              tone === index ? "bg-(--color-surface-sunken)" : "hover:bg-(--color-surface-sunken)",
            )}
          >
            <Emoji char={sample} />
          </button>
        ))}
      </div>
    </div>
  );
}

/**
 * The picker, its button, and the decision of what shape to open in.
 *
 * Both call sites — the reaction bar and the composer — want the same thing: a button that opens
 * a grid and hands back one emoji. Giving them a component that owns its own trigger is what
 * keeps that from being written twice, and keeps the popover-or-sheet rule from being written
 * twice with one of the two forgotten.
 *
 * # A popover above `duo`, a sheet below it
 *
 * A 22rem panel anchored to a button is a window inside a window on a phone: it covers most of
 * the screen while pretending to float beside something. Below 48rem the grid goes in the modal
 * sheet the rest of the application already uses, which takes the whole screen and comes up from
 * the bottom edge.
 *
 * `useDuo()` and not a `duo:` variant, unlike `Sheet` itself: this decides **which component to
 * mount**, which is a question about state, not about appearance. There is no first-paint flash
 * to avoid because nothing is mounted until the button is pressed.
 *
 * # Closing before reporting
 *
 * `setOpen(false)` comes first and `onPick` second. The other order sends the emoji while the
 * panel is still open, and on the reaction bar that means a re-render of the thread underneath a
 * popover anchored to a button that may have moved.
 */
export function EmojiDrawer({
  label,
  size = "md",
  onPick,
  side = "top",
  align = "start",
}: {
  /** The accessible name of the button. Names the action: "React with an emoji". */
  label: string;
  size?: "sm" | "md";
  onPick: (emoji: string) => void;
  side?: "top" | "bottom";
  align?: "start" | "center" | "end";
}) {
  const [open, setOpen] = useState(false);
  const duo = useDuo();

  const pick = (emoji: string) => {
    setOpen(false);
    onPick(emoji);
  };

  const button = (
    <IconButton
      label={label}
      icon={<Icon name="emoji" size={size === "sm" ? 16 : 18} />}
      size={size}
      {...(duo ? {} : { onClick: () => setOpen(true) })}
    />
  );

  if (duo) {
    return (
      <Popover trigger={button} open={open} onOpenChange={setOpen} label="Emoji" side={side} align={align}>
        <EmojiPicker onPick={pick} />
      </Popover>
    );
  }

  return (
    <>
      {button}
      {/* `hideTitle`: the grid says what it is, and a heading over it would only eat the height a
          phone does not have. The name stays in the accessibility tree either way. */}
      <Sheet open={open} onOpenChange={setOpen} title="Emoji" hideTitle>
        <EmojiPicker onPick={pick} />
      </Sheet>
    </>
  );
}
