/**
 * Keyboard shortcuts: one place that knows what `mod` means.
 *
 * # `mod`, and why the word exists
 *
 * The same shortcut is ⌘K on a Mac and Ctrl+K everywhere else, and it is not a rendering
 * difference — the two are different keys, and treating ⌘ as Ctrl on a Mac collides with the
 * system's own bindings while Ctrl+K on Linux is what everyone's muscle memory expects. Writing
 * the combo as `"mod+k"` means the choice is made once, here, instead of at each call site with
 * a platform test somebody will forget.
 *
 * # The parser and the formatter are pure, and that is deliberate
 *
 * `parseCombo`, `formatShortcut` and `matches` take everything they need as arguments, including
 * the platform. They are the part of this module that can be wrong in a way nobody notices — an
 * off-by-one in the modifier set fires a shortcut on the wrong chord — so they are the part that
 * is tested. `useShortcut` is the thin, untestable-without-a-DOM shell around them.
 *
 * What this module does not do: it binds nothing itself, and it names no shortcut. Which chords
 * exist is `lib/keymap.ts`, and who answers them is `app/Shortcuts.tsx`. This layer is the
 * mechanism alone.
 *
 * That separation is a repair rather than a preference. This comment used to state that the
 * shell wired `mod+k`, `mod+,` and `mod+i`. Two of the three were never written: the sentence
 * was accurate when someone meant to write them and became false without a line of code
 * changing, which is the failure mode a prose list of bindings has. The registry cannot drift
 * that way — the help screen is generated from the bindings that are actually mounted.
 */
import { useEffect, useRef } from "react";

/** A combo, taken apart. Exported because the tests inspect it and the matcher consumes it. */
export interface Combo {
  /** ⌘ on Apple, Ctrl elsewhere. Resolved at match time, not at parse time. */
  mod: boolean;
  /** A literal Ctrl, asked for by name. Distinct from `mod` even on Linux, where both are Ctrl. */
  ctrl: boolean;
  /** ⌥ on Apple. */
  alt: boolean;
  shift: boolean;
  /** Lower-cased `KeyboardEvent.key`. */
  key: string;
}

const MODIFIERS = new Set(["mod", "ctrl", "control", "alt", "option", "shift", "meta", "cmd", "command"]);

/**
 * Spellings a person writes, mapped to what `KeyboardEvent.key` actually reports.
 *
 * Only the keys whose event value is not the word itself need an entry: `"space"` is `" "`, and
 * without the mapping the matcher would compare a word against a character and never fire.
 */
const KEY_ALIASES: Record<string, string> = {
  esc: "escape",
  return: "enter",
  space: " ",
  spacebar: " ",
};

/**
 * Reads `"mod+shift+k"` into its parts.
 *
 * Throws on a combo it cannot read. Combos are string literals written by a programmer, never
 * user input, so a malformed one is a bug that should surface on the first render rather than
 * become a shortcut that silently never fires.
 */
export function parseCombo(combo: string): Combo {
  const parsed: Combo = { mod: false, ctrl: false, alt: false, shift: false, key: "" };

  // Empty tokens are dropped rather than rejected: `"mod + k"` and `"mod+k"` are the same
  // intention written two ways, and there is nothing to gain from refusing one of them.
  const tokens = combo
    .split("+")
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token.length > 0);

  for (const token of tokens) {
    if (!MODIFIERS.has(token)) {
      if (parsed.key !== "") throw new Error(`shortcut "${combo}" names more than one key`);
      parsed.key = KEY_ALIASES[token] ?? token;
      continue;
    }

    // `cmd`, `command` and `meta` are aliases of `mod`, not a separate modifier. A shortcut that
    // truly wants ⌘ on a Linux keyboard — the Super key — does not exist in this application,
    // and pretending it might would mean a fourth flag that nothing ever sets.
    if (token === "meta" || token === "cmd" || token === "command") parsed.mod = true;
    else if (token === "ctrl" || token === "control") parsed.ctrl = true;
    else if (token === "alt" || token === "option") parsed.alt = true;
    else if (token === "shift") parsed.shift = true;
    else parsed.mod = true;
  }

  if (parsed.key === "") throw new Error(`shortcut "${combo}" names no key`);
  return parsed;
}

/**
 * Is this the machine where `mod` means ⌘?
 *
 * # Why `navigator.platform`, against the doctrine in `lib/platform.ts`
 *
 * That module detects Tauri by the object Tauri injects, and says so: never the user agent,
 * which webviews disguise. The same feature-test approach is unavailable here, because there is
 * no feature to test — no API reports which key the keyboard labels as the command modifier, and
 * nothing observable about the page differs.
 *
 * `navigator.platform` is the least-bad remaining source. It is deprecated and it is derived
 * from the same string as the user agent, but unlike `userAgent` it is not routinely rewritten:
 * no webview and no privacy extension has a reason to lie about it, and every engine still
 * ships it. `navigator.userAgentData.platform` is the modern replacement and is Chromium-only,
 * so relying on it would mean getting Safari — the one browser where being wrong is guaranteed
 * to be wrong — through this fallback anyway.
 *
 * What this does not solve: an iPad reports `MacIntel`, and a Mac driven by an external PC
 * keyboard still reports Apple. Both answers happen to be right for this question — the iPad's
 * on-screen keyboard has a ⌘ row, and macOS maps the PC's Windows key to ⌘ — but that is luck,
 * not design.
 */
export function isApplePlatform(): boolean {
  const platform = globalThis.navigator?.platform ?? "";
  return /mac|iphone|ipad|ipod/i.test(platform);
}

/** Keys whose `KeyboardEvent.key` is a word rather than the character it types. */
const NAMED_KEYS: Record<string, string> = {
  " ": "Space",
  arrowdown: "↓",
  arrowleft: "←",
  arrowright: "→",
  arrowup: "↑",
  backspace: "⌫",
  enter: "↵",
  escape: "Esc",
  tab: "⇥",
};

function keyLabel(key: string): string {
  return NAMED_KEYS[key] ?? key.toUpperCase();
}

/**
 * How the combo is written next to a menu item.
 *
 * Apple stacks glyphs with no separator and in a fixed order — ⌃⌥⇧⌘ — because that order is what
 * every native menu on the system uses, and a shortcut column that disagrees with the rest of
 * the machine reads as a mistake. Everywhere else the convention is words joined by `+`.
 *
 * The platform is a parameter with a default rather than a lookup, so the formatter stays pure
 * and both branches are testable on one machine.
 */
export function formatShortcut(combo: string, apple: boolean = isApplePlatform()): string {
  const parsed = parseCombo(combo);

  if (apple) {
    return (
      (parsed.ctrl ? "⌃" : "") +
      (parsed.alt ? "⌥" : "") +
      (parsed.shift ? "⇧" : "") +
      (parsed.mod ? "⌘" : "") +
      keyLabel(parsed.key)
    );
  }

  const parts: string[] = [];
  // `mod` and a literal `ctrl` are the same key here, and naming it twice would be nonsense.
  if (parsed.mod || parsed.ctrl) parts.push("Ctrl");
  if (parsed.alt) parts.push("Alt");
  if (parsed.shift) parts.push("Shift");
  parts.push(keyLabel(parsed.key));
  return parts.join("+");
}

/** The parts of a keyboard event this module reads. Narrowed so a test can supply a plain object. */
export type Chord = Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey" | "altKey" | "shiftKey">;

/**
 * Does this key press *exactly* match the combo?
 *
 * Exactly is the operative word: every modifier is compared, including the ones the combo does
 * not ask for. Without that, `mod+k` also fires on ⌘⇧K and ⌘⌥K, stealing chords that belong to
 * the browser or to a future shortcut of ours.
 *
 * `mod` resolves here rather than in the parser so that one parsed combo is valid on both
 * platforms, and so the resolution is visible at the point where it matters.
 *
 * # The one modifier that is not compared, and when
 *
 * Shift is exempt when the combo asks for a punctuation character. `?` is Shift+/ on a US
 * keyboard, Shift+, on a French one, and an unshifted key on a Spanish one: the browser reports
 * `key: "?"` with `shiftKey: true` on the first two, so a combo parsed as "? with no modifiers"
 * could never match a real press of `?`. The shift is not part of the intention, it is part of
 * how that character is typed on that layout — and which layout is in front of us is precisely
 * what we cannot know.
 *
 * Letters keep the strict comparison, because there Shift *is* an intention: `mod+k` must not
 * fire on ⌘⇧K, which is a chord somebody may want for something else.
 *
 * What this does not solve: `mod+,` and `mod+shift+,` become indistinguishable, and so does any
 * other pair that differs only by Shift on a punctuation key. Nothing here has both, and a
 * project that wanted both would have to ask the user's layout, which the platform does not
 * offer.
 */
export function matches(combo: Combo, chord: Chord, apple: boolean = isApplePlatform()): boolean {
  if (chord.key.toLowerCase() !== combo.key) return false;

  const wantsMeta = apple ? combo.mod : false;
  const wantsCtrl = combo.ctrl || (apple ? false : combo.mod);
  const punctuation = combo.key.length === 1 && !/[a-z0-9]/.test(combo.key);

  return (
    chord.metaKey === wantsMeta &&
    chord.ctrlKey === wantsCtrl &&
    chord.altKey === combo.alt &&
    (punctuation || chord.shiftKey === combo.shift)
  );
}

/** Is the press happening inside something the reader is typing into? */
function isEditing(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

/**
 * Binds a combo for as long as the component is mounted.
 *
 * On `window`, in the bubble phase: a shortcut is a global affordance, and capturing would take
 * the chord away from a Radix menu or a dialog that has its own idea about the key.
 *
 * `enabled` exists because the alternative — calling the hook conditionally — is not allowed.
 * A shortcut that must be off while a modal is open passes `false` and keeps its position in the
 * hook order.
 *
 * The handler is read through a ref so that a fresh closure on every render does not tear the
 * listener down and put it back each time. The effect then depends only on the combo and the
 * flag, which is what makes it stable.
 *
 * What this does not solve: it does not arbitrate. Two components binding the same chord both
 * run, in mount order, and nothing warns. And `preventDefault` is unconditional on a match, so
 * binding a chord the browser owns — `mod+w`, `mod+t` — will not work on the web and will
 * silently swallow it under Tauri, where the webview does not own it.
 */
export function useShortcut(combo: string, handler: () => void, enabled: boolean = true): void {
  const latest = useRef(handler);
  useEffect(() => {
    latest.current = handler;
  });

  useEffect(() => {
    if (!enabled) return;

    const parsed = parseCombo(combo);
    const apple = isApplePlatform();
    // A combo with no modifier is a bare letter, and a bare letter belongs to whatever field has
    // focus. Firing it while someone types would make the composer unusable.
    const bare = !parsed.mod && !parsed.ctrl && !parsed.alt;

    const react = (event: KeyboardEvent) => {
      // Held keys repeat at the OS rate; a shortcut is one intention, not thirty.
      if (event.repeat) return;
      if (bare && isEditing(event.target)) return;
      if (!matches(parsed, event, apple)) return;

      event.preventDefault();
      latest.current();
    };

    globalThis.addEventListener("keydown", react);
    return () => globalThis.removeEventListener("keydown", react);
  }, [combo, enabled]);
}
