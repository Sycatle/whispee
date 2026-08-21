import type { ReactElement, ReactNode } from "react";
import * as RadixMenu from "@radix-ui/react-dropdown-menu";
import { formatShortcut } from "../lib/shortcuts.ts";
import { cn } from "./cn.ts";
import { Icon, type IconName } from "./Icon.tsx";
import { useOverlayContainer } from "./Overlays.tsx";

/**
 * A list of actions that appears next to whatever opened it.
 *
 * # The profile menu, and the 480px window
 *
 * The first caller is the control at the bottom of the rail, which is the widest thing this menu
 * will ever have to fit beside and the closest to two edges of the screen. `tauri.conf.json`
 * declares `minWidth: 480`, and the rail plus a menu that opens to its right does not fit in 480
 * — so the menu has to flip, shift, and shrink on its own.
 *
 * Radix's collision handling does all three, and the only way to break it is to over-specify.
 * So: no fixed width, no `max-w` in absolute units, no `left`/`top` of our own. The width is
 * bounded by `--radix-dropdown-menu-content-available-width` and the height by its counterpart,
 * both of which Radix computes from the measured space after flipping. `collisionPadding` keeps
 * a gutter so the menu never touches the window edge.
 *
 * `side` and `align` are therefore **preferences, not instructions**. A caller asking for
 * `side="right"` in a 480px window will get a menu on the left, and that is correct.
 *
 * # `Menu.Item` takes `onSelect`, not `onClick`
 *
 * Radix's `onSelect` fires for a click, for Enter and for Space, and it closes the menu
 * afterwards. An `onClick` would work for the pointer and silently do nothing for the keyboard —
 * which is the failure mode nobody testing with a mouse ever sees. The handler here takes no
 * argument: the event Radix passes exists to be able to `preventDefault()` and keep the menu
 * open, and a menu that stays open after an item is chosen is not a menu.
 *
 * # `shortcut` is a hint, and never a binding
 *
 * Passing `shortcut="mod+k"` draws `⌘K` or `Ctrl+K` in the item's right column. It binds
 * nothing: `lib/shortcuts.ts` does that, and it is the shell that calls it. Keeping the two apart
 * means a shortcut still works when the menu is closed — which is when a shortcut is used.
 *
 * What this does not solve: nothing checks that the label and the binding agree. An item that
 * advertises a chord the shell never wired shows a lie, and only a reader pressing it finds out.
 */
export function Menu({
  trigger,
  align = "start",
  side = "bottom",
  children,
}: {
  /** The control that opens the menu. Cloned by Radix, so it must forward its ref — every
      control in this directory does. */
  trigger: ReactNode;
  align?: "start" | "end";
  side?: "top" | "bottom" | "right";
  children: ReactNode;
}): ReactElement {
  const container = useOverlayContainer();

  return (
    <RadixMenu.Root>
      <RadixMenu.Trigger asChild>{trigger}</RadixMenu.Trigger>

      <RadixMenu.Portal container={container ?? undefined}>
        <RadixMenu.Content
          side={side}
          align={align}
          sideOffset={6}
          // The gutter Radix keeps between the menu and the window edge when it shifts.
          collisionPadding={8}
          className={cn(surface, "min-w-48")}
        >
          {children}
        </RadixMenu.Content>
      </RadixMenu.Portal>
    </RadixMenu.Root>
  );
}

/**
 * Shared by the menu and its submenus, which are the same surface at two depths.
 *
 * The hairline is `border-strong` rather than `border-subtle` and it is not a style choice: in
 * the dark palette a black shadow over an L=0.22 ground does nothing, so the edge is the only
 * thing separating the menu from what is behind it. `index.css` says so in the elevation note.
 */
const surface = cn(
  "z-(--z-index-overlay) overflow-y-auto rounded-control border border-(--color-border-strong)",
  "bg-(--color-surface-raised) p-tight shadow-menu",
  // Radix measures these after it has decided which way to flip. Anything absolute here would
  // override the measurement and reintroduce the overflow it just avoided.
  "max-w-(--radix-dropdown-menu-content-available-width)",
  "max-h-(--radix-dropdown-menu-content-available-height)",
  // The portal sits outside the layout: in landscape on a notched phone the menu can otherwise
  // open under the notch.
  "safe-sides safe-bottom",
);

const item = cn(
  "flex cursor-default select-none items-center gap-gutter rounded-control px-gutter py-snug text-body",
  // Radix moves the highlight with the pointer *and* with the arrow keys, so styling
  // `data-highlighted` covers both; a `hover:` rule would leave keyboard users with no cursor.
  "outline-none data-[highlighted]:bg-(--color-surface-sunken)",
  "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
  "touch:min-h-11",
);

/**
 * A heading over a group of items. Not focusable and not selectable — Radix skips it with the
 * arrow keys, which is the difference between a label and a disabled item.
 */
function MenuLabel({ children }: { children: ReactNode }): ReactElement {
  return (
    <RadixMenu.Label className="px-gutter py-tight text-caption text-(--color-ink-muted)">
      {children}
    </RadixMenu.Label>
  );
}

/** A rule between two groups. Decorative, and hidden from the accessibility tree by Radix. */
function MenuSeparator(): ReactElement {
  return <RadixMenu.Separator className="my-tight h-px bg-(--color-border-subtle)" />;
}

function MenuItem({
  icon,
  shortcut,
  tone = "default",
  disabled = false,
  onSelect,
  children,
}: {
  icon?: IconName;
  /** A combo in the `lib/shortcuts.ts` spelling — `"mod+k"`. Drawn, not bound. */
  shortcut?: string;
  tone?: "default" | "danger";
  disabled?: boolean;
  onSelect: () => void;
  children: ReactNode;
}): ReactElement {
  return (
    <RadixMenu.Item
      disabled={disabled}
      // The event is dropped deliberately: keeping the menu open after a choice is not something
      // a call site should be able to do by accident.
      onSelect={() => onSelect()}
      className={cn(
        item,
        tone === "danger"
          ? "text-(--color-danger) data-[highlighted]:bg-(--color-danger)/10"
          : "text-(--color-ink)",
      )}
    >
      {/* Decorative: the label beside it is what names the action, and announcing both would
          read the same thing twice. */}
      {icon === undefined ? null : <Icon name={icon} className="shrink-0" />}

      <span className="min-w-0 flex-1 truncate">{children}</span>

      {shortcut === undefined ? null : (
        // `--font-evidence` for the same reason fingerprints use it: a chord is read as data,
        // character by character, and a proportional ⌘⇧K is harder to take in at 12px.
        // `aria-hidden` because a screen reader announcing "command shift K" after every item
        // label triples the length of the menu, and the binding works whether or not it is read.
        <span aria-hidden="true" className="shrink-0 font-evidence text-caption text-(--color-ink-muted)">
          {formatShortcut(shortcut)}
        </span>
      )}
    </RadixMenu.Item>
  );
}

/**
 * A nested menu, opened by hovering or by the right arrow key.
 *
 * Its own portal, with the same container: a submenu is a separate popper and inherits nothing
 * from its parent's mounting point.
 *
 * What this does not solve: a submenu in a 480px window has even less room than its parent and
 * will flip back over it. Radix keeps it on screen, but two overlapping surfaces is a sign the
 * menu wanted to be a dialog.
 */
function MenuSub({
  label,
  icon,
  children,
}: {
  label: string;
  icon?: IconName;
  children: ReactNode;
}): ReactElement {
  const container = useOverlayContainer();

  return (
    <RadixMenu.Sub>
      <RadixMenu.SubTrigger className={cn(item, "text-(--color-ink)")}>
        {icon === undefined ? null : <Icon name={icon} className="shrink-0" />}
        <span className="min-w-0 flex-1 truncate">{label}</span>
        {/* The disclosure chevron, rotated: the inventory in `Icon.tsx` is closed, and a
            right-pointing chevron is the down one turned a quarter. */}
        <Icon name="collapse" className="shrink-0 -rotate-90 text-(--color-ink-muted)" />
      </RadixMenu.SubTrigger>

      <RadixMenu.Portal container={container ?? undefined}>
        <RadixMenu.SubContent sideOffset={4} collisionPadding={8} className={cn(surface, "min-w-44")}>
          {children}
        </RadixMenu.SubContent>
      </RadixMenu.Portal>
    </RadixMenu.Sub>
  );
}

Menu.Label = MenuLabel;
Menu.Separator = MenuSeparator;
Menu.Item = MenuItem;
Menu.Sub = MenuSub;
