import type { ReactElement, ReactNode } from "react";
import * as RadixContextMenu from "@radix-ui/react-context-menu";

import { cn } from "./cn.ts";
import { Icon, type IconName } from "./Icon.tsx";
import { item, surface } from "./menuSurface.ts";
import { useOverlayContainer } from "./Overlays.tsx";

/**
 * The actions of a thing, on the thing itself.
 *
 * # Why a seventh Radix package rather than an `onContextMenu` handler
 *
 * A context menu looks like an afternoon's work and is not. What has to be right: opening from
 * the keyboard, which is Shift+F10 *and* the Menu key, and which nobody remembers to implement;
 * trapping the focus and giving it back to where it came from; positioning against the pointer
 * while staying inside the window on all four edges; long-press on touch, where there is no right
 * button at all; and dismissing on scroll, since a menu anchored to a point in a list that has
 * moved is pointing at the wrong row.
 *
 * `docs/THREAT-MODEL.md` states the trade this project already made — "the accessibility work
 * nobody here would have written correctly — focus traps, focus restoration, `inert`" — and this
 * is squarely inside it. Writing this one by hand would be reversing that decision on the single
 * component where it is least defensible.
 *
 * # It duplicates, and that is the design
 *
 * Every action offered here exists somewhere visible: on the hover bar of a message, in the group
 * panel, behind a button. A context menu that is the *only* way to reach something is a feature
 * hidden behind a gesture — untrue on touch, unknown to anybody who has not tried right-clicking,
 * and invisible to a screen reader reading in order. This is a shortcut to what is already there.
 */
export function ContextMenu({
  trigger,
  children,
}: {
  /** What is right-clicked. Rendered as-is; the menu wraps it without adding a box. */
  trigger: ReactNode;
  children: ReactNode;
}): ReactElement {
  const container = useOverlayContainer();

  return (
    <RadixContextMenu.Root>
      {/* `asChild` so the row keeps its own element: wrapping a `<li>` in a `<div>` would break
          the list semantics the thread and the rail both depend on. */}
      <RadixContextMenu.Trigger asChild>{trigger}</RadixContextMenu.Trigger>

      <RadixContextMenu.Portal container={container ?? undefined}>
        <RadixContextMenu.Content
          collisionPadding={8}
          className={cn(
            surface,
            "min-w-48",
            // The context menu names its own variables — the dropdown's are a different set.
            "max-w-(--radix-context-menu-content-available-width)",
            "max-h-(--radix-context-menu-content-available-height)",
            "safe-sides safe-bottom",
          )}
        >
          {children}
        </RadixContextMenu.Content>
      </RadixContextMenu.Portal>
    </RadixContextMenu.Root>
  );
}

function ContextMenuItem({
  icon,
  tone = "default",
  disabled = false,
  onSelect,
  children,
}: {
  icon?: IconName;
  tone?: "default" | "danger";
  disabled?: boolean;
  onSelect: () => void;
  children: ReactNode;
}): ReactElement {
  return (
    <RadixContextMenu.Item
      disabled={disabled}
      // The event is dropped for the same reason it is in `Menu`: keeping the menu open after a
      // choice is not something a call site should be able to do by accident.
      onSelect={() => onSelect()}
      className={cn(
        item,
        tone === "danger"
          ? "text-(--color-danger) data-[highlighted]:bg-(--color-danger)/10"
          : "text-(--color-ink)",
      )}
    >
      {/* Decorative: the label beside it names the action, and announcing both reads it twice. */}
      {icon === undefined ? null : <Icon name={icon} className="shrink-0" />}
      <span className="min-w-0 flex-1 truncate">{children}</span>
    </RadixContextMenu.Item>
  );
}

/** A heading over a group of items. Radix skips it with the arrow keys. */
function ContextMenuLabel({ children }: { children: ReactNode }): ReactElement {
  return (
    <RadixContextMenu.Label className="px-gutter py-tight text-caption text-(--color-ink-muted)">
      {children}
    </RadixContextMenu.Label>
  );
}

/** A rule between two groups. Decorative, and hidden from the accessibility tree by Radix. */
function ContextMenuSeparator(): ReactElement {
  return <RadixContextMenu.Separator className="my-tight h-px bg-(--color-border-subtle)" />;
}

/**
 * A row of one-tap choices inside the menu — the quick reactions, and nothing else so far.
 *
 * Laid out as a row because five emoji stacked as five menu items would be a menu you scroll to
 * react, which is slower than the hover bar it is meant to shortcut. Each is still a menu item,
 * so the arrow keys reach them and Enter picks one.
 */
function ContextMenuRow({ children }: { children: ReactNode }): ReactElement {
  return <div className="flex items-center gap-tight px-tight py-tight">{children}</div>;
}

function ContextMenuChoice({
  label,
  onSelect,
  children,
}: {
  label: string;
  onSelect: () => void;
  children: ReactNode;
}): ReactElement {
  return (
    <RadixContextMenu.Item
      aria-label={label}
      onSelect={() => onSelect()}
      className={cn(
        "flex size-8 shrink-0 cursor-default items-center justify-center rounded-control text-body",
        "outline-none data-[highlighted]:bg-(--color-accent) data-[highlighted]:text-(--color-accent-ink)",
        "touch:size-11",
      )}
    >
      {children}
    </RadixContextMenu.Item>
  );
}

ContextMenu.Item = ContextMenuItem;
ContextMenu.Label = ContextMenuLabel;
ContextMenu.Separator = ContextMenuSeparator;
ContextMenu.Row = ContextMenuRow;
ContextMenu.Choice = ContextMenuChoice;
