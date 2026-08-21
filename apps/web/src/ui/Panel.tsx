import { forwardRef, useId, type ReactNode } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn.ts";

/**
 * A titled block of settings: a heading, an optional description, its controls, and the actions
 * that apply them.
 *
 * # What it replaces
 *
 * The six settings panels — devices, pairing, lock, backup, receipts, notifications — each build
 * their own header out of a `<p className="font-medium">` and a muted paragraph, with the
 * spacing retyped every time. They are the same block six times, and they have already drifted:
 * some use `p-3`, some `p-4`, and only some of them are inside anything a screen reader can
 * navigate by.
 *
 * The heading here is a real `<h2>` inside a `<section aria-labelledby>`, so the settings screen
 * gains a landmark structure that can be jumped through, which it does not currently have.
 * `<h2>` and not a configurable level: these all sit under one screen title, and a prop for it
 * would only be a way to get the order wrong.
 *
 * # A surface, not a control
 *
 * This used to be `rounded-control border bg-(--color-surface)`: a hairline drawn around a block
 * that was already the same colour as the settings pane it sits on. The border was doing the
 * whole job of saying "this is a thing", which is the wrong way round — a panel is a surface the
 * reader stands on, not a control they operate, and a surface is told apart by what it is made
 * of rather than by a line drawn around it. So the fill changed to `--color-surface-raised`, one
 * step above the pane, the hairline went, and the corner moved to `--radius-surface`, which is
 * twice `--radius-control` because a corner has to scale with the box it turns.
 *
 * The settings pane stacks six of these. Six hairlines in a column read as a table with no data
 * in it; six raised blocks separated by `--spacing-pane` read as six things, which is what they
 * are.
 *
 * What this does not solve, and it is worth being plain about it: in the light palette
 * `--color-surface-raised` is `oklch(1 0 0)` against a pane of `oklch(0.985 0.003 265)`. That is
 * a one-and-a-half percent step, and on a dim or badly calibrated screen the edge of a panel is
 * effectively invisible — the spacing and the heading carry it alone. The dark palette has five
 * times that separation and is not in question. Putting the hairline back would fix the light
 * case and undo the point of the change; the real fix is a light `--color-surface` that steps
 * further down, which is a palette decision and not this component's to make.
 *
 * # `tone="danger"` is a border, not a colour scheme
 *
 * The destructive panels — remove the lock, forget this identity — are marked by their edge and
 * their heading, while their body text stays in normal ink. Tinting the whole block would make
 * the explanation of *why* it is dangerous harder to read, which is the one thing in it that
 * must be read. Same doctrine as `Verification.tsx`: emphasis is spent where it changes a
 * decision.
 *
 * The danger edge survives the change above, and now it is the only edge in the file. That is an
 * improvement rather than an inconsistency: when every panel had a hairline, the red one was a
 * hairline in a different colour; now a border on a panel means exactly one thing.
 *
 * What this does not solve: it does not confirm anything. A panel that deletes data still needs
 * a dialog in front of the action, and the tone here is a warning, not a guard.
 */
const panel = cva("rounded-surface bg-(--color-surface-raised) p-pane", {
  variants: {
    tone: {
      default: "",
      danger: "border border-(--color-danger)",
    },
  },
  defaultVariants: { tone: "default" },
});

export interface PanelProps extends VariantProps<typeof panel> {
  title: string;
  /** What this group of settings is for, or what it costs. Read before the controls. */
  description?: ReactNode;
  /** Buttons that apply the panel, laid out after its content. */
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}

export const Panel = forwardRef<HTMLElement, PanelProps>(function Panel(
  { title, description, actions, children, tone, className },
  ref,
) {
  const titleId = useId();

  return (
    <section
      ref={ref}
      aria-labelledby={titleId}
      data-tone={tone ?? "default"}
      className={cn(panel({ tone }), className)}
    >
      <h2
        id={titleId}
        className={cn(
          "text-body font-medium",
          tone === "danger" ? "text-(--color-danger)" : "text-(--color-ink)",
        )}
      >
        {title}
      </h2>

      {description === undefined ? null : (
        <p className="mt-tight text-caption text-(--color-ink-muted)">{description}</p>
      )}

      {children === undefined ? null : <div className="mt-gutter">{children}</div>}

      {/* `flex-wrap` because two buttons and a 480px desktop window is the case the shell has to
          survive — the minimum size the Tauri window can be dragged to. */}
      {actions === undefined ? null : (
        <div className="mt-pane flex flex-wrap items-center gap-snug">{actions}</div>
      )}
    </section>
  );
});
