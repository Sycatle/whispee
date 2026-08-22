import { useCallback, useEffect, useState } from "react";

import type { ViewerKind, ViewerProps } from "@/lib/viewer";
import { Button } from "@/ui/Button";
import { Sheet } from "@/ui/Sheet";

/**
 * A file filling the screen, with the controls that only make sense there.
 *
 * # Built on `Sheet`, and not on a lightbox
 *
 * Every hand-rolled image overlay omits the same four things, and `ui/Dialog.tsx` lists them
 * because this codebase had already omitted them once: the focus trap, `inert` on the rest of the
 * page, the scroll lock, and giving focus back to whatever opened it. Radix does all four, `Sheet`
 * wraps Radix, and so this file is layout and a zoom — not an implementation.
 *
 * `Sheet` rather than `Dialog` for the reason its own comment gives: below `duo` it takes the
 * whole screen, which is what a picture wants, and its controls stay pinned instead of scrolling
 * away under a tall image.
 *
 * # Zoom is the viewer's, not the file's
 *
 * The scale lives here and is handed to the viewer, because what it means is the viewer's
 * business: an image is re-encoded at a larger edge and then transformed, a PDF is re-rendered at
 * a larger scale, and text is not zoomed at all — the browser's own zoom does that better and
 * follows the reader's preferences, which a control in this file never could.
 *
 * A viewer that does not zoom simply ignores the prop, and `ZOOMABLE` decides whether the buttons
 * are drawn. One list, so a kind cannot end up with controls that do nothing.
 */

/** Which kinds have something to reveal at a larger size. */
const ZOOMABLE: ReadonlySet<ViewerKind> = new Set<ViewerKind>(["image", "pdf"]);

/** Zoom steps. Doubling is coarse; this is fine enough to frame a face and short enough to walk. */
const STEPS = [1, 1.5, 2, 3, 4] as const;

export interface AttachmentViewerProps extends Omit<ViewerProps, "mode"> {
  kind: ViewerKind;
  /** The viewer for `kind`, resolved by the caller — this file never maps kinds to components. */
  children: (props: ViewerProps & { scale: number }) => React.ReactNode;
  onClose: () => void;
}

export function AttachmentViewer({
  blob,
  name,
  kind,
  onRefused,
  onClose,
  children,
}: AttachmentViewerProps) {
  const [step, setStep] = useState(0);
  const [pan, setPan] = useState({ x: 0, y: 0 });

  const scale = STEPS[step] ?? 1;
  const zoomable = ZOOMABLE.has(kind);

  // Panning past the edges of an unzoomed image would slide it off a screen it already fits, so
  // the offset is dropped whenever the scale returns to 1 rather than being left to accumulate.
  const zoom = useCallback((next: number) => {
    const clamped = Math.max(0, Math.min(STEPS.length - 1, next));
    setStep(clamped);
    if (clamped === 0) setPan({ x: 0, y: 0 });
  }, []);

  // The keyboard is not a shortcut here, it is the second route. A zoom reachable only by
  // pointer is a zoom somebody cannot use, and the arrows are the only way to pan without one.
  useEffect(() => {
    if (!zoomable) return;

    const onKey = (event: KeyboardEvent) => {
      const nudge = 60;
      switch (event.key) {
        case "+":
        case "=":
          zoom(step + 1);
          break;
        case "-":
          zoom(step - 1);
          break;
        case "0":
          zoom(0);
          break;
        case "ArrowLeft":
          setPan((p) => ({ ...p, x: p.x + nudge }));
          break;
        case "ArrowRight":
          setPan((p) => ({ ...p, x: p.x - nudge }));
          break;
        case "ArrowUp":
          setPan((p) => ({ ...p, y: p.y + nudge }));
          break;
        case "ArrowDown":
          setPan((p) => ({ ...p, y: p.y - nudge }));
          break;
        default:
          return;
      }
      // Only for keys actually handled: the sheet's own Escape has to keep working, and a blanket
      // preventDefault here would take the reader's Tab with it.
      event.preventDefault();
    };

    // On the document rather than on the frame, and the frame is not made focusable to receive
    // them. A `tabIndex` on a plain container is a tab stop that announces nothing and lands
    // nowhere — `eslint-plugin-jsx-a11y` refuses it, correctly. The sheet is modal and traps
    // focus, so while this component is mounted every keystroke on the page is already one of
    // ours; the component is mounted only while the sheet is open, so there is no window in
    // which this listener could steal a key from the thread underneath.
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [zoomable, step, zoom]);

  return (
    <Sheet
      open
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title={name}
      description={zoomable ? "Use + and − to zoom, arrow keys to pan, 0 to reset." : undefined}
      actions={
        zoomable ? (
          <div className="flex items-center gap-snug">
            {/* Buttons and not only the wheel or a pinch. Those are shortcuts for the people who
                have them; a control that exists only as a gesture does not exist for a keyboard
                or for a trackpad nobody has configured. */}
            <Button variant="secondary" onClick={() => zoom(step - 1)} disabled={step === 0}>
              Zoom out
            </Button>
            <Button
              variant="secondary"
              onClick={() => zoom(step + 1)}
              disabled={step === STEPS.length - 1}
            >
              Zoom in
            </Button>
            {/* Announced as a live region so that a reader who cannot see the picture still hears
                what their own control did. */}
            <span aria-live="polite" className="text-caption text-(--color-ink-muted)">
              {Math.round(scale * 100)}%
            </span>
          </div>
        ) : undefined
      }
    >
      {/* No role and no tab stop: what a reader needs to know about the zoom is in the sheet's
          `description`, which is announced with its name, and the buttons say the rest. A group
          wrapping one image would add a level to walk and nothing to hear at the end of it. */}
      <div className="flex h-full w-full items-center justify-center overflow-hidden">
        <div
          style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${scale})` }}
          // `motion-reduce:transition-none` is the project's rule and it matters more here than
          // anywhere: a zoom that eases is a zoom that moves the whole picture under someone who
          // asked the system for less of that.
          className="transition-transform duration-(--duration-quick) ease-out motion-reduce:transition-none"
        >
          {children({ blob, name, mode: "full", onRefused, scale })}
        </div>
      </div>
    </Sheet>
  );
}
