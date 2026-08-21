import { createContext, use, useEffect, useState, type ReactElement, type ReactNode } from "react";

/**
 * Where everything that floats is mounted.
 *
 * # The container is a node in `index.html`, and it has to be
 *
 * `#overlays` is written by hand in the markup, as a sibling of `#root`. Three reasons, and the
 * third is the one that forces the hand:
 *
 *   - A portal that lands inside the layout inherits whatever the layout imposes. A `transform`
 *     anywhere up the tree re-anchors `position: fixed` to that element instead of the viewport,
 *     an `overflow: hidden` clips a menu that overhangs its pane, and a stacking context traps
 *     the whole thing behind a sibling. The three-pane shell has all three in places.
 *   - Being last in the document settles paint order without a `z-index` argument.
 *   - **It cannot be created at run time before React mounts, because the CSP allows no inline
 *     script.** A `<script>` with no `src` is refused by `script-src 'self'`, on the web and
 *     under Tauri alike (`tauri.conf.json`), and there is no nonce. Static markup is the only
 *     place a node can exist before the bundle has parsed.
 *
 * # Every portal must be told about it
 *
 * Radix defaults `container` to `document.body`. That is not the same node: `#overlays` is where
 * the shell's own painting rules apply, and a surface mounted outside it sits outside the safe
 * areas the shell establishes. The visible failure is a mobile sheet on a notched phone — its
 * close button under the notch, its footer under the gesture bar. So each floating surface in
 * this directory reads `useOverlayContainer()` and passes it to `<X.Portal container={…}>`, and
 * each one carries `safe-sides` / `safe-bottom` itself.
 *
 * What this does not solve: the container is shared, and nothing here orders two surfaces
 * against each other. Two menus open at once is a design mistake, not a stacking one.
 */
const OverlayContainerContext = createContext<HTMLElement | null | undefined>(undefined);

export function OverlayProvider({ children }: { children: ReactNode }): ReactElement {
  /**
   * Read once, lazily, at the first render. The node is static markup, so it is already there —
   * this is a lookup, not a wait. The state exists rather than a bare constant only so that a
   * hot reload that replaced the document picks up the new node.
   */
  const [container] = useState<HTMLElement | null>(
    () => globalThis.document?.getElementById("overlays") ?? null,
  );

  return <OverlayContainerContext value={container}>{children}</OverlayContainerContext>;
}

/**
 * The node floating surfaces portal into, or `null` when the markup does not carry one.
 *
 * `null` is not a case to recover from: it means `index.html` lost its `#overlays` div, and the
 * honest response is to let Radix fall back to `document.body` rather than refuse to render a
 * dialog. Being outside the provider is a different thing entirely — that is a mounting mistake,
 * and it throws.
 */
export function useOverlayContainer(): HTMLElement | null {
  const container = use(OverlayContainerContext);
  if (container === undefined) {
    throw new Error("useOverlayContainer must be used inside an <OverlayProvider>");
  }
  return container;
}

/**
 * False on the first painted frame, true from the next one.
 *
 * # Why an entrance is a state flip and not a keyframe
 *
 * A CSS transition needs two values and a paint between them. A component that mounts already
 * wearing its final classes has no "before", so it appears instantly. The usual fix is
 * `@keyframes` plus `data-[state=open]:animate-…`, which needs either a keyframe block in
 * `index.css` or `tailwindcss-animate`; neither is available here.
 *
 * So: mount in the "before" state, let the browser paint it, then flip. Two nested
 * `requestAnimationFrame` calls, because `useEffect` runs after commit but *before* the browser
 * has painted — a single frame would flip the classes in the same paint as the initial ones and
 * the transition would never start.
 *
 * The durations these drive are `--duration-quick` / `--duration-panel`, which collapse to 1ms
 * under `prefers-reduced-motion`. The respect is therefore structural: nothing here reads the
 * preference.
 *
 * `active` covers the surface that stays mounted across openings. A component that unmounts and
 * comes back — a toast keyed by its id — can leave it at its default and get a fresh entrance
 * from the remount; one whose parent survives, like a sheet driven by an `open` prop, passes the
 * flag so that closing rearms the entrance for next time.
 *
 * What this does not solve: **there is no exit.** Radix unmounts its content the moment it
 * closes, so a surface leaves the screen at once. Keeping it alive to animate out means
 * `forceMount` plus manual presence tracking, which buys 180ms of polish in exchange for a
 * dialog that can be visible after it is logically closed. Not worth it here.
 */
export function useEntered(active: boolean = true): boolean {
  const [entered, setEntered] = useState(false);

  useEffect(() => {
    if (!active) {
      setEntered(false);
      return;
    }

    let inner = 0;
    const outer = requestAnimationFrame(() => {
      inner = requestAnimationFrame(() => setEntered(true));
    });
    return () => {
      cancelAnimationFrame(outer);
      cancelAnimationFrame(inner);
    };
  }, [active]);

  return entered;
}
