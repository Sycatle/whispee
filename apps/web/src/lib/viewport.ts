/**
 * What the window actually shows.
 *
 * # Why `100vh` is not enough, and never was
 *
 * On mobile, `100vh` is the height of the window **with the browser chrome expanded** — the
 * address bar that retracts on scroll, the system bar. A layout that trusts it overflows the
 * screen by a hundred pixels or so: on a messenger, that is exactly the composer and the last
 * message going under the fold.
 *
 * `100dvh` fixes that case and needs no help from JavaScript. This module handles what CSS
 * cannot express.
 *
 * # What CSS cannot express: the keyboard
 *
 * When the software keyboard opens, iOS does not resize the window — it **slides** the page
 * under the keyboard, and tells the layout nothing. No media query fires, `dvh` does not move,
 * and the input ends up hidden behind the keyboard that just focused it.
 *
 * Only `visualViewport` reports it: its height is that of the genuinely visible area, and it
 * shrinks when the keyboard opens. It is the only source that tells "the window resized" apart
 * from "something is covering the window".
 *
 * # What this module does not do
 *
 * It decides nothing. It reports a height and an occlusion; what to do with them — raise a
 * composer, shrink a list, change nothing — belongs to the components, the only ones that know
 * what has to stay visible.
 */
import { useEffect, useState } from "react";

export interface Viewport {
  /** Genuinely visible height, in CSS pixels. */
  height: number;
  /**
   * Height hidden at the bottom by the software keyboard, in CSS pixels. Zero when it is closed.
   *
   * Measured by difference rather than asked for: no API says "the keyboard is open", and
   * inferring it from focus would be wrong with a hardware keyboard, where focus hides nothing.
   */
  occlusion: number;
}

/**
 * Measures the current state.
 *
 * Falls back to `innerHeight` where `visualViewport` does not exist — old browsers, and test
 * environments without a DOM. Occlusion is zero there: wrong only in the cases those browsers
 * never meet.
 */
export function measure(): Viewport {
  const view = globalThis.visualViewport;
  if (!view) return { height: globalThis.innerHeight ?? 0, occlusion: 0 };

  // `offsetTop` counts: a page slid under the keyboard shifts the view down, and that shift is
  // part of what is hidden.
  const hidden = globalThis.innerHeight - view.height - view.offsetTop;

  // A pixel or two of difference shows up at rest, from rounding. Treating that as occlusion
  // would make the layout jitter on every scroll.
  return { height: view.height, occlusion: hidden > 24 ? hidden : 0 };
}

/**
 * Subscribes to changes, and returns a way to unsubscribe.
 *
 * Both events are needed and say different things: `resize` covers rotation and the keyboard
 * opening, `scroll` covers the page sliding under the keyboard, which changes the occlusion
 * without changing the height.
 */
export function observe(react: (view: Viewport) => void): () => void {
  const view = globalThis.visualViewport;
  const refresh = () => react(measure());

  if (!view) {
    globalThis.addEventListener?.("resize", refresh);
    return () => globalThis.removeEventListener?.("resize", refresh);
  }

  view.addEventListener("resize", refresh);
  view.addEventListener("scroll", refresh);
  return () => {
    view.removeEventListener("resize", refresh);
    view.removeEventListener("scroll", refresh);
  };
}

/**
 * The height hidden by the keyboard, tracked as it opens.
 *
 * Returned in pixels, for the component to apply as a margin or a padding. The module sets no
 * style itself: the same measurement serves to offset a composer or to shorten a list, and only
 * the caller knows which of the two is right.
 */
export function useOcclusion(): number {
  const [occlusion, setOcclusion] = useState(0);

  useEffect(() => observe((view) => setOcclusion(view.occlusion)), []);

  return occlusion;
}
