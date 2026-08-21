/**
 * Light, dark, or whatever the machine says.
 *
 * # Three states, because two would be a lie
 *
 * `index.css` already answers all three, in CSS and with no help from here: the `@theme` block
 * is the light palette, a `prefers-color-scheme: dark` media query overrides it, and two
 * `:root[data-theme=…]` blocks outrank the media query by specificity. So the entire job of this
 * module is to put — or remove — one attribute on `<html>`.
 *
 * `"system"` is therefore the *absence* of the attribute, not a third value written into it.
 * That is what lets the media query stay in charge, and it is why the choice is removed rather
 * than set: `data-theme="system"` would match neither override block and the reader would be
 * stuck in light.
 *
 * # There is no anti-flash script, and there cannot be
 *
 * The usual pattern is a synchronous inline `<script>` in `<head>` that reads `localStorage` and
 * stamps the attribute before the first paint. The CSP forbids it — `script-src 'self'` with no
 * nonce, on the web and under Tauri alike — and adding a nonce means generating one per
 * response, which a static bundle served from a file system cannot do.
 *
 * The honest consequence, written out rather than hidden:
 *
 *   - **`"system"`, which is the default and what most readers will be on, paints correctly on
 *     the first frame.** The media query is in the stylesheet; nothing waits for JavaScript.
 *   - **Only a reader who explicitly asked to contradict their OS sees one frame of the other
 *     theme** — a dark-mode machine set to light, or the reverse — for as long as the bundle
 *     takes to parse and mount.
 *
 * That is a flash for the minority who opted into a mismatch, in exchange for no inline script
 * at all. The alternative trade — loosening the CSP for every user to spare that frame — is the
 * wrong way round on an application whose point is that it is careful.
 *
 * # One store, not one state per caller
 *
 * The choice is module-level and read through `useSyncExternalStore`, so a theme control in a
 * settings panel and another in the profile menu are never out of step. A `useState` in the hook
 * would give each call site its own copy, and the second one would still be showing "system"
 * after the first switched to dark.
 */
import { useEffect, useSyncExternalStore } from "react";

export type ThemeChoice = "system" | "light" | "dark";

/**
 * Namespaced, like `storage.ts`'s database. `localStorage` is shared with anything else on the
 * origin, and a bare `"theme"` is the single most likely key to collide.
 */
const STORAGE_KEY = "whispee.theme";

function isChoice(value: string | null): value is ThemeChoice {
  return value === "system" || value === "light" || value === "dark";
}

function read(): ThemeChoice {
  // Reading can throw outright: Safari with cookies blocked makes `localStorage` a property
  // access that raises. Unreadable storage is the same situation as no preference stored.
  try {
    const stored = globalThis.localStorage?.getItem(STORAGE_KEY) ?? null;
    return isChoice(stored) ? stored : "system";
  } catch {
    return "system";
  }
}

let choice: ThemeChoice | undefined;
const listeners = new Set<() => void>();

function snapshot(): ThemeChoice {
  // Read once and cached: `useSyncExternalStore` calls the snapshot on every render and compares
  // by identity, so touching `localStorage` here would be a synchronous disk read per render.
  choice ??= read();
  return choice;
}

function announce(next: ThemeChoice): void {
  if (choice === next) return;
  choice = next;
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);

  // Another tab, or another window of the desktop shell, changing the choice. `storage` fires
  // only in the *other* documents, never in the one that wrote — so this never echoes our own
  // write back at us.
  const react = (event: StorageEvent) => {
    if (event.key !== null && event.key !== STORAGE_KEY) return;
    announce(read());
  };
  globalThis.addEventListener("storage", react);

  return () => {
    listeners.delete(listener);
    globalThis.removeEventListener("storage", react);
  };
}

function apply(theme: ThemeChoice): void {
  const root = globalThis.document?.documentElement;
  if (!root) return;

  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

function setTheme(next: ThemeChoice): void {
  announce(next);
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, next);
  } catch {
    // Full or forbidden storage. The choice still applies for this session; it just will not
    // survive a reload, and there is nothing worth telling the reader about that.
  }
}

/**
 * The current choice, and the way to change it.
 *
 * `setTheme` is a module-level function, so its identity never changes and a control that takes
 * it as a callback never re-renders on that account.
 *
 * The attribute is written from an effect rather than during render — writing to the document
 * while rendering is a side effect React is entitled to run twice. Applying on every mount is
 * deliberate and idempotent: it is also what stamps the attribute on the very first load, since
 * nothing else in the page can do it.
 */
export function useTheme(): { theme: ThemeChoice; setTheme: (t: ThemeChoice) => void } {
  const theme = useSyncExternalStore(subscribe, snapshot, snapshot);

  useEffect(() => apply(theme), [theme]);

  return { theme, setTheme };
}
