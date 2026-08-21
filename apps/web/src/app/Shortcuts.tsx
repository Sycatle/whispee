import {
  type ReactElement,
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

import { type Binding, type BindingId, KEYMAP } from "@/lib/keymap";
import { useShortcut } from "@/lib/shortcuts";

/**
 * Who answers the shortcuts, and what the help screen is allowed to claim.
 *
 * # Components ask for an id, never for a chord
 *
 * `useBinding("detail.toggle", …)` rather than `useShortcut("mod+i", …)`. The component says what
 * it does; `lib/keymap.ts` says which keys do it. Changing a chord is then one line in one file,
 * and a component cannot quietly bind a chord that appears in no list.
 *
 * # Nothing is intercepted for a shortcut nobody claims
 *
 * A chord is wired only while some component has asked for it. This matters because
 * `useShortcut` calls `preventDefault` on a match: a binding mounted permanently for
 * `settings.open` would swallow ⌘, on every screen, including the ones where nothing opens. Here
 * an unclaimed chord is not listened for at all and goes to the browser untouched.
 *
 * The same fact drives the help screen. It lists what is mounted rather than the whole keymap,
 * so it cannot advertise a shortcut that does nothing on the screen the reader is looking at —
 * which is the failure the prose list in `lib/shortcuts.ts` used to have, and had for months.
 *
 * # Arbitration: the last to mount wins
 *
 * Handlers for one id form a stack and only the top runs. Two components claiming the same id
 * means one has opened over the other, and the one that opened last is the more specific — a
 * dialog covering a screen should answer Escape, not the screen underneath. In development a
 * second claim logs a warning, because it is far more often an oversight than a design.
 */
interface Registry {
  claim: (id: BindingId, handler: () => void) => () => void;
  run: (id: BindingId) => void;
  mounted: readonly BindingId[];
}

const RegistryContext = createContext<Registry | null>(null);

/**
 * One `useShortcut` per claimed binding.
 *
 * A component and not a loop in the provider: hooks cannot be called from a callback, and mapping
 * over a changing list would move them in the hook order. With one component per binding, React's
 * own mounting handles it, keyed by id.
 */
function Wire({ binding, fire }: { binding: Binding; fire: (id: BindingId) => void }): null {
  useShortcut(binding.combo, () => fire(binding.id));
  return null;
}

export function ShortcutsProvider({ children }: { children: ReactNode }): ReactElement {
  // A ref and not state: the stacks change when a component mounts, and a re-render there would
  // be a render inside a render. Only the *set of ids* is state, because only that is drawn.
  const stacks = useRef(new Map<BindingId, (() => void)[]>());
  const [mounted, setMounted] = useState<readonly BindingId[]>([]);

  const claim = useCallback((id: BindingId, handler: () => void) => {
    const stack = stacks.current.get(id) ?? [];

    if (import.meta.env.DEV && stack.length > 0) {
      console.warn(
        `[shortcuts] "${id}" is claimed twice; the one that mounted last will answer it.`,
      );
    }

    stack.push(handler);
    stacks.current.set(id, stack);
    setMounted([...stacks.current.keys()]);

    return () => {
      const remaining = (stacks.current.get(id) ?? []).filter((one) => one !== handler);
      if (remaining.length === 0) stacks.current.delete(id);
      else stacks.current.set(id, remaining);
      setMounted([...stacks.current.keys()]);
    };
  }, []);

  const fire = useCallback((id: BindingId) => {
    const stack = stacks.current.get(id);
    stack?.[stack.length - 1]?.();
  }, []);

  return (
    <RegistryContext.Provider value={{ claim, run: fire, mounted }}>
      {KEYMAP.filter((binding) => mounted.includes(binding.id)).map((binding) => (
        <Wire key={binding.id} binding={binding} fire={fire} />
      ))}
      {children}
    </RegistryContext.Provider>
  );
}

/**
 * Answers a shortcut for as long as the component is mounted.
 *
 * `enabled` exists for the same reason it does in `useShortcut`: a binding that must be off while
 * something covers it cannot be un-called, so it passes `false` and keeps its place in the hook
 * order. A disabled binding is not merely silent — it is not mounted at all, so its chord is not
 * listened for and does not appear in the help screen.
 *
 * The handler is read through a ref, so a fresh closure on every render does not re-claim the
 * binding and, with it, log a duplicate-claim warning once a render.
 */
export function useBinding(id: BindingId, handler: () => void, enabled: boolean = true): void {
  const registry = useContext(RegistryContext);
  if (registry === null) throw new Error("useBinding outside a ShortcutsProvider");

  const latest = useRef(handler);
  useEffect(() => {
    latest.current = handler;
  });

  const { claim } = registry;
  useEffect(() => {
    if (!enabled) return;
    return claim(id, () => latest.current());
  }, [claim, id, enabled]);
}

/**
 * Does what a shortcut does, from a button.
 *
 * A menu item and a chord that open the same thing should not be two implementations of opening
 * it — that is how one of them ends up doing slightly less. The item borrows the handler the
 * binding already registered, so the menu cannot drift from the key it advertises beside itself.
 */
export function useRunBinding(): (id: BindingId) => void {
  const registry = useContext(RegistryContext);
  if (registry === null) throw new Error("useRunBinding outside a ShortcutsProvider");
  return registry.run;
}

/** The bindings currently answered by something, for the screen that lists them. */
export function useMountedBindings(): readonly BindingId[] {
  const registry = useContext(RegistryContext);
  if (registry === null) throw new Error("useMountedBindings outside a ShortcutsProvider");
  return registry.mounted;
}
