import type { ReactElement } from "react";

import { grouped } from "@/lib/keymap";
import { formatShortcut } from "@/lib/shortcuts";
import { Dialog } from "@/ui/Dialog";

import { useMountedBindings } from "./Shortcuts";

/**
 * What the keyboard can do here, listed from what actually answers it.
 *
 * # A dialog and not a route
 *
 * `#/settings/shortcuts` would be bookmarkable, which is the wrong promise for a reference
 * somebody opens mid-sentence: it would take them out of the conversation they were writing in
 * to answer a question about writing in it. Radix brings the focus trap, `inert` on the rest of
 * the page, and the return of the focus to whatever opened it.
 *
 * # It lists what is mounted, not what exists
 *
 * `useMountedBindings` reports the bindings some component is currently answering, and only
 * those are shown. So the list cannot advertise a shortcut that does nothing on this screen —
 * `mod+i` is absent when no conversation is open, because nothing is claiming it.
 *
 * This is the property the old prose list did not have. A comment in `lib/shortcuts.ts` named
 * three chords, two of which were never written; it read as documentation and was fiction. A
 * screen generated from the handlers cannot be fiction, because there is nothing to write.
 *
 * What this does not solve: it says nothing about the keys that are contextual rather than
 * global — the arrows in the rail and the thread, Escape stepping out of an action bar. Those
 * are described where they apply, in the thread's own hidden note, because a key that means
 * something different in three places is not a line in a table.
 */
export function ShortcutsHelp({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}): ReactElement {
  const mounted = useMountedBindings();

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Keyboard shortcuts"
      description="What the keyboard can do on this screen."
    >
      <div className="flex flex-col gap-pane">
        {grouped(mounted).map(([group, bindings]) => (
          <section key={group} aria-labelledby={`shortcuts-${group}`}>
            <h3
              id={`shortcuts-${group}`}
              className="mb-tight text-caption font-medium tracking-wide text-(--color-ink-muted) uppercase"
            >
              {group}
            </h3>

            {/* A description list, because that is what this is: a term and what it means. A
                table would promise columns that can be compared down their length, and nobody
                reads the second column of a shortcut list on its own. */}
            <dl className="flex flex-col gap-tight">
              {bindings.map((binding) => (
                <div key={binding.id} className="flex items-baseline justify-between gap-gutter">
                  <dt className="text-body text-(--color-ink)">{binding.label}</dt>
                  <dd>
                    {/* `--font-evidence` for the same reason fingerprints use it: a chord is
                        read character by character, and a proportional ⌘⇧K is harder to take in
                        at 12px. */}
                    <kbd className="rounded-control border border-(--color-border-strong) bg-(--color-surface-raised) px-tight py-0.5 font-evidence text-caption text-(--color-ink-muted)">
                      {formatShortcut(binding.combo)}
                    </kbd>
                  </dd>
                </div>
              ))}
            </dl>
          </section>
        ))}
      </div>
    </Dialog>
  );
}
