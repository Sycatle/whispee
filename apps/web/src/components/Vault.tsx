import { useState } from "react";
import type { ConversationView, Session } from "@/lib/session";

/**
 * History vault settings, **on by default**.
 *
 * This screen does not exist to get a trade-off accepted: it has already been made, in
 * `Session.attach`. It exists to **restate** it and to let the user back out — which is not
 * the same thing as staying quiet about it.
 *
 * Hence the shape: the warning stays on screen, in the present tense, while archiving is on,
 * rather than only on an activation screen nobody will ever see again. A trade-off that
 * becomes the default is exactly the one you stop saying out loud unless you take care to.
 */
export function VaultSettings({
  session,
  active,
  onDone,
}: {
  session: Session;
  active: ConversationView | null;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [understood, setUnderstood] = useState(false);
  const [restored, setRestored] = useState<number | null>(null);

  const toggle = async () => {
    setBusy(true);
    try {
      if (session.archiving) {
        await session.disableVault();
      } else {
        await session.enableVault();
      }
      onDone();
    } finally {
      setBusy(false);
    }
  };

  const restore = async () => {
    if (!active) return;
    setBusy(true);
    try {
      setRestored(await session.restoreHistory(active));
    } finally {
      setBusy(false);
    }
  };

  if (session.archiving) {
    return (
      <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="font-medium">History backup</h2>
          <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
            Close
          </button>
        </div>

        <p className="mt-2 text-(--color-ink-muted)">
          Your messages are archived, encrypted under a key derived from your recovery phrase.
          The server cannot read them, and your history comes back on its own when you open a
          conversation.
        </p>

        <div className="mt-3 rounded-md border border-(--color-danger) bg-(--color-danger)/10 p-3">
          <p className="font-medium text-(--color-danger)">What you gave up</p>
          <p className="mt-1 text-(--color-ink-muted)">
            The archive is encrypted under a key derived from your recovery phrase, so
            <strong> the same key forever</strong>. If that phrase ever gets away from you, the
            whole of your backed-up past becomes readable — retroactively. Without the backup,
            that past would have stayed out of reach: that is forward secrecy, and it is real
            protection.
          </p>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={restore}
            disabled={busy || !active}
            className="rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white disabled:opacity-50"
          >
            {busy ? "…" : "Reload from the vault"}
          </button>
          <button
            type="button"
            onClick={toggle}
            disabled={busy}
            className="rounded-md border border-(--color-border-subtle) px-3 py-1.5 disabled:opacity-50"
          >
            Stop backing up
          </button>
        </div>

        {restored !== null && (
          <p className="mt-2 text-(--color-ok)">
            {restored === 0
              ? "Nothing to restore for this conversation."
              : `${restored} message${restored === 1 ? "" : "s"} restored.`}
          </p>
        )}

        <p className="mt-3 text-xs text-(--color-ink-muted)">
          Stopping the backup does not erase what has already been archived: the server keeps
          those entries, and the key that opens them stays derivable from your phrase. Promising
          a deletion we do not control would be dishonest. Nor does it give back the forward
          secrecy the already-archived past has lost — while the messages that follow will be
          unrecoverable on a new device.
        </p>
      </div>
    );
  }

  return (
    <div className="border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-4 py-4 text-sm">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">Backup off</h2>
        <button type="button" onClick={onDone} className="text-(--color-ink-muted) underline">
          Close
        </button>
      </div>

      <p className="mt-2 text-(--color-ink-muted)">
        You turned the backup off. Your messages therefore disappear when the application
        closes, and a new device starts from an empty conversation. This is not a failure: it is
        forward secrecy, which keeps the past unreadable even to someone who gets hold of the
        server later on.
      </p>

      <div className="mt-3 rounded-md border border-(--color-danger) bg-(--color-danger)/10 p-3">
        <p className="font-medium text-(--color-danger)">What you would give up</p>
        <p className="mt-1 text-(--color-ink-muted)">
          The archive is encrypted under a key derived from your recovery phrase, so
          <strong> the same key forever</strong>. If that phrase ever gets away from you, the
          whole of your backed-up past becomes readable — retroactively. Without the backup,
          that past would have stayed out of reach.
        </p>
      </div>

      <p className="mt-3 text-xs text-(--color-ink-muted)">
        Archiving would resume from now on and does not reach back in time: the messages
        exchanged while it was off had their keys destroyed, and nothing can reconstruct them.
      </p>

      <label className="mt-3 flex items-start gap-2">
        <input
          type="checkbox"
          checked={understood}
          onChange={(e) => setUnderstood(e.target.checked)}
          className="mt-1"
        />
        <span>
          I understand that my history will no longer be protected by forward secrecy.
        </span>
      </label>

      <button
        type="button"
        onClick={toggle}
        disabled={busy || !understood}
        className="mt-3 rounded-md bg-(--color-accent) px-3 py-1.5 font-medium text-white disabled:opacity-50"
      >
        {busy ? "…" : "Turn the backup back on"}
      </button>
    </div>
  );
}
