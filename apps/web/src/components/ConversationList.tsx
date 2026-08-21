import { useState } from "react";
import { DeviceSettings } from "@/components/Devices";
import { LockSettings } from "@/components/Lock";
import { PairDevice } from "@/components/Pairing";
import { VaultSettings } from "@/components/Vault";
import { PresenceDot } from "@/components/Presence";
import { SignalSettings } from "@/components/Signals";
import { type ConversationView, Session } from "@/lib/session";

export function ConversationList({
  session,
  conversations,
  current,
  onSelect,
  onError,
  onChanged,
}: {
  session: Session;
  conversations: ConversationView[];
  current: ConversationView | null;
  onSelect: (view: ConversationView) => void;
  onError: (message: string) => void;
  onChanged: () => void;
}) {
  const [peer, setPeer] = useState("");
  const [pairing, setPairing] = useState(false);
  const [lockPanel, setLockPanel] = useState(false);
  const [vaultPanel, setVaultPanel] = useState(false);
  const [devicePanel, setDevicePanel] = useState(false);
  const [signalPanel, setSignalPanel] = useState(false);

  const start = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      // Several handles separated by commas open a group. Past one peer, the creator becomes
      // its first administrator.
      const handles = peer
        .split(",")
        .map((handle) => handle.trim().replace(/^@/, ""))
        .filter((handle) => handle.length > 0);

      onSelect(await session.startConversation(handles));
      setPeer("");
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <aside
      // Full width when it is alone on screen, a fixed column when it sits next to a
      // conversation. The border follows: it separates two panes, and has nothing to separate
      // when there is only one.
      className="flex w-full shrink-0 flex-col duo:w-64 duo:border-r duo:border-(--color-border-subtle)"
    >
      <form onSubmit={start} className="space-y-2 border-b border-(--color-border-subtle) p-3">
        <input
          value={peer}
          onChange={(e) => setPeer(e.target.value)}
          placeholder="bob, or bob, carol"
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-2 py-1.5 text-sm"
        />
        <button type="submit" className="w-full rounded-md bg-(--color-accent) px-2 py-1.5 text-sm text-white">
          Start a conversation
        </button>
      </form>

      {pairing && <PairDevice session={session} onDone={() => setPairing(false)} />}
      {lockPanel && (
        <LockSettings
          session={session}
          onDone={() => {
            setLockPanel(false);
            onChanged();
          }}
        />
      )}

      {vaultPanel && (
        <VaultSettings
          session={session}
          active={current}
          onDone={() => {
            setVaultPanel(false);
            onChanged();
          }}
        />
      )}

      {signalPanel && (
        <div className="border-b border-(--color-border-subtle) p-3">
          <SignalSettings session={session} onError={onError} />
          <button
            type="button"
            onClick={() => setSignalPanel(false)}
            className="mt-3 text-xs underline opacity-70"
          >
            Close
          </button>
        </div>
      )}

      {devicePanel && (
        <DeviceSettings
          session={session}
          onError={onError}
          onClose={() => {
            setDevicePanel(false);
            onChanged();
          }}
        />
      )}

      {!pairing && !lockPanel && !vaultPanel && !devicePanel && !signalPanel && (
        <div className="flex flex-col gap-1 border-b border-(--color-border-subtle) px-3 py-2 text-left text-xs text-(--color-ink-muted)">
          <button type="button" onClick={() => setPairing(true)} className="text-left underline">
            Add a device
          </button>
          <button type="button" onClick={() => setDevicePanel(true)} className="text-left underline">
            Your devices
          </button>
          <button type="button" onClick={() => setLockPanel(true)} className="text-left underline">
            {session.locked ? "Remove the lock" : "Lock this device"}
          </button>
          <button type="button" onClick={() => setVaultPanel(true)} className="text-left underline">
            {/* The off state reads as a deliberate anomaly, not as an invitation. */}
            {session.archiving ? "History backup" : "Backup disabled"}
          </button>
          <button type="button" onClick={() => setSignalPanel(true)} className="text-left underline">
            Receipts and indicators
          </button>
        </div>
      )}

      {/*
        Neither epoch nor prekey stock. The epoch is a debugging detail, and the stock refills
        itself on every poll — exposing it would turn automatic upkeep into user worry.
      */}
      <ul className="min-h-0 flex-1 overflow-y-auto">
        {conversations.map((view) => (
          <li key={view.key}>
            <button
              type="button"
              onClick={() => onSelect(view)}
              // `touch:` and not `duo:`: the question is not screen width but pointer
              // precision. A tablet is wide **and** finger-driven; a width breakpoint would
              // give it targets designed for a mouse.
              className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm touch:min-h-11 ${
                current?.key === view.key ? "bg-(--color-surface-raised) font-medium" : ""
              }`}
            >
              {/*
                One dot per conversation, and only one-to-one. In a group it would not say who
                it is about — and asking the question multiplies inferences instead of
                informing.
              */}
              {view.accounts.length === 1 && (
                <PresenceDot session={session} handle={view.accounts[0].handle} />
              )}
              <span className="min-w-0 truncate">
                {view.accounts.map((a) => `@${a.handle}`).join(", ") ||
                  [...new Set(view.peers.map((p) => p.name))].map((n) => `@${n}`).join(", ") ||
                  "empty conversation"}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </aside>
  );
}
