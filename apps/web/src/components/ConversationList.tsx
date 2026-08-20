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
      // Plusieurs pseudonymes séparés par des virgules ouvrent un groupe. Au-delà d'un
      // correspondant, le créateur en devient le premier administrateur.
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
    <aside className="flex w-64 shrink-0 flex-col border-r border-(--color-border-subtle)">
      <form onSubmit={start} className="space-y-2 border-b border-(--color-border-subtle) p-3">
        <input
          value={peer}
          onChange={(e) => setPeer(e.target.value)}
          placeholder="bob, ou bob, carol"
          required
          className="w-full rounded-md border border-(--color-border-subtle) bg-(--color-surface-raised) px-2 py-1.5 text-sm"
        />
        <button type="submit" className="w-full rounded-md bg-(--color-accent) px-2 py-1.5 text-sm text-white">
          Ouvrir une conversation
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
            Fermer
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
            Ajouter un appareil
          </button>
          <button type="button" onClick={() => setDevicePanel(true)} className="text-left underline">
            Vos appareils
          </button>
          <button type="button" onClick={() => setLockPanel(true)} className="text-left underline">
            {session.locked ? "Retirer le verrou" : "Verrouiller cet appareil"}
          </button>
          <button type="button" onClick={() => setVaultPanel(true)} className="text-left underline">
            {/* L'état coupé se lit comme une anomalie choisie, pas comme une invitation. */}
            {session.archiving ? "Sauvegarde de l'historique" : "Sauvegarde désactivée"}
          </button>
          <button type="button" onClick={() => setSignalPanel(true)} className="text-left underline">
            Accusés et indicateurs
          </button>
        </div>
      )}

      {/*
        Ni epoch, ni stock de clés d'accueil. L'epoch est un détail de débogage, et le stock
        se reconstitue tout seul à chaque relève — l'exposer transformerait de l'entretien
        automatique en inquiétude pour l'utilisateur.
      */}
      <ul className="min-h-0 flex-1 overflow-y-auto">
        {conversations.map((view) => (
          <li key={view.key}>
            <button
              type="button"
              onClick={() => onSelect(view)}
              className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm ${
                current?.key === view.key ? "bg-(--color-surface-raised) font-medium" : ""
              }`}
            >
              {/*
                Une pastille par conversation, et seulement en tête-à-tête. Sur un groupe, elle
                ne dirait pas de qui elle parle — et poser la question multiplie les inférences
                au lieu d'informer.
              */}
              {view.accounts.length === 1 && (
                <PresenceDot session={session} handle={view.accounts[0].handle} />
              )}
              <span className="min-w-0 truncate">
                {view.accounts.map((a) => `@${a.handle}`).join(", ") ||
                  [...new Set(view.peers.map((p) => p.name))].map((n) => `@${n}`).join(", ") ||
                  "conversation vide"}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </aside>
  );
}
