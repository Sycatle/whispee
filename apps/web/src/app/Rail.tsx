import { useCallback, useState } from "react";

import { PresenceDot } from "@/components/Presence";
import { timeOf } from "@/lib/datetime";
import { compactNameOf, nameMatches, nameOf } from "@/lib/naming";
import { roster } from "@/lib/roster";
import type { ConversationView } from "@/lib/session";
import { Avatar } from "@/ui/Avatar";
import { Button } from "@/ui/Button";
import { Dialog } from "@/ui/Dialog";
import { EmojiText } from "@/ui/Emoji";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Input } from "@/ui/Input";
import { Menu } from "@/ui/Menu";
import { Tooltip } from "@/ui/Tooltip";
import { cn } from "@/ui/cn";
import { useTheme } from "@/lib/theme";
import { useNames } from "@/state/names";
import { useReport } from "@/state/report";
import { useBump, useRevision, useSession } from "@/state/SessionProvider";
import { useNavigate, useRoute } from "@/routes/Router";

/**
 * The left column: everybody this account knows, in one scroll.
 *
 * # Two sections, and why they are not tabs
 *
 * Conversations and Contacts sit one above the other inside a single scrolling area, each in a
 * `<details>`. **Not tabs.** The rail is 288 pixels wide; tabs would hide half of what it holds
 * behind a click, to save vertical space in the one axis that scrolls anyway. The whole point of
 * a permanent left column is that it is a place you glance at, and you cannot glance at the tab
 * that is not selected.
 *
 * **And not a 72 pixel icon column either**, the way Discord and Slack stack their servers to the
 * left of their channels. That column exists because those products have a level above the
 * conversation — a server, a workspace — that people switch between all day. This application
 * has one account and one flat list of threads. Copying the shape without the level underneath
 * it would be cargo cult: sixty pixels of permanent chrome expressing a hierarchy that does not
 * exist.
 *
 * `<details>` rather than a `useState` and a conditional: the collapse, the disclosure role, the
 * keyboard behaviour and the `open` state are what the element is for, and every hand-written
 * version of it in the wild is missing at least one of the four. Only the persistence is ours.
 */

/**
 * One line of the last thing said, for the list.
 *
 * Reactions are skipped: they annotate a message rather than being one, and a list showing "👍"
 * as the latest news of a conversation says nothing about it. An attachment shows its name — the
 * name is content, encrypted like the rest, and it is what the person would recognise.
 */
function preview(view: ConversationView): string {
  const queued = view.outbox.at(-1);
  if (queued) return queued.text;

  for (let i = view.messages.length - 1; i >= 0; i -= 1) {
    const { content } = view.messages[i];
    if (content.kind === "text" || content.kind === "reply") return content.text;
    if (content.kind === "attachment") return content.ref.name;
  }
  return "";
}

/**
 * Whether a section is unfolded, remembered across reloads.
 *
 * Per section rather than one flag for the rail: somebody who never opens Contacts should not
 * have to close it again every morning, and that is a different preference from wanting
 * Conversations open. Kept in `localStorage` and not in the session: it is a property of this
 * browser's window, not of the identity, and it must survive "erase this identity" the same way
 * a scroll position does.
 *
 * Unreadable or absent storage falls back to open. A rail whose sections were all shut because a
 * private window refused to persist anything would look broken, and the cost of being wrong the
 * other way is one click.
 */
function useSectionOpen(id: string): [boolean, (open: boolean) => void] {
  const key = `whispee.rail.${id}.open`;
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem(key) !== "closed";
    } catch {
      return true;
    }
  });

  const remember = useCallback(
    (next: boolean) => {
      setOpen(next);
      try {
        localStorage.setItem(key, next ? "open" : "closed");
      } catch {
        // A browser that refuses storage still gets a working rail for this session. Nothing to
        // report to the user: they did not ask for anything.
      }
    },
    [key],
  );

  return [open, remember];
}

function Section({
  id,
  label,
  count,
  children,
}: {
  id: string;
  label: string;
  count: number;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useSectionOpen(id);

  return (
    <details open={open} onToggle={(e) => setOpen(e.currentTarget.open)} className="group">
      <summary className="sticky top-0 z-(--z-index-sticky) flex cursor-default list-none items-center gap-tight bg-(--color-surface-sunken) px-gutter py-snug text-caption font-medium tracking-wide text-(--color-ink-muted) uppercase focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent) [&::-webkit-details-marker]:hidden">
        <Icon
          name="collapse"
          size={14}
          className="-rotate-90 transition-transform duration-(--duration-quick) ease-out group-open:rotate-0 motion-reduce:transition-none"
        />
        <span className="flex-1">{label}</span>
        <span className="font-evidence tabular-nums">{count}</span>
      </summary>
      {children}
    </details>
  );
}

export function Rail({ onLock, onForget }: { onLock: () => void; onForget: () => void }) {
  const session = useSession();
  const revision = useRevision();
  const bump = useBump();
  const report = useReport();
  const names = useNames();
  const route = useRoute();
  const navigate = useNavigate();
  const { theme, setTheme } = useTheme();
  const [searching, setSearching] = useState(false);
  const [erasing, setErasing] = useState(false);
  /**
   * Filters the list, and nothing else.
   *
   * Deliberately not a message search. Searching bodies would mean either scanning what happens
   * to be in the local window — answering "not found" for a message that exists, which is worse
   * than not offering it — or asking the server, which holds only ciphertext. A real one needs an
   * encrypted local index, and that is a feature, not a text box.
   */
  const [filter, setFilter] = useState("");

  const currentKey = route.kind === "conversation" ? route.key : null;
  const conversations = [...session.conversations.values()];

  // `revision` is read so this list recomputes after a mutation. The views are mutated in place,
  // so their identity says nothing about their contents — see the rule at the top of
  // `state/SessionProvider.tsx`.
  void revision;

  /*
    The filter searches every string a person has, not the handle alone. Somebody typing
    "charlie" has no way of knowing which of the three strings the rail happens to be showing
    them — that is the whole point of a naming order — so a filter that only looked at one of
    them would answer "no match" about a row the reader can see.

    What it does not solve: it still only filters the list. Message bodies are not searched, for
    the reasons stated where `filter` is declared.
  */
  const matches = (view: ConversationView) =>
    view.accounts.some((account) => nameMatches(account.handle, names, filter));

  /*
    Most recent first. The list used to be in whatever order the `Map` happened to hold, which
    is insertion order — so the conversation someone just wrote in could sit at the bottom
    under a dozen they have not opened in weeks.

    Sorted at render rather than by reordering the `Map`: the `Map` is keyed state that other
    code reads by key, and rotating it to express a display concern would be the wrong place
    to hold this.
  */
  const listed = conversations
    .filter(matches)
    .sort((a, b) => session.lastActivityIn(b) - session.lastActivityIn(a));

  /**
   * Handles verified out of band, as far as this component can see them.
   *
   * Derived from the accounts already on screen because the record itself is private to
   * `Session`. That makes the union in `roster()` a no-op today; it is written there anyway
   * because the friend batch will supply a list this component cannot reach, and the signature
   * should not have to change on that day.
   */
  const verified = conversations
    .flatMap((view) => view.accounts)
    .filter((account) => session.verificationOf(account).status === "verified")
    .map((account) => account.handle);

  const contacts = roster({ conversations, verified, self: session.handle }).filter((handle) =>
    nameMatches(handle, names, filter),
  );

  /**
   * Every handle the rail draws, in one set.
   *
   * It is the `among` passed to every compact name below, and it is deliberately the whole rail
   * rather than one row: here the reader compares rows *against each other*, so a display name
   * that could be mistaken for somebody in another conversation is ambiguous in this list even
   * though the two people never share a thread. Narrowing it per row would let exactly that pair
   * render identically, one above the other.
   *
   * What it does not solve: the set is what is on screen after filtering, so typing in the filter
   * can remove the rival that was forcing a fallback and let a name appear. That is honest —
   * a name is only ambiguous against what is actually shown — but it does mean a row can change
   * its label while being filtered.
   */
  const rendered = new Set([
    ...listed.flatMap((view) => [
      ...view.accounts.map((account) => account.handle),
      ...view.peers.map((peer) => peer.name),
    ]),
    ...contacts,
  ]);

  // Our own row goes through the same function as everybody else's: `useNames` folds this
  // account's display name into `profiles` under its own handle, so there is no self case here.
  const self = nameOf(session.handle, names);

  const open = async (handle: string) => {
    try {
      const view = await session.startConversation([handle]);
      bump();
      navigate({ kind: "conversation", key: view.key });
    } catch (e) {
      report.error(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <aside
      aria-label="Conversations and contacts"
      className="safe-top safe-sides flex h-full w-full shrink-0 flex-col bg-(--color-surface-sunken) duo:w-72 duo:border-r duo:border-(--color-border-subtle)"
    >
      <div className="flex items-center gap-tight border-b border-(--color-border-subtle) px-gutter py-snug">
        <h2 className="flex-1 text-body font-medium">Whispee</h2>
        {/* Shown from a handful of conversations up. Below that it is one more thing on screen
            between the reader and a list they can already see all of. */}
        {conversations.length > 5 && (
          <Tooltip label="Filter by name">
            <IconButton
              label="Filter by name"
              icon="search"
              aria-expanded={searching}
              onClick={() => {
                setSearching(!searching);
                if (searching) setFilter("");
              }}
            />
          </Tooltip>
        )}
        <Tooltip label="Start a conversation">
          <IconButton
            label="Start a conversation"
            icon="add"
            onClick={() => navigate({ kind: "new" })}
          />
        </Tooltip>
      </div>

      {searching && (
        <div className="border-b border-(--color-border-subtle) p-snug">
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by name or handle"
            aria-label="Filter conversations by name or handle"
            autoFocus
            className="w-full text-base"
          />
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <Section id="conversations" label="Conversations" count={listed.length}>
          <ul className="px-snug pb-snug">
            {listed.map((view) => {
              const unread = session.unreadIn(view);
              const line = preview(view);
              const last = session.lastActivityIn(view);
              const selected = currentKey === view.key;
              const only = view.accounts.length === 1 ? view.accounts[0] : undefined;
              /*
                The compact form, because this row has no second line to move the handle onto:
                the one under the title is the message preview, and the preview is why anybody
                looks at this list. So the name shown here has to be able to stand alone, which
                is precisely what `compactNameOf` refuses to let it do when it cannot.
              */
              const title =
                view.accounts.map((a) => compactNameOf(a.handle, names, rendered)).join(", ") ||
                [...new Set(view.peers.map((p) => p.name))]
                  .map((n) => compactNameOf(n, names, rendered))
                  .join(", ") ||
                "empty conversation";

              return (
                <li key={view.key}>
                  <button
                    type="button"
                    onClick={() =>
                      navigate({
                        kind: "conversation",
                        key: view.key,
                        // Switching conversation keeps the detail column as it was. That is what
                        // Discord does and what people expect: the column is a mode you are in,
                        // not a property of the thread you left.
                        ...(route.kind === "conversation" && route.detail
                          ? { detail: {} }
                          : {}),
                      })
                    }
                    // `aria-current` rather than the highlight alone: the selected conversation is a
                    // fact about where you are, and a background colour states it only to whoever can
                    // see it.
                    aria-current={selected ? "true" : undefined}
                    // `touch:` and not `duo:`: the question is not screen width but pointer
                    // precision. A tablet is wide **and** finger-driven; a width breakpoint would
                    // give it targets designed for a mouse.
                    className={cn(
                      "flex w-full items-start gap-snug rounded-control px-snug py-snug text-left text-body touch:min-h-11",
                      "focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent)",
                      selected
                        ? "bg-(--color-surface-raised) font-medium"
                        : "hover:bg-(--color-surface)",
                    )}
                  >
                    <Avatar
                      seed={only?.fingerprint ?? (only ? undefined : view.key)}
                      label={title}
                      size="md"
                      {...(only ? { proof: session.verificationOf(only) } : {})}
                      rejected={view.accounts.some((a) => a.rejected.length > 0)}
                      className="shrink-0"
                    />

                    <span className="min-w-0 flex-1">
                      <span className="flex items-baseline gap-snug">
                        <span className="min-w-0 flex-1 truncate">{title}</span>
                        {/* Nothing where nothing is known: a thread with no stamps shows no hour
                            rather than one taken from the clock. */}
                        {last > 0 && (
                          <time
                            dateTime={new Date(last).toISOString()}
                            className="shrink-0 font-evidence text-caption font-normal text-(--color-ink-muted)"
                          >
                            {timeOf(last)}
                          </time>
                        )}
                      </span>
                      <span className="mt-0.5 flex items-baseline gap-snug">
                        {/*
                          One dot per conversation, and only one-to-one. In a group it would not say who
                          it is about — and asking the question multiplies inferences instead of
                          informing.
                        */}
                        {only && (
                          <span className="shrink-0 self-center">
                            <PresenceDot session={session} handle={only.handle} />
                          </span>
                        )}
                        <span className="min-w-0 flex-1 truncate text-caption font-normal text-(--color-ink-muted)">
                          <EmojiText text={line} />
                        </span>
                        {unread > 0 && (
                          <span
                            className="shrink-0 rounded-(--radius-pill) bg-(--color-accent) px-1.5 font-evidence text-caption font-medium text-(--color-accent-ink)"
                            aria-label={`${unread} unread`}
                          >
                            {unread}
                          </span>
                        )}
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
            {listed.length === 0 && (
              <li className="px-snug py-snug text-caption text-(--color-ink-muted)">
                {filter === "" ? "No conversations yet." : "No conversation matches that."}
              </li>
            )}
          </ul>
        </Section>

        {/* Everybody we have a reason to know and no open thread with — see `lib/roster.ts` for
            what that means and what it cannot see. */}
        <Section id="contacts" label="Contacts" count={contacts.length}>
          <ul className="px-snug pb-snug">
            {contacts.map((handle) => {
              const contact = nameOf(handle, names);

              return (
                <li key={handle}>
                  <button
                    type="button"
                    onClick={() => void open(handle)}
                    className="flex w-full items-center gap-snug rounded-control px-snug py-snug text-left text-body hover:bg-(--color-surface) focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent) touch:min-h-11"
                  >
                    <Avatar label={contact.primary} size="sm" className="shrink-0" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate">{contact.primary}</span>
                      {/* Room for a second line here, unlike a conversation row: nothing else
                          claims it, so the handle stays on screen under the name instead of being
                          replaced by it. */}
                      {contact.secondary !== null && (
                        <span className="block truncate text-caption text-(--color-ink-muted)">
                          {contact.secondary}
                        </span>
                      )}
                    </span>
                  </button>
                </li>
              );
            })}
            {contacts.length === 0 && (
              <li className="px-snug py-snug text-caption text-(--color-ink-muted)">
                People you share a group with, or have verified, appear here once they have no
                conversation of their own.
              </li>
            )}
          </ul>
        </Section>
      </div>

      {/*
        The profile button is a launcher, not a container.

        The six booleans it replaces each swapped a settings panel into this 288 pixel column —
        a password field, a QR code and a device list rendered inside a sidebar. Only two things
        still change from inside the menu, and both are single-value choices with an immediate
        visible effect: the theme, and locking the device now. Everything else is a screen, and
        goes to one.
      */}
      <div className="safe-bottom border-t border-(--color-border-subtle) p-snug">
        <Menu
          align="start"
          side="top"
          trigger={
            <button
              type="button"
              className="flex w-full items-center gap-snug rounded-control p-snug text-left hover:bg-(--color-surface) focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent) touch:min-h-11"
            >
              <Avatar
                seed={session.accountFingerprint()}
                label={self.primary}
                size="md"
                className="shrink-0"
              />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-body font-medium">{self.primary}</span>
                {/*
                  A named account gets three lines here rather than two, and the device
                  identifier keeps the last of them. It is not a decoration: it is what somebody
                  compares character by character while pairing, and dropping it to make room for
                  a name would trade evidence for a label the user typed themselves.
                */}
                {self.secondary !== null && (
                  <span className="block truncate text-caption text-(--color-ink-muted)">
                    {self.secondary}
                  </span>
                )}
                <span className="block truncate font-evidence text-caption text-(--color-ink-muted)">
                  {session.deviceId.slice(session.handle.length + 1)}
                </span>
              </span>
              <Icon name="settings" className="shrink-0 text-(--color-ink-muted)" />
            </button>
          }
        >
          {/* One line, but a wide one, so both strings fit side by side and the anchor is not
              lost the moment the menu is the only thing on screen. */}
          <Menu.Label>
            {self.primary}
            {self.secondary !== null && <span className="ml-tight">{self.secondary}</span>}
          </Menu.Label>

          <Menu.Sub label="Theme" icon="theme">
            <Menu.Item onSelect={() => setTheme("system")}>
              System{theme === "system" ? " ✓" : ""}
            </Menu.Item>
            <Menu.Item onSelect={() => setTheme("light")}>
              Light{theme === "light" ? " ✓" : ""}
            </Menu.Item>
            <Menu.Item onSelect={() => setTheme("dark")}>
              Dark{theme === "dark" ? " ✓" : ""}
            </Menu.Item>
          </Menu.Sub>

          {/* The one lock action that happens on the spot. Configuring the lock is a screen with
              a password field in it, and a password field does not belong in a dropdown. */}
          <Menu.Item icon="lock" disabled={!session.locked} onSelect={onLock}>
            Lock now
          </Menu.Item>

          <Menu.Separator />

          <Menu.Item
            icon="devices"
            onSelect={() => navigate({ kind: "settings", section: "devices" })}
          >
            Your devices
          </Menu.Item>
          <Menu.Item
            icon="pair"
            onSelect={() => navigate({ kind: "settings", section: "pairing" })}
          >
            Add a device
          </Menu.Item>
          <Menu.Item
            icon="lock"
            onSelect={() => navigate({ kind: "settings", section: "lock" })}
          >
            Lock
          </Menu.Item>
          <Menu.Item
            icon="backup"
            onSelect={() => navigate({ kind: "settings", section: "backup" })}
          >
            {/* The off state reads as a deliberate anomaly, not as an invitation. */}
            {session.archiving ? "History backup" : "Backup disabled"}
          </Menu.Item>
          <Menu.Item
            icon="settings"
            onSelect={() => navigate({ kind: "settings", section: "receipts" })}
          >
            Receipts and indicators
          </Menu.Item>
          <Menu.Item
            icon="notifications"
            onSelect={() => navigate({ kind: "settings", section: "notifications" })}
          >
            Notifications
          </Menu.Item>

          <Menu.Separator />

          <Menu.Item icon="revoke" tone="danger" onSelect={() => setErasing(true)}>
            Erase this identity
          </Menu.Item>
        </Menu>
      </div>

      <Dialog
        open={erasing}
        onOpenChange={setErasing}
        tone="danger"
        title="Erase this identity?"
        description="Everything on this device goes: the keys, the conversations, the vault key. Without the recovery phrase there is no way back, and nobody can restore it for you."
        actions={
          <>
            <Button variant="secondary" onClick={() => setErasing(false)}>
              Keep it
            </Button>
            <Button variant="destructive" onClick={onForget}>
              Erase
            </Button>
          </>
        }
      />
    </aside>
  );
}
