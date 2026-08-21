import { useEffect, useRef, useState } from "react";

import { GroupPanel } from "@/components/Group";
import { PresenceLine } from "@/components/Presence";
import { VerificationPanel } from "@/components/Verification";
import { Fingerprint } from "@/components/Fingerprint";
import type { ResolvedAccount } from "@/lib/account";
import { useDuo, useTrio } from "@/lib/duo";
import type { ConversationView, VerificationState } from "@/lib/session";
import { Avatar } from "@/ui/Avatar";
import { Button } from "@/ui/Button";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { ProofStrip } from "@/ui/ProofStrip";
import { useSession } from "@/state/SessionProvider";
import { useNames } from "@/state/names";
import { useReport } from "@/state/report";
import { nameOf } from "@/lib/naming";
import { MAX_CODE_POINTS, sanitize, validate } from "@/lib/display-name";
import { Field } from "@/ui/Field";
import { Input } from "@/ui/Input";
import { useNavigate, useRoute } from "@/routes/Router";

/**
 * The right column: who you are talking to, proved.
 *
 * # It is a route, and that is the whole reason it exists as a column
 *
 * `#/c/<key>/info` survives `Ctrl+R`, a re-lock and a shared link. The two panels it replaces
 * were `useState` booleans inside `Conversation.tsx`, so a reload dropped you back into the
 * thread with the verification you were half way through comparing closed.
 *
 * **Closed by default.** `#/c/<key>` alone renders no column: this is reference material, not
 * chrome, and a panel that opens itself takes a third of the window from the messages every time
 * somebody clicks a name. Switching conversation, on the other hand, *keeps* the suffix — the
 * open column is a mode the user is in, and Discord's behaviour here is the one people expect.
 *
 * # How it closes, and why the rules differ by width
 *
 * - `[✕]` everywhere. It is the control that always works and the one a mouse looks for.
 * - **Escape at `duo` and below only.** There the column is laid over the conversation and reads
 *   as a temporary surface, so dismissing it with Escape is what the gesture means. At `trio` it
 *   is an inline third of the layout, no more modal than the rail is; closing a permanent column
 *   with Escape would be a keystroke doing something the screen gives no hint of.
 * - **Outside click at `duo` only.** Same reasoning, and the boundary matters in the other
 *   direction too: at `trio` a click on the conversation is a click *in* the conversation, and
 *   losing the panel for it would be infuriating. Below `duo` the panel is the whole screen, so
 *   there is no outside.
 * - `[‹]` on one panel, which calls `history.back()` — it undoes the navigation that opened the
 *   panel rather than going to a place. See the rule in `routes/Router.tsx`.
 *
 * # Focus
 *
 * On open, focus moves to the panel heading, which carries `tabIndex={-1}` so it can receive it
 * without becoming a tab stop of its own. On close it returns to the `[ⓘ]` that opened it.
 *
 * That return is done by element id rather than by a shared ref, and the reason is a boundary:
 * `[ⓘ]` lives in the conversation header and this panel is mounted by the shell, so a ref would
 * have to travel through a context whose only member is one button. What it does not solve: at
 * one panel the toggle is not mounted while the detail covers the screen, so the focus lands
 * wherever the browser puts it after a history move. That is the browser's job on a back
 * navigation and it does it better than we would.
 */

/** The id the conversation header's `[ⓘ]` carries, so this panel can hand focus back to it. */
export const INFO_TOGGLE_ID = "conversation-info-toggle";

/** The id `[ⓘ]` points `aria-controls` at. */
export const DETAIL_PANEL_ID = "conversation-detail";

/**
 * The verification state, spelled out.
 *
 * "Secure" is the word this refuses to print. Nothing here has been compared by a human, so the
 * honest sentence names the machine part and the missing part in the same breath — an attested
 * key with no out-of-band check is exactly as strong as the first key the server handed us, and
 * a one-word verdict hides which of the two the reader is getting.
 */
function describe(state: VerificationState, rejected: boolean): { title: string; note: string } {
  if (rejected) {
    return {
      title: "Unattested device presented",
      note: "The server announced a device whose signature does not match this account. There is no benign explanation for that.",
    };
  }

  switch (state.status) {
    case "verified":
      return {
        title: "Compared by hand",
        note: "You confirmed this fingerprint out of band. It has not changed since.",
      };
    case "changed":
      return {
        title: "Fingerprint changed since you compared it",
        note: "Either they restored their account from their recovery phrase, or somebody has stepped in between. Nothing in the protocol tells the two apart.",
      };
    case "unverified":
      return {
        title: "Attested automatically · Not compared by hand",
        note: "Every device on this account carries a signature this client checked itself. That proves the server did not invent them; it does not prove the first key we were given was theirs.",
      };
  }
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-caption font-medium tracking-wide text-(--color-ink-muted) uppercase">
      {children}
    </h3>
  );
}

/**
 * The nickname this device gives somebody, and the only name on this panel nobody else can move.
 *
 * It sits under the proof rather than over it on purpose. The order of this column is shape,
 * verdict, digits, action — the argument that a pattern is noticed before a sentence is read. A
 * text field above that would push the one section that establishes *who this is* below the fold
 * in favour of a cosmetic one.
 *
 * # Why the reader gets to overrule the name somebody chose
 *
 * A display name is asserted by its subject: anybody can claim to be Charlie, and the one who
 * wants to be mistaken for Charlie is exactly the one who will. A petname is written by the
 * person reading it, which makes it the only link in the naming chain that no peer and no server
 * can influence — so it wins, everywhere, over both the asserted name and the handle.
 *
 * It is never sent. There is no code path that could send it, and that is not an accident: a note
 * you took about somebody is not something to hand back to them.
 */
function Petname({ handle }: { handle: string }) {
  const session = useSession();
  const report = useReport();
  const names = useNames();

  const saved = names.petnames[handle] ?? "";
  const [draft, setDraft] = useState(saved);

  // Keyed on the handle so that navigating from one member to another in the same panel resets
  // the field instead of carrying the previous person's nickname into it. `key` on the element
  // does the remount; this state simply starts from what is stored.
  const cleaned = sanitize(draft);
  const error = cleaned === "" ? null : validate(cleaned);
  const unchanged = cleaned === saved;

  async function save() {
    try {
      await session.setPetname(handle, draft);
      report.done(cleaned === "" ? `Nickname removed.` : `Saved. You will see them as ${cleaned}.`);
    } catch (failure: unknown) {
      report.error(failure instanceof Error ? failure.message : "The nickname could not be saved.");
    }
  }

  return (
    <section className="space-y-snug border-b border-(--color-border-subtle) p-pane">
      <SectionTitle>Nickname</SectionTitle>
      <form
        className="space-y-snug"
        onSubmit={(event) => {
          event.preventDefault();
          if (error === null && !unchanged) void save();
        }}
      >
        <Field
          label="Nickname"
          labelHidden
          hint="Only you see this. It replaces the name they chose for themselves, everywhere."
          error={error === "too-long" ? `At most ${MAX_CODE_POINTS} characters.` : undefined}
        >
          {(control) => (
            <Input
              id={control.id}
              aria-describedby={control.describedBy}
              aria-invalid={control.invalid}
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              placeholder="Not set"
              autoComplete="off"
              maxLength={MAX_CODE_POINTS * 2}
            />
          )}
        </Field>
        <Button type="submit" variant="secondary" size="sm" disabled={error !== null || unchanged}>
          Save nickname
        </Button>
      </form>
    </section>
  );
}

function AccountDetail({ account }: { account: ResolvedAccount }) {
  const session = useSession();
  const names = useNames();
  const [comparing, setComparing] = useState(false);

  const name = nameOf(account.handle, names);
  const state = session.verificationOf(account);
  const rejected = account.rejected.length > 0;
  const { title, note } = describe(state, rejected);
  // A changed fingerprint and an unattested device are the two states that get to shout. Both are
  // already red in the strip and in the avatar; the words are red too so the reader who scanned
  // the colour and the reader who read the sentence arrive at the same place.
  const loud = rejected || state.status === "changed";

  return (
    <>
      <section className="flex flex-col items-center gap-snug border-b border-(--color-border-subtle) p-pane text-center">
        <Avatar
          seed={account.fingerprint}
          label={name.primary}
          size="lg"
          proof={state}
          rejected={rejected}
        />
        {/* Both lines, always. The handle is what identifies this account; the name above it is
            only what the account says about itself, and dropping the anchor to save a line would
            leave a claim standing alone. */}
        <p className="text-title font-medium">{name.primary}</p>
        {name.secondary !== null && (
          <p className="font-evidence text-caption text-(--color-ink-muted)">{name.secondary}</p>
        )}
        <PresenceLine session={session} handle={account.handle} />
      </section>

      {/*
        The proof section, in the order the reading happens: the shape, then the verdict in words,
        then the digits the verdict is about, then the one action that can change the verdict.

        The strip is first because it is pre-verbal — a changed pattern is noticed before a
        sentence is read. It is also the weakest thing on the screen: nineteen bits, grindable.
        It says *something moved*; the hexadecimal underneath, compared out of band, is the only
        thing here that says *who this is*. That ordering is the section's whole argument, and it
        is why the strip never appears without the digits below it.
      */}
      <section className="space-y-snug border-b border-(--color-border-subtle) p-pane">
        <SectionTitle>Proof</SectionTitle>
        <ProofStrip
          fingerprint={account.fingerprint}
          scale="detail"
          verification={state}
          rejected={rejected}
        />
        <p
          className={
            loud ? "text-body font-medium text-(--color-danger)" : "text-body font-medium"
          }
        >
          {title}
        </p>
        <p className="text-caption text-(--color-ink-muted)">{note}</p>

        {comparing ? (
          <VerificationPanel account={account} onClose={() => setComparing(false)} />
        ) : (
          <>
            <Fingerprint value={account.fingerprint} />
            <Button
              variant={loud ? "primary" : "secondary"}
              size="sm"
              onClick={() => setComparing(true)}
            >
              Compare fingerprints
            </Button>
          </>
        )}
      </section>

      <Petname key={account.handle} handle={account.handle} />

      <section className="space-y-snug border-b border-(--color-border-subtle) p-pane">
        <SectionTitle>Devices</SectionTitle>
        {/* The count, then the identifiers. The fingerprint covers the account and does not move
            when a device is added, so this list is the only place a change of hardware is
            visible at all. */}
        <p className="text-caption text-(--color-ink-muted)">
          {account.devices.length} {account.devices.length === 1 ? "device" : "devices"} declared
          by this account.
        </p>
        <ul className="space-y-tight">
          {account.devices.map((device) => (
            <li key={device.id} className="font-evidence text-caption break-all">
              {device.id}
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}

export function DetailPanel({ view }: { view: ConversationView }) {
  const session = useSession();
  const names = useNames();
  const route = useRoute();
  const navigate = useNavigate();
  const duo = useDuo();
  const trio = useTrio();
  const heading = useRef<HTMLHeadingElement>(null);
  const panel = useRef<HTMLElement>(null);

  const wanted = route.kind === "conversation" ? route.detail?.handle : undefined;
  // A group with no member singled out shows the roster; a one-to-one has exactly one person to
  // show and asking the user to pick them would be a click that means nothing.
  const focused =
    view.accounts.find((account) => account.handle === wanted) ??
    (view.accounts.length === 1 ? view.accounts[0] : undefined);

  const close = () => {
    navigate({ kind: "conversation", key: view.key });
    // After the route change, not before: at `duo` and above the toggle is still mounted, but
    // React has not re-rendered it yet at the moment `navigate` returns.
    requestAnimationFrame(() => document.getElementById(INFO_TOGGLE_ID)?.focus());
  };

  // The heading takes focus when the panel appears, so a keyboard or screen reader user lands in
  // what just opened rather than continuing from the button they pressed.
  useEffect(() => {
    heading.current?.focus();
  }, []);

  useEffect(() => {
    if (trio) return;

    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      close();
    };

    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
    // Keyed on the conversation rather than on `close`, which is a fresh closure every render:
    // listing it would re-subscribe on every keystroke elsewhere in the tree.
  }, [trio, view.key]);

  useEffect(() => {
    // Only at exactly two panels: at three the column is inline and a click on the conversation
    // is a click in the conversation; at one there is nothing outside it.
    if (!duo || trio) return;

    const onDown = (event: PointerEvent) => {
      const target = event.target;
      if (target instanceof Node && panel.current?.contains(target)) return;
      // The toggle is outside the panel, and letting this fire would close and reopen in the
      // same gesture — the button would look dead.
      if (target instanceof Element && target.closest(`#${INFO_TOGGLE_ID}`)) return;
      close();
    };

    addEventListener("pointerdown", onDown);
    return () => removeEventListener("pointerdown", onDown);
    // Keyed on the conversation rather than on `close`, which is a fresh closure every render:
    // listing it would re-subscribe on every keystroke elsewhere in the tree.
  }, [duo, trio, view.key]);

  const title =
    view.accounts.map((a) => nameOf(a.handle, names).primary).join(", ") ||
    // `peers` carries MLS credentials, which are handles: available from restore, before the
    // first poll has resolved anybody, so a conversation reopened cold still has a title.
    [...new Set(view.peers.map((p) => p.name))].map((n) => nameOf(n, names).primary).join(", ") ||
    "empty conversation";

  return (
    <aside
      ref={panel}
      id={DETAIL_PANEL_ID}
      aria-label="Conversation details"
      className="safe-sides flex h-full min-h-0 w-full flex-col overflow-y-auto bg-(--color-surface-sunken)"
    >
      <header className="safe-top sticky top-0 z-(--z-index-sticky) flex items-center gap-snug border-b border-(--color-border-subtle) bg-(--color-surface-sunken) px-pane py-snug">
        {!duo && (
          <IconButton
            label="Back to the conversation"
            icon={<Icon name="back" size={20} />}
            onClick={() => history.back()}
            className="-ml-tight"
          />
        )}
        <h2
          ref={heading}
          tabIndex={-1}
          className="min-w-0 flex-1 truncate text-body font-medium outline-none"
        >
          {focused ? nameOf(focused.handle, names).primary : title}
        </h2>
        {duo && (
          <IconButton label="Close details" icon={<Icon name="close" />} onClick={close} />
        )}
      </header>

      {/* A group that has not singled anybody out lists its members; picking one is a navigation,
          so the back gesture collapses the card and leaves the column open. */}
      {focused === undefined && (
        <section className="space-y-snug border-b border-(--color-border-subtle) p-pane">
          <SectionTitle>Members</SectionTitle>
          <ul className="space-y-tight">
            {view.accounts.map((account) => {
              const name = nameOf(account.handle, names);

              return (
              <li key={account.handle}>
                <button
                  type="button"
                  onClick={() =>
                    navigate({
                      kind: "conversation",
                      key: view.key,
                      detail: { handle: account.handle },
                    })
                  }
                  className="flex w-full items-center gap-snug rounded-control p-snug text-left text-body hover:bg-(--color-surface) focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent) touch:min-h-11"
                >
                  <Avatar
                    seed={account.fingerprint}
                    label={name.primary}
                    size="md"
                    proof={session.verificationOf(account)}
                    rejected={account.rejected.length > 0}
                    className="shrink-0"
                  />
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate">{name.primary}</span>
                    {name.secondary !== null && (
                      <span className="truncate font-evidence text-caption text-(--color-ink-muted)">
                        {name.secondary}
                      </span>
                    )}
                  </span>
                </button>
              </li>
              );
            })}
            {view.accounts.length === 0 && (
              <li className="text-caption text-(--color-ink-muted)">
                Nobody has been resolved yet. The next poll fills this in.
              </li>
            )}
          </ul>
        </section>
      )}

      {focused && <AccountDetail account={focused} />}

      {/*
        Membership, roles and leaving, for groups only. `GroupPanel` already says the two things
        the user cannot guess — that leaving takes another member's commit, and that removing
        somebody removes all of their devices — and repeating either of them here would be a
        second copy to keep in step. It says them in the confirmation dialogs, at the moment the
        commit is about to go out, which is the only moment either sentence changes a decision.

        It takes no `session`, no `onError` and no `onChanged`: it reads the session through
        `useSession` and reports through `useReport`, so the roster and the roles stay fresh under
        it whatever this column's own render schedule does.
      */}
      {view.accounts.length > 1 && (
        <section className="space-y-snug p-pane">
          <SectionTitle>Conversation</SectionTitle>
          <GroupPanel view={view} onClose={close} />
        </section>
      )}
    </aside>
  );
}
