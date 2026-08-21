import { useEffect, useRef, useState } from "react";

import { useGroupAdmin } from "@/components/Group";
import { MiniProfile } from "@/components/MiniProfile";
import { ContextMenu } from "@/ui/ContextMenu";
import { PresenceBadge, PresenceLine } from "@/components/Presence";
import { VerificationPanel } from "@/components/Verification";
import { Fingerprint } from "@/components/Fingerprint";
import type { ResolvedAccount } from "@/lib/account";
import { useDuo, useTrio } from "@/lib/duo";
import { isOnline } from "@/lib/presence";
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
 * # Sections are separated by space, and by nothing else
 *
 * The column is five blocks stacked — identity, proof, nickname, devices, and either the member
 * list or the group controls. Each used to end in a `border-b`, so the panel was five hairlines
 * tall, and a reader scrolling it saw a ruled form rather than a document. They are gone. Each
 * section still carries `p-pane`, so two adjacent ones put a full `2rem` between their contents
 * against `0.5rem` inside them — a four-to-one ratio, which is a wider margin than the hairline
 * ever drew and is read the same way for the same reason: things that belong together sit
 * closer.
 *
 * The one rule that stays is under the sticky header, and it is doing a different job. See the
 * comment at the header itself.
 *
 * What this does not solve: it assumes every section keeps `p-pane`. A future section written
 * with tighter padding would collapse into its neighbour with nothing to catch it, because
 * nothing here enforces the ratio — the separation lives in each section's own class list rather
 * than in a `gap` on the container, since the container also holds the header, which must not be
 * pushed away from the content it covers.
 *
 * # Its header exists at two widths out of three
 *
 * At `trio` this panel has **no header bar**. The conversation bar above it spans the centre and
 * this column both, it already carries the conversation's title, and its `[ⓘ]` is a toggle with
 * `aria-expanded` — so a second bar here would be a second title for the same conversation and a
 * second control for the same open/closed state. The heading survives as an `sr-only` `<h2>`,
 * because it is what focus lands on when the panel opens and what names the region to a screen
 * reader; only its painting goes.
 *
 * At `duo` and below the bar comes back, and the reason is what this panel *is* at those widths
 * rather than a shortage of room. At `duo` it is an overlay: it paints over the right hand side
 * of the conversation, bar included, so there is no shared bar left for it to borrow a close
 * control from. Below `duo` it is the only pane mounted. Detached surfaces carry their own chrome;
 * that is the whole difference between a surface and a section.
 *
 * # How it closes, and why the rules differ by width
 *
 * - `[✕]` at `duo` exactly. At `trio` the control that closes this column is the `[ⓘ]` in the
 *   shared bar; below `duo` it is `[‹]` and the back gesture.
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
 * That return is done by element id rather than by a shared ref. `[ⓘ]` lives in
 * `ConversationHeader`, which is this panel's sibling under the shell rather than its ancestor:
 * a ref would have to go up to the shell and back down, through a context whose only member is
 * one button, and it would have to survive the bar being mounted in two different places
 * depending on the width. An id is the same lookup at all three widths.
 *
 * What it does not solve: at one panel the toggle is not mounted while the detail covers the
 * screen, so the focus lands wherever the browser puts it after a history move. That is the
 * browser's job on a back navigation and it does it better than we would.
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
    <section className="space-y-snug p-pane">
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
      <section className="flex flex-col items-center gap-snug p-pane text-center">
        <PresenceBadge session={session} handle={account.handle}>
          <Avatar
            seed={account.fingerprint}
            label={name.primary}
            size="lg"
            proof={state}
            rejected={rejected}
          />
        </PresenceBadge>
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
      <section className="space-y-snug p-pane">
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

      <section className="space-y-snug p-pane">
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
    // Only outside a group. A group of two is still a group: it has a member list to show, and
    // opening straight onto the one other person's card would hide the roster and the actions
    // that go with it.
    (!session.isGroup(view) && view.accounts.length === 1 ? view.accounts[0] : undefined);

  const close = () => {
    navigate({ kind: "conversation", key: view.key });
    // After the route change, not before: at `duo` and above the toggle is still mounted, but
    // React has not re-rendered it yet at the moment `navigate` returns.
    requestAnimationFrame(() => document.getElementById(INFO_TOGGLE_ID)?.focus());
  };

  // The administration of a group, as a menu per member and a footer. Called unconditionally —
  // it is a hook — and it costs nothing in a one-to-one, where `roles` is null and `menuFor`
  // returns the empty answer.
  const group = useGroupAdmin({ view });

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
      className="safe-sides flex h-full min-h-0 w-full flex-col overflow-y-auto bg-(--color-surface)"
    >
      {/*
        At three columns the heading is announced and not painted. The bar above this column names
        the conversation already, and a panel that repeated the name under the bar showing it
        would be saying the same word twice, six millimetres apart. It stays in the DOM because it
        is what `focus()` lands on when the panel opens and what a screen reader reads on entering
        the region — removing it would trade a duplicated word for a panel nobody can be put into.

        `tabIndex={-1}` for the same reason as below: focusable on purpose, never a tab stop.
      */}
      {trio ? (
        <h2 ref={heading} tabIndex={-1} className="sr-only">
          {focused ? nameOf(focused.handle, names).primary : title}
        </h2>
      ) : (
        /*
          The header keeps its hairline while the sections below have lost theirs, and the two are
          not the same kind of line. A section boundary separates two blocks that are simply next
          to each other, and space says that better than a rule. This one separates a bar that
          stays put from content that slides underneath it: the scrolled sentence has to stop
          somewhere visible, and without the rule it fades into the identically coloured bar
          mid-word.

          The fill has to be opaque and has to match the panel exactly, which is why it is
          repeated here rather than inherited — a sticky element with no background of its own
          shows whatever is passing behind it.
        */
        <header className="safe-top sticky top-0 z-(--z-index-sticky) flex items-center gap-snug border-b border-(--color-border-subtle) bg-(--color-surface) px-pane py-snug">
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
          {/* `duo` and not `trio` too: at three columns this panel is in flow under a shared bar
              whose `[ⓘ]` closes it, and a second closing control for one state is a second thing
              to keep in step. */}
          {duo && <IconButton label="Close details" icon={<Icon name="close" />} onClick={close} />}
        </header>
      )}

      {/* A group that has not singled anybody out lists its members; picking one is a navigation,
          so the back gesture collapses the card and leaves the column open. */}
      {focused === undefined && (
        <section className="space-y-snug p-pane">
          {/*
            Split by presence, and our own row first.
            
            A member list is read to answer "who can I reach right now", and a single alphabet of
            names makes that a scan rather than a look. Two headings turn it into one glance.
            
            We are in the list because we are in the group. Leaving ourselves out made the count
            disagree with the group panel below, which has always said "@you (admin)" — and a
            member list that quietly omits the reader is a list they have to do arithmetic on.
            
            What this does not solve: accounts nobody has ever reported on sit under "Offline",
            which is a claim we cannot fully back — it may only mean the server has never had a
            signal for them. They are distinguishable on the row itself, where the badge and the
            "last seen" line are both absent rather than wrong, but the heading above them is
            more definite than the knowledge under it.
          */}
          {(() => {
            const self = {
              handle: session.accountId,
              fingerprint: session.accountFingerprint(),
              mine: true as const,
            };
            const others = view.accounts.map((account) => ({ account, mine: false as const }));
            const online = (handle: string) =>
              handle === session.accountId || isOnline(session.presenceOf(handle), session.presenceClock);

            const rows = [{ account: self, mine: true as const }, ...others];
            const groups: [string, typeof rows][] = [
              ["Online", rows.filter((row) => online(row.account.handle))],
              ["Offline", rows.filter((row) => !online(row.account.handle))],
            ];

            return groups
              .filter(([, members]) => members.length > 0)
              .map(([heading, members]) => (
                <div key={heading} className="space-y-snug">
                  <SectionTitle>{heading}</SectionTitle>
                  <ul className="space-y-tight">
                    {members.map(({ account, mine }) => {
                      const name = nameOf(account.handle, names);

                      return (
              <ContextMenu key={account.handle} trigger={
              <li>
                {/* The card, not the column. Clicking a name used to replace this whole panel
                    with that person's verification card — the right destination for comparing a
                    key, the wrong one for "who is this", which is what a click on a name in a
                    member list is asking. The column stays one press away, from inside the card. */}
                <MiniProfile handle={account.handle} view={view}>
                <button
                  type="button"
                  className="flex w-full items-center gap-snug rounded-control p-snug text-left text-body hover:bg-(--color-surface-sunken) focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent) touch:min-h-11"
                >
                  <PresenceBadge session={session} handle={account.handle}>
                    <Avatar
                      seed={account.fingerprint}
                      label={name.primary}
                      size="md"
                      // Our own entry carries neither: there is no verification of this device's
                      // own key, and nothing of ours to have been rejected.
                      {...(mine ? {} : { proof: session.verificationOf(account as ResolvedAccount) })}
                      rejected={!mine && (account as ResolvedAccount).rejected.length > 0}
                      className="shrink-0"
                    />
                  </PresenceBadge>
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="flex min-w-0 items-baseline gap-snug">
                      <span className="truncate">{name.primary}</span>
                      {mine && <span className="text-(--color-ink-muted)">(you)</span>}
                      {/* Who administers, which the removed roster used to say and nothing else
                          does now. */}
                      {group.role(account.handle) !== null && (
                        <span className="shrink-0 text-caption text-(--color-accent)">
                          {group.role(account.handle)}
                        </span>
                      )}
                    </span>
                    {name.secondary !== null && (
                      <span className="truncate font-evidence text-caption text-(--color-ink-muted)">
                        {name.secondary}
                      </span>
                    )}
                    {/* The badge on the face says *whether*, this says *when* — and the second is
                        the question somebody opens this column to answer. It renders nothing at
                        all for an account nobody has reported on, which is the same silence the
                        badge keeps: "we have never been told" has no honest wording here. */}
                    <PresenceLine session={session} handle={account.handle} />
                  </span>
                </button>
                </MiniProfile>
              </li>
                      }>
                        {/* Promote, hand over, remove — the same actions the group panel used to
                            carry under each name, and they still go through the confirmations
                            that explain what removing somebody costs. A context menu must not be
                            the door that skips the warning. */}
                        {group.menuFor(account.handle)}
                      </ContextMenu>
                      );
                    })}
                  </ul>
                </div>
              ));
          })()}

          {view.accounts.length === 0 && (
            <p className="text-caption text-(--color-ink-muted)">
              Nobody else has been resolved yet. The next poll fills this in.
            </p>
          )}
        </section>
      )}

      {focused && <AccountDetail account={focused} />}

      {/* The confirmations, mounted outside every menu — see `useGroupAdmin`. Nothing is drawn
          until one is asked for. */}
      {group.dialogs}
    </aside>
  );
}
