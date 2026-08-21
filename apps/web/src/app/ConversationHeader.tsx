import { type FormEvent, useState } from "react";

import { PresenceLine } from "@/components/Presence";
import { membersOf } from "@/components/Conversation";
import { DETAIL_PANEL_ID, INFO_TOGGLE_ID } from "@/app/DetailPanel";
import { useDuo, useTrio } from "@/lib/duo";
import { normalize, validate } from "@/lib/handle";
import { compactNameOf, formatHandle, titleOf } from "@/lib/naming";
import type { ConversationView } from "@/lib/session";
import { Button } from "@/ui/Button";
import { cn } from "@/ui/cn";
import { Field } from "@/ui/Field";
import { handleMessage } from "@/ui/handleMessage";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Input } from "@/ui/Input";
import { Sheet } from "@/ui/Sheet";
import { Tooltip } from "@/ui/Tooltip";
import { useNames } from "@/state/names";
import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { useBinding } from "@/app/Shortcuts";
import { useNavigate, useRoute } from "@/routes/Router";

/**
 * The bar that names the conversation, and the controls that act on the conversation as a whole.
 *
 * # Why it left `Conversation.tsx`
 *
 * It used to be the first child of the thread's `<section>`, which made its width the width of
 * the thread: opening the detail column pushed the title and its controls left, and the column
 * arrived with a second header of its own carrying a second title for the same conversation. Two
 * bars, two titles, one thing being described. Mounted by the shell instead, the bar can span the
 * centre and the detail column at once — which is the arrangement this batch is after, and the
 * one every desktop client with a member column already uses.
 *
 * # The bar spans both columns at `trio`, and only at `trio`
 *
 * This asymmetry is decided, not approximated, and it follows from what each regime *is* rather
 * than from what is convenient to write.
 *
 * - **`trio` (≥ 64rem)** — the detail column is in flow, a third of the layout beside the thread.
 *   A bar drawn above both of them is above two things that are genuinely side by side, so the
 *   detail column starts *under* it and drops its own header entirely: the control that closes it
 *   is `[ⓘ]` here, which is already a toggle carrying `aria-expanded`. One title, one close, no
 *   duplication.
 * - **`duo` (48–64rem)** — the detail column is an overlay. It is lifted off the thread and
 *   covers the right hand side of it, including whatever bar is drawn there. Nothing can be
 *   "under" a surface that paints over it, so at this width the panel keeps its own header and
 *   its own `[✕]`. That is not an exception grudgingly made for a narrow window; it is what an
 *   overlay is. A shared bar would be a bar the panel hides half of.
 * - **below `duo`** — one pane on screen at a time, and the detail panel is the pane. It keeps
 *   its header and its back chevron for the same reason: there is no other bar on screen to
 *   share.
 *
 * The bar therefore paints itself two ways. At `trio` it is a surface of its own — rounded, sat
 * on the sunken ground with the shell's gutter under it, separated from the columns below by that
 * gutter and by nothing else, which is the rule the whole shell is built on. Everywhere else it
 * is the top of the centre surface, and it keeps the hairline it has always had: there it is not
 * a neighbour of the thread, it is the lid of it, and the scrolled message that stops behind it
 * needs a visible line to stop against.
 *
 * # What is deliberately absent
 *
 * A conversation search field. See the comment at the right hand end of the bar.
 */
export function ConversationHeader({ view }: { view: ConversationView }) {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const route = useRoute();
  const navigate = useNavigate();
  const duo = useDuo();
  const trio = useTrio();
  const names = useNames();

  const detailOpen = route.kind === "conversation" && route.detail !== undefined;

  const toggleDetail = () => {
    if (detailOpen) {
      navigate({ kind: "conversation", key: view.key });
      return;
    }
    navigate({ kind: "conversation", key: view.key, detail: {} });
  };

  // The keyboard route into the detail column. It is a navigation like the button, so it lands
  // in history and the back gesture closes the panel.
  //
  // It lives here because the toggle lives here: the shortcut and the button have to compute the
  // same destination from the same route, and splitting them across two components is how the two
  // drift apart. Below `duo` this component is not mounted while the detail panel is on screen —
  // the shell mounts one pane at a time — so `mod+i` opens the panel there and the back gesture
  // closes it, which is the same arrangement as before this bar moved.
  useBinding("detail.toggle", toggleDetail);

  /*
    One line and no room for a second: the line under this one belongs to the typing indicator
    and the presence line, both of which say something the title cannot. So the compact form,
    which falls back to handles rather than showing a name it cannot tell apart from another
    member's. The full two-line form is in the detail column, which is where somebody goes when
    they want to know exactly who is in the room.
  */
  // What makes this a group is its MLS roster, not how many people are left in it: removing the
  // third member of a group of three leaves two, and counting would have called that a
  // one-to-one — no roles, no way out, and an "add" button that started a different conversation.
  const group = session.isGroup(view);

  // Still needed below: the typing line names people against the same set the title does.
  const members = membersOf(view);
  const title = titleOf(view, names, members, group ? session.handle : undefined);

  const isTyping = session.typingIn(view);

  /**
   * Everybody in this conversation except us.
   *
   * `accounts` first, because that is the resolved list and the one the rest of the interface
   * counts. When it is empty the conversation has been restored but not yet polled, and the MLS
   * tree is the fallback — the same fallback, and the same `!== session.handle` filter, that
   * `Session.findConversation` applies to decide whether two conversations have the same members.
   *
   * It no longer answers "is this a group": that is `session.isGroup`, which reads the MLS
   * roster. This list was standing in for it, and the fallback above exists because of exactly
   * the failure that substitution caused — a cold-restored group being offered the one-to-one
   * treatment. The roster does not need the fallback.
   */
  const others =
    view.accounts.length > 0
      ? [...new Set(view.accounts.map((account) => account.handle))]
      : [...new Set(view.peers.map((peer) => peer.name))].filter(
          (handle) => handle !== session.handle,
        );
  const [adding, setAdding] = useState(false);

  // Moderators and the admin. `roles` is null in a one-to-one, where the question does not arise
  // and the button starts a new conversation instead.
  const roles = session.roles(view);
  const iModerate =
    roles !== null &&
    (roles.admin === session.handle || roles.moderators.includes(session.handle));
  const [invitees, setInvitees] = useState("");
  const [busy, setBusy] = useState(false);

  /**
   * Adding somebody to a one-to-one opens a **new** conversation, and says so before it does it.
   *
   * There is no other truthful shape for this button. An MLS group is its membership: the people
   * in it are the people the key schedule was derived for, and a two-person group does not grow a
   * third member any more than a signature grows a second signer. So the gesture everybody knows
   * from every other messenger — "add Carol to this chat" — is here a request to start the
   * conversation that has Carol in it, and the sheet is where that is said in words rather than
   * discovered afterwards by finding the old thread still sitting in the rail.
   *
   * It goes through `session.startConversation`, which is the same call `NewConversation.tsx`
   * makes, with the same `normalize`/`validate` pass in front of it for the same reason: a
   * malformed handle can never match an account, so sending it produces a 404 that reads as "that
   * person does not exist" when the truth is "that is not the shape a handle has". The one
   * addition is that the current members are prepended, so the new conversation carries the
   * person you were already talking to.
   *
   * `startConversation` returns the existing conversation when the member set already matches, so
   * typing a handle that is already here navigates back to this same thread rather than opening a
   * duplicate of it. That is the correct outcome and it needs no special case.
   */
  const add = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const wanted = invitees
        .split(",")
        .map(normalize)
        .filter((handle) => handle.length > 0);

      const malformed = wanted
        .map((handle) => ({ handle, problem: validate(handle) }))
        .find((entry) => entry.problem !== null);
      if (malformed?.problem) {
        report.error(
          `"${malformed.handle}" is not a usable handle. ${handleMessage(malformed.problem)}`,
        );
        return;
      }

      // A group takes them in; a one-to-one cannot and starts a new conversation instead. The
      // difference is not a preference: a two-person conversation is flat, with no admin, and
      // growing it in place would leave a group nobody administers — which the policy treats as
      // frozen for good.
      if (group) {
        for (const handle of wanted) await session.addAccount(view, handle);

        setInvitees("");
        setAdding(false);
        bump();
        report.done(
          wanted.length === 1
            ? `${formatHandle(wanted[0])} joined the conversation.`
            : `${wanted.length} people joined the conversation.`,
        );
        return;
      }

      const next = await session.startConversation([...others, ...wanted]);
      setInvitees("");
      setAdding(false);
      bump();
      // Pushed, not replaced. `NewConversation` replaces because the form it leaves behind has
      // been spent and nobody wants to go back to it; here the thing left behind is the
      // conversation the user was reading a second ago, and the back gesture returning to it is
      // exactly what somebody who added the wrong person will reach for.
      navigate({ kind: "conversation", key: next.key });
    } catch (e) {
      report.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <header
      className={cn(
        "safe-top flex items-center gap-pane px-pane py-snug",
        trio
          ? // Its own surface, sat on the sunken ground: at three columns this bar is a neighbour
            // of the two columns under it and the gutter is what separates neighbours here. A
            // hairline as well would be two devices doing one job.
            "shrink-0 rounded-surface bg-(--color-surface)"
          : // The lid of the centre surface. Content scrolls up to it, so it needs a line to stop
            // against.
            "border-b border-(--color-border-subtle)",
      )}
    >
      {/* Only where the list is not beside us. It undoes the navigation that opened this
          conversation rather than going to `#/`, so a round trip between the list and a thread
          does not stack one history entry per visit — see the rule in `routes/Router.tsx`. */}
      {!duo && (
        <IconButton
          label="Back to conversations"
          icon={<Icon name="back" size={20} />}
          onClick={() => history.back()}
          className="-ml-tight shrink-0"
        />
      )}
      {/*
        The epoch is not displayed — it is a protocol detail that teaches the user nothing.
        It is exposed as an attribute because two members on different epochs can no longer
        read each other at all: it is the first thing to check when a message fails to
        arrive, and finding it any other way means instrumenting the WebAssembly module.
      */}
      <div className="min-w-0 flex-1">
        {/* `<h1>`, because an open thread is what this page is about. The document used to start
            at `<h2>` the moment a conversation was opened: the only `<h1>` in the shell lived in
            `EmptyCenter`, which is the screen shown when nothing is open. Each route now has
            exactly one — this one, `Settings`, or the identity on the empty screen. */}
        {/* `text-prose` and not `text-body`: this is the page's heading, and it was set at the
            same size as the messages under it — so the one piece of text saying *which
            conversation this is* had no more weight than any line inside it. One step up the
            scale, which is enough to be found without turning the bar into a banner. */}
        <h1 className="truncate text-prose font-medium" data-epoch={String(view.epoch)}>
          {title}
        </h1>
        {/*
          "is typing…" wins over presence: typing implies being online, and showing both adds
          noise without adding information. One-to-one only — in a group, "online" would not
          say who it is talking about.
        */}
        {isTyping.length > 0 ? (
          <span className="text-caption text-(--color-ink-muted)">
            {isTyping.map((handle) => compactNameOf(handle, names, members)).join(", ")}{" "}
            {isTyping.length > 1 ? "are typing" : "is typing"}…
          </span>
        ) : (
          // One person's presence under the title, and only where the title is that person. In a
          // group — including one that removals have brought down to two — "last seen an hour
          // ago" under a name that stands for several people says nothing the reader can use.
          !group &&
          view.accounts.length === 1 && (
            <PresenceLine session={session} handle={view.accounts[0].handle} />
          )
        )}
      </div>

      {/*
        The controls, left to right: add people, details, and then the conversation search that
        does not exist yet.

        In a group the first of the three is inert, and the sentence that says why is in the
        detail panel's "Conversation" section — one press of `[ⓘ]` away, beside the removal
        controls it belongs with. A disabled button cannot carry the explanation itself:
        `IconButton` sets `pointer-events: none` when disabled, so a tooltip on it would never
        open for anybody, and a control whose reason only exists on hover has no reason at all for
        a finger. The accessible name carries the whole sentence instead, which is what a screen
        reader reads out when it lands on the button.
      */}
      {group && !iModerate ? (
        /* Adding is a moderator's act, like removing. A member who could add somebody they
           cannot then remove would be able to change the room for everybody with no way to undo
           it — and `removeAccount` is already a moderator's to call.

           A disabled button cannot carry its own explanation: `IconButton` sets
           `pointer-events: none` when disabled, so a tooltip on it never opens for anybody, and a
           reason that exists only on hover has no existence at all for a finger. The accessible
           name carries the whole sentence, which is what a screen reader reads when it lands
           here. */
        <IconButton
          label="Only a moderator can add people to this group."
          icon={<Icon name="add" size={18} />}
          disabled
          className="shrink-0"
        />
      ) : (
        <Tooltip label="Add people">
          <IconButton
            label="Add people"
            icon={<Icon name="add" size={18} />}
            onClick={() => setAdding(true)}
            className="shrink-0"
          />
        </Tooltip>
      )}

      <Tooltip label="Conversation details">
        <IconButton
          id={INFO_TOGGLE_ID}
          label="Conversation details"
          icon={<Icon name="info" size={18} />}
          aria-expanded={detailOpen}
          aria-controls={DETAIL_PANEL_ID}
          onClick={toggleDetail}
          className="shrink-0"
        />
      </Tooltip>

      {/*
        Conversation search belongs here, at the far right end of this bar, after the two controls
        above it. The order of the three is settled — add, details, search — so whoever writes the
        search has a place waiting rather than a row to rearrange.

        Nothing is rendered for it today, and that is the point. There is no search in this client:
        `searchCoverage` is a field on the stored session and nothing reads it. A magnifier that
        opened nothing, or a field that returned nothing, would be the one kind of interface lie
        this repository refuses everywhere else — a control that looks like a capability the
        product does not have. The absence is honest until the capability exists.
      */}

      {/* One field, because `startConversation` takes a list and the shape of the list is the
          thing being decided. A `Sheet` rather than a `Popover`: this is a question that has to be
          answered before anything else happens, it carries a text input that must survive a
          software keyboard, and it is the same surface at every width — a popover on a phone would
          be a card anchored to a corner of a screen it nearly fills. */}
      <Sheet
        open={adding}
        onOpenChange={(next) => {
          if (!busy) setAdding(next);
        }}
        title={group ? "Add people to this group" : "Add people"}
        description={
          group
            ? "They join from this moment. Nothing said before they arrive is readable to them — the group key moves forward with their arrival and does not reach back, whatever the server still holds."
            : "This does not change the conversation you are in. A two-person conversation cannot grow, so this starts a new one with everybody currently here plus whoever you name."
        }
      >
        {/* The submit sits inside the form rather than in the sheet's `actions` slot: a button in
            that slot is outside the `<form>` element and would have to be reconnected to it by id,
            across a portal, to make Enter in the field mean submit. One element that contains both
            is the version that cannot come apart. */}
        <form onSubmit={add} className="space-y-pane">
          <Field
            label="Handles"
            hint={
              group
                ? "One handle, or several separated by commas."
                : "One handle, or several separated by commas. Everybody already in this conversation comes along."
            }
          >
            {(control) => (
              <Input
                id={control.id}
                describedBy={control.describedBy}
                invalid={control.invalid}
                value={invitees}
                onChange={(event) => setInvitees(event.target.value)}
                placeholder="carol, or carol, dave"
                autoComplete="off"
                required
                // `text-base` on purpose: below 16 pixels, iOS zooms into the field on focus and
                // does not zoom back out on blur.
                className="w-full text-base"
              />
            )}
          </Field>

          <Button
            type="submit"
            variant="primary"
            busy={busy}
            // Nothing typed is nothing to do, and in a one-to-one the sentence on the button
            // promises a new conversation that would in that case be this one.
            disabled={invitees.trim() === ""}
          >
            {group ? "Add to the group" : "Start the new conversation"}
          </Button>
        </form>
      </Sheet>
    </header>
  );
}
