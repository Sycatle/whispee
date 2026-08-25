/**
 * Saying that something arrived, without saying what, from whom, or where.
 *
 * # Why this exists when push deliberately does not
 *
 * Server push is built and left inert on purpose, and `docs/ROADMAP.md` argues why: a server that
 * chooses *whom* to wake gains a targeted activity trigger, and ceasing to wake four members out
 * of five makes the next post attributable to the fifth. Nothing cryptographic answers that.
 *
 * Everything here is the opposite kind of thing. A `Notification` raised by this page, from an
 * envelope this page already decrypted, tells the server nothing it did not already know — it
 * involves no server at all. It costs the threat model exactly zero, which is the only reason it
 * ships while push does not.
 *
 * # What it still does not solve
 *
 * It only fires while the page is running. A closed tab, a killed process, a phone asleep: no
 * notification, and no amount of client-side work changes that. Waking a stopped process is what
 * push is for, and push is the thing we are declining. The honest statement of this feature is
 * "you find out sooner while the app is open", not "you find out".
 *
 * # Why no React and no work at import
 *
 * The harness is `node --test` with no DOM. Every browser object this module touches is a
 * parameter with a structural type, in the way `lifecycle.ts` injects its clock and its
 * `EventTarget`, so the whole file is exercised against fakes. Nothing runs on import: the
 * defaults that reach for `document` and `Notification` are read inside functions, never at module
 * scope.
 */

/**
 * The permission, including the case the browser API has no word for.
 *
 * `Notification` is absent in a worker-only context, in older WebViews, and — the case that
 * actually happens — in the Android Chrome tab, where the constructor exists but throws. A caller
 * offering a "turn on notifications" button needs to distinguish "not yet asked" from "cannot be
 * asked", and `NotificationPermission` collapses both onto `"default"`.
 */
export type Permission = "unsupported" | "default" | "granted" | "denied";

/** The options this module ever passes. A subset of `NotificationOptions`, and deliberately tiny. */
export interface NoticeOptions {
  body?: string;
  tag?: string;
  renotify?: boolean;
}

/** What a raised notification has to offer us: a click, and a way to take it back. */
export interface NotificationHandle {
  /**
   * Typed loosely on purpose. The DOM declares `onclick` as taking an `Event` bound to a
   * `Notification`; a narrower signature here would stop the real constructor from satisfying
   * this interface, for no gain — nothing in this module reads the event.
   */
  onclick: ((...args: never[]) => unknown) | null;
  close(): void;
}

/** The constructor, as this module uses it. Satisfied by the browser's `Notification`. */
export interface NotificationApi {
  new (title: string, options?: NoticeOptions): NotificationHandle;
  readonly permission: string;
  requestPermission(): Promise<string>;
}

/**
 * Is the user looking?
 *
 * Two questions, not one, and `document` answers both. Satisfied by `document` itself.
 */
export interface Attention {
  readonly visibilityState: string;
  hasFocus(): boolean;
}

/** Anything with a mutable title. Satisfied by `document`. */
export interface TitleTarget {
  title: string;
}

/**
 * The browser's constructor, or `undefined` where there is none.
 *
 * Read through a function rather than captured in a module-level constant, so that importing this
 * file touches no global — which is what makes it loadable under `node --test`.
 */
export function browserNotifications(): NotificationApi | undefined {
  return typeof Notification === "undefined" ? undefined : Notification;
}

/** Reads a browser permission string, mapping anything unexpected onto "not yet asked". */
function readPermission(value: string): Permission {
  return value === "granted" || value === "denied" ? value : "default";
}

/** The current permission, without asking for it. */
export function notificationPermission(api = browserNotifications()): Permission {
  if (!api) return "unsupported";
  return readPermission(api.permission);
}

/**
 * Asks for the permission. **Call this from a click, never from an effect.**
 *
 * A page that asks on load is denied once and denied for good: Chrome and Firefox both remember
 * the refusal, and there is no second prompt to recover with. The browsers are right — a prompt
 * arriving before the user has any idea what the page is gets dismissed reflexively. So this
 * function exists to be wired to a button and is never called by this module.
 *
 * What it does not solve: a permission already denied cannot be re-requested from here. The only
 * way back is the browser's own site settings, and a caller seeing `"denied"` should say that
 * rather than offer the button again.
 */
export async function requestNotificationPermission(
  api = browserNotifications(),
): Promise<Permission> {
  if (!api) return "unsupported";
  return readPermission(await api.requestPermission());
}

/**
 * The application name, and the whole of what the notification says about itself.
 *
 * Not read from `document.title`: by the time a notification is raised the title carries an unread
 * count (see `countUnreadInTitle` below), and "(3) Whispee" on a lock screen is a worse thing to
 * publish than the name alone.
 */
export const NOTICE_TITLE = "Whispee";

/**
 * What a notification says, and why it says so little.
 *
 * "New message", with no sender, no group and no text. The argument the project makes against
 * push is that a wake-up must carry nothing; a local notification that spelled out
 * "@bob: see you at 8" would hand exactly that to whoever glances at the lock screen — the one
 * reader end-to-end encryption is powerless against, because they are looking at the decrypted
 * side. Everything in the protocol is arranged so the sender is not learnable, and printing the
 * handle on the outside of the device would give it away for a convenience.
 *
 * What this wording still discloses, plainly: that Whispee is installed, and that somebody wrote
 * to this device just now. That is irreducible — any notification at all says both — and it is why
 * the feature is off until the user turns it on.
 */
export const NOTICE_BODY_ONE = "New message";

/** Second and later arrivals in the same conversation, once the first has been collapsed into. */
export const NOTICE_BODY_MANY = "New messages";

/**
 * What an arrival addressed to this reader says instead.
 *
 * # This discloses more than the line above, and it is worth saying so
 *
 * "New message" says that somebody wrote to this device. "You were mentioned" says that somebody
 * addressed *this person* by name — which is a fact about a relationship, not only about traffic,
 * and it is legible to whoever picks the device up without unlocking it.
 *
 * It ships anyway, and the reason is that the alternative is not a quieter notification but no
 * feature at all: a mention that arrives saying exactly what every other message says has not
 * been signalled. A reader who wants the smaller disclosure has the setting that governs the
 * whole feature, and it is off until they turn it on.
 *
 * Still absent, and not by omission: **who** mentioned them, and **what** was said. Those remain
 * unavailable at any setting, for the reason `NOTICE_BODY_ONE` gives.
 */
export const NOTICE_BODY_MENTION = "You were mentioned";

/** A reply to something this reader wrote. Addressed to them as surely as their name would be. */
export const NOTICE_BODY_REPLY = "You were replied to";

/**
 * An incoming call.
 *
 * It carries no more than the other three — no name in the body, no conversation — for the reason
 * `NOTICE_BODY_ONE` gives about all of them. What it does say is *which kind* of thing arrived,
 * because a call announced as "New message" is a call somebody decides to read later.
 */
export const NOTICE_BODY_CALL = "Incoming call";

/**
 * Copy for a settings screen offering the disclosure, stated before the choice as `Signals.tsx`
 * does — and exported from here so the sentence and the behaviour cannot drift apart.
 */
export const DISCLOSE_NAME_COPY =
  "Showing the conversation name puts it on your lock screen, where anyone who picks the device " +
  "up reads it without unlocking. The message itself is never shown either way.";

/** One arrival, as the caller describes it. */
export interface Arrival {
  /**
   * Which conversation it landed in. `ConversationView.key` is exactly this.
   *
   * Used as the collapse key and handed back to `select`; never displayed. It is a local
   * identifier that leaves neither the process nor the page, so there is nothing to gain by
   * hashing it first.
   */
  conversation: string;
  /**
   * Why this arrival is for this reader in particular, when it is.
   *
   * Replaces the body rather than adding to it: a notification is one line, and "New message —
   * you were mentioned" spends the line saying twice what the second half already says.
   *
   * It also **defeats the collapse**, and that is the point of carrying it at all. Forty
   * messages and one mention share a tag, so without this the mention would be replaced by the
   * next ordinary arrival and the reader would never learn it happened.
   */
  address?: "mention" | "reply" | "call";
  /**
   * The conversation's display name, and **the only thing a user can opt into disclosing**.
   *
   * Passed by the caller, never read from storage here — this module owns no setting. Leave it
   * undefined and the notification names nothing. Message content has no flag: there is no value
   * of any setting that puts a decrypted body on a lock screen.
   */
  name?: string;
}

/** Raising and retracting arrival notices. */
export interface Notifier {
  /** Announces an arrival, or stays silent — see `createNotifier` for every reason it stays silent. */
  arrived(arrival: Arrival): void;
  /** Takes back the notice for one conversation, and forgets its count. For when it is read. */
  dismiss(conversation: string): void;
  /** Takes back everything still standing. For unmount, and for re-locking. */
  dismissAll(): void;
}

export interface NotifierConfig {
  /**
   * What clicking a notice should do, beyond focusing the window.
   *
   * A callback and not a route: navigation in this application is component state in `App.tsx`,
   * there is no router to reach into, and a module that imported one would be wrong the day that
   * changes.
   */
  select: (conversation: string) => void;
  /** Brings the window forward. Injected because `node --test` has no `window`. */
  focus?: () => void;
  /** Defaults to `document`, read at call time so the module still imports without a DOM. */
  attention?: Attention;
  /** Defaults to the browser constructor. */
  api?: NotificationApi;
}

export function createNotifier({
  select,
  focus = () => globalThis.focus(),
  attention = document,
  api = browserNotifications(),
}: NotifierConfig): Notifier {
  /**
   * One entry per conversation with an outstanding notice.
   *
   * The count decides singular against plural, and the handle is kept so a conversation being
   * opened can retract its notice. A handle the platform already replaced is stale, but `close()`
   * on a closed notification is defined as a no-op, so nothing has to track that.
   */
  const standing = new Map<string, { handle: NotificationHandle; count: number }>();

  const forget = (conversation: string) => {
    standing.get(conversation)?.handle.close();
    standing.delete(conversation);
  };

  return {
    arrived({ conversation, name, address }) {
      if (!api || readPermission(api.permission) !== "granted") return;

      // Nothing while the user is already looking at it.
      //
      // Both halves are needed. `visibilityState` alone calls a window sitting behind the editor
      // "visible", which is true of the tab and false of the person; `hasFocus` alone would go
      // quiet for a focused window on a virtual desktop nobody is on. This is the same
      // distinction `Messages.tsx` makes when it decides that a thread rendered in a background
      // tab was delivered and not read.
      if (attention.visibilityState === "visible" && attention.hasFocus()) return;

      const count = (standing.get(conversation)?.count ?? 0) + 1;
      // An address outranks the count. Being mentioned once among forty arrivals is the fact
      // worth carrying, and "New messages" would bury it under the thing that is true of every
      // other line in the batch.
      const lead =
        address === "call"
          ? NOTICE_BODY_CALL
          : address === "mention"
            ? NOTICE_BODY_MENTION
            : address === "reply"
              ? NOTICE_BODY_REPLY
              : count > 1
                ? NOTICE_BODY_MANY
                : NOTICE_BODY_ONE;
      const body = name ? `${lead} — ${name}` : lead;

      let handle: NotificationHandle;
      try {
        handle = new api(NOTICE_TITLE, {
          // `tag` is what stops a conversation catching up on forty messages from stacking forty
          // notices: same tag replaces rather than appends, so the shade holds one line per
          // conversation however far behind the device was. `renotify` is left off deliberately —
          // a replacement is then silent, which is the point. Forty pings is the failure mode
          // people turn the whole feature off over.
          tag: conversation,
          body,
          // Silence is the default and the right one — see `tag` above — but a replacement that
          // says something new has to be heard, or it is a line of text nobody was told to look
          // at. This is the one case: being addressed is rare, which is exactly what makes it
          // affordable to ping for and worth pinging for. Forty ordinary arrivals still make one
          // sound between them.
          ...(address ? { renotify: true } : {}),
        });
      } catch {
        // `new Notification()` throws `TypeError: Illegal constructor` in the Android Chrome tab,
        // where notifications exist only through a service worker's registration. Swallowed
        // rather than reported: the caller has no repair to offer, and an error banner for "your
        // browser cannot do this" on every message would be worse than the silence.
        //
        // **This used to say there was no service worker here, and that a worker would be a cache
        // of the application shell served by the same server the desktop build exists to stop
        // trusting.** There is one now — `public/sw.js` — and the sentence needed amending rather
        // than deleting, because the objection it made is still right about the thing it names.
        // That worker caches nothing: no `fetch` handler, no `Cache`, no precache manifest, and
        // `push.test.ts` asserts the absence rather than trusting the comment. It exists because
        // the Push API has no other delivery point — a push message wakes the worker, never a
        // document — and it cannot serve a stale application because it cannot serve one at all.
        //
        // What that does **not** fix is the path this `catch` is on: the worker only runs for a
        // push, so a tab open on Android Chrome still has no notification to show. The feature is
        // absent there exactly as before, and `lib/push.ts` covers the other case — the tab
        // closed — on the browsers that offer Web Push.
        return;
      }

      handle.onclick = () => {
        focus();
        select(conversation);
        // Closed by hand: a click leaves the notice standing on Windows and on GNOME, and a user
        // who has just been taken to the conversation should not have to dismiss the invitation
        // to go there.
        handle.close();
        standing.delete(conversation);
      };

      standing.set(conversation, { handle, count });
    },

    dismiss: forget,

    dismissAll() {
      for (const conversation of [...standing.keys()]) forget(conversation);
    },
  };
}

/**
 * The title with an unread count in front of it, or the title untouched.
 *
 * Exact, with no "99+" cap: a cap invents a threshold nobody asked for, and the number is the
 * whole information being conveyed.
 */
export function unreadTitle(original: string, unread: number): string {
  return unread > 0 ? `(${unread}) ${original}` : original;
}

/** A title being kept in step with an unread count, and the way to give it back. */
export interface TitleCounter {
  show(unread: number): void;
  /** Puts the original title back, whatever the count. For unmount. */
  restore(): void;
}

/**
 * Keeps `(3) Whispee` in the tab, and — the part that matters — puts `Whispee` back.
 *
 * The original is captured once, here, rather than recomputed by stripping a `(n) ` prefix off
 * whatever the title currently is. Stripping a prefix is a parser, and a parser is a thing that
 * gets it wrong on a title that legitimately begins with a bracket; storing the original cannot.
 *
 * A title left mutated after the count reaches zero is the bug nobody files and everybody sees, so
 * zero is a case in its own right and is tested as one.
 *
 * What it does not solve: it captures whatever the title is at creation. If something else has
 * already rewritten it, that rewrite becomes the "original" and is what gets restored. Nothing
 * else in this application writes `document.title`, and one owner is the only arrangement in which
 * restoring means anything.
 */
export function countUnreadInTitle(target: TitleTarget = document): TitleCounter {
  const original = target.title;

  return {
    show(unread) {
      const next = unreadTitle(original, unread);
      // Only on a change: assigning `document.title` is a DOM write, and this is called on every
      // render of a list that re-renders on every poll.
      if (target.title !== next) target.title = next;
    },
    restore() {
      target.title = original;
    },
  };
}

/*
 * # On the sound that is not here
 *
 * A short tone from the Web Audio API needs no audio file, and it was written and then removed.
 * Two reasons, both fatal:
 *
 *  1. **The notification already makes a sound.** Every platform plays its own on a fresh notice,
 *     and the one case where a tag replacement is silent is precisely the case — catching up on a
 *     conversation — where a second sound would be the obnoxious one. A tone here is a duplicate
 *     everywhere it works.
 *
 *  2. **It does not work where it would be needed.** An `AudioContext` created without a prior
 *     user gesture starts `suspended`, and browsers suspend it again for a backgrounded page. The
 *     only moment this module makes any noise is the moment the page is not being looked at, which
 *     is the moment autoplay policy silences it. Shipping it would mean a tone that plays on the
 *     developer's machine, where the page was clicked a second ago, and nowhere else.
 *
 * A sound for a message arriving in *another* conversation while the window is focused would be a
 * real feature — it is the one gap the visibility gate leaves — but that is an unrequested noise
 * in a window someone is working in, and it needs its own setting before it needs an oscillator.
 */
