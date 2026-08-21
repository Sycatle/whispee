import assert from "node:assert/strict";
import { test } from "node:test";

import {
  type Attention,
  type NotificationApi,
  type NotificationHandle,
  type NoticeOptions,
  NOTICE_BODY_MANY,
  NOTICE_BODY_ONE,
  NOTICE_TITLE,
  countUnreadInTitle,
  createNotifier,
  notificationPermission,
  requestNotificationPermission,
  unreadTitle,
} from "./notifications.ts";

/** One notice the fake constructor raised, kept so a test can read what was published. */
interface Raised {
  title: string;
  options: NoticeOptions | undefined;
  handle: NotificationHandle;
  closed: boolean;
}

/**
 * A stand-in for `Notification`.
 *
 * `tag` collapsing is the platform's job, not the constructor's, so the fake does not implement
 * it: what the tests can and do check is that the same tag is asked for every time, which is the
 * only half of the bargain this codebase is responsible for.
 */
function fakeNotifications(permission: string, throwing = false) {
  const raised: Raised[] = [];

  const api = function (this: unknown, title: string, options?: NoticeOptions) {
    if (throwing) throw new TypeError("Illegal constructor");

    const entry: Raised = {
      title,
      options,
      closed: false,
      handle: {
        onclick: null,
        close() {
          entry.closed = true;
        },
      },
    };
    raised.push(entry);
    return entry.handle;
  } as unknown as NotificationApi;

  Object.defineProperty(api, "permission", { value: permission, writable: true });
  return { api, raised };
}

const looking: Attention = { visibilityState: "visible", hasFocus: () => true };
const away: Attention = { visibilityState: "hidden", hasFocus: () => false };
/** A visible tab in a window sitting behind the editor: the case `visibilityState` alone gets wrong. */
const unfocused: Attention = { visibilityState: "visible", hasFocus: () => false };

test("a browser with no Notification constructor reports unsupported, not denied", async () => {
  assert.equal(notificationPermission(undefined), "unsupported");
  assert.equal(await requestNotificationPermission(undefined), "unsupported");
});

test("the three browser permission states are reported as they are", () => {
  for (const state of ["granted", "denied", "default"] as const) {
    assert.equal(notificationPermission(fakeNotifications(state).api), state);
  }
});

/** Some engines have answered "prompt". Anything that is not a decision is "not yet asked". */
test("an unrecognised permission string is read as not yet asked", () => {
  assert.equal(notificationPermission(fakeNotifications("prompt").api), "default");
});

test("requesting the permission returns what the browser answered", async () => {
  const { api } = fakeNotifications("default");
  api.requestPermission = async () => "granted";
  assert.equal(await requestNotificationPermission(api), "granted");
});

/**
 * The prompt must be a consequence of a click. A module that fired it on import, or on the first
 * arrival, would spend the single prompt the browser ever grants before the user knew what for.
 */
test("nothing asks for the permission on its own", () => {
  const { api } = fakeNotifications("default");
  let asked = 0;
  api.requestPermission = async () => {
    asked += 1;
    return "granted";
  };

  const notifier = createNotifier({ select: () => {}, focus: () => {}, attention: away, api });
  notifier.arrived({ conversation: "a" });

  assert.equal(asked, 0);
});

test("without the permission granted, nothing is raised", () => {
  for (const state of ["default", "denied"] as const) {
    const { api, raised } = fakeNotifications(state);
    createNotifier({ select: () => {}, focus: () => {}, attention: away, api }).arrived({
      conversation: "a",
    });
    assert.equal(raised.length, 0);
  }
});

test("a message arriving while the page is hidden is announced", () => {
  const { api, raised } = fakeNotifications("granted");
  createNotifier({ select: () => {}, focus: () => {}, attention: away, api }).arrived({
    conversation: "a",
  });

  assert.equal(raised.length, 1);
  assert.equal(raised[0].title, NOTICE_TITLE);
  assert.equal(raised[0].options?.body, NOTICE_BODY_ONE);
});

test("nothing is announced while the user is looking at the page", () => {
  const { api, raised } = fakeNotifications("granted");
  createNotifier({ select: () => {}, focus: () => {}, attention: looking, api }).arrived({
    conversation: "a",
  });

  assert.equal(raised.length, 0);
});

test("a visible tab in an unfocused window still counts as away", () => {
  const { api, raised } = fakeNotifications("granted");
  createNotifier({ select: () => {}, focus: () => {}, attention: unfocused, api }).arrived({
    conversation: "a",
  });

  assert.equal(raised.length, 1);
});

/**
 * The property that stops a device catching up on forty messages from stacking forty notices: the
 * tag is the conversation, so the platform replaces rather than appends.
 */
test("every notice for one conversation carries that conversation as its tag", () => {
  const { api, raised } = fakeNotifications("granted");
  const notifier = createNotifier({ select: () => {}, focus: () => {}, attention: away, api });

  for (let i = 0; i < 40; i += 1) notifier.arrived({ conversation: "a" });
  notifier.arrived({ conversation: "b" });

  assert.deepEqual(
    [...new Set(raised.map((r) => r.options?.tag))],
    ["a", "b"],
  );
});

test("the second arrival in a conversation reads as plural, and a different conversation restarts at one", () => {
  const { api, raised } = fakeNotifications("granted");
  const notifier = createNotifier({ select: () => {}, focus: () => {}, attention: away, api });

  notifier.arrived({ conversation: "a" });
  notifier.arrived({ conversation: "a" });
  notifier.arrived({ conversation: "b" });

  assert.deepEqual(
    raised.map((r) => r.options?.body),
    [NOTICE_BODY_ONE, NOTICE_BODY_MANY, NOTICE_BODY_ONE],
  );
});

/**
 * Nothing decrypted goes onto a lock screen. The conversation key is a collapse tag, and a tag is
 * not displayed by any platform — but the body and the title are, and neither may name anything.
 */
test("the notice names no sender, no group and no content unless the caller discloses the name", () => {
  const { api, raised } = fakeNotifications("granted");
  const notifier = createNotifier({ select: () => {}, focus: () => {}, attention: away, api });

  notifier.arrived({ conversation: "group-with-a-telling-key" });
  assert.equal(raised[0].options?.body, NOTICE_BODY_ONE);
  assert.equal(raised[0].title, NOTICE_TITLE);

  notifier.dismiss("group-with-a-telling-key");
  notifier.arrived({ conversation: "group-with-a-telling-key", name: "Book club" });
  assert.equal(raised[1].options?.body, `${NOTICE_BODY_ONE} — Book club`);
});

test("reading a conversation takes back its notice and restarts its count", () => {
  const { api, raised } = fakeNotifications("granted");
  const notifier = createNotifier({ select: () => {}, focus: () => {}, attention: away, api });

  notifier.arrived({ conversation: "a" });
  notifier.dismiss("a");
  assert.equal(raised[0].closed, true);

  notifier.arrived({ conversation: "a" });
  assert.equal(raised[1].options?.body, NOTICE_BODY_ONE);
});

test("dismissing everything closes every conversation still standing", () => {
  const { api, raised } = fakeNotifications("granted");
  const notifier = createNotifier({ select: () => {}, focus: () => {}, attention: away, api });

  notifier.arrived({ conversation: "a" });
  notifier.arrived({ conversation: "b" });
  notifier.dismissAll();

  assert.deepEqual(raised.map((r) => r.closed), [true, true]);
});

test("clicking a notice focuses the window, selects that conversation, and closes the notice", () => {
  const { api, raised } = fakeNotifications("granted");
  const selected: string[] = [];
  let focused = 0;

  const notifier = createNotifier({
    select: (conversation) => selected.push(conversation),
    focus: () => {
      focused += 1;
    },
    attention: away,
    api,
  });

  notifier.arrived({ conversation: "a" });
  raised[0].handle.onclick?.();

  assert.equal(focused, 1);
  assert.deepEqual(selected, ["a"]);
  assert.equal(raised[0].closed, true);
});

/**
 * Android Chrome exposes `Notification` and throws `TypeError` on the constructor: notifications
 * exist there only through a service worker, and there is none here. A throw on every arriving
 * message must not reach the caller, which has no repair to offer.
 */
test("a browser whose constructor throws is silent rather than broken", () => {
  const { api } = fakeNotifications("granted", true);
  const notifier = createNotifier({ select: () => {}, focus: () => {}, attention: away, api });

  assert.doesNotThrow(() => notifier.arrived({ conversation: "a" }));
  assert.doesNotThrow(() => notifier.dismissAll());
});

test("the unread count is prefixed to the title, and zero leaves the title alone", () => {
  assert.equal(unreadTitle("Whispee", 3), "(3) Whispee");
  assert.equal(unreadTitle("Whispee", 1), "(1) Whispee");
  assert.equal(unreadTitle("Whispee", 0), "Whispee");
});

/** No cap: the number is the whole information, and a threshold nobody asked for is an invention. */
test("a large count is shown exactly", () => {
  assert.equal(unreadTitle("Whispee", 1247), "(1247) Whispee");
});

test("the counter writes the original title back when the count reaches zero", () => {
  const target = { title: "Whispee — end-to-end encrypted messaging" };
  const counter = countUnreadInTitle(target);

  counter.show(2);
  assert.equal(target.title, "(2) Whispee — end-to-end encrypted messaging");

  counter.show(0);
  assert.equal(target.title, "Whispee — end-to-end encrypted messaging");
});

/** Going from one count to another must not stack prefixes, which a naive prepend would do. */
test("counts replace each other rather than accumulating", () => {
  const target = { title: "Whispee" };
  const counter = countUnreadInTitle(target);

  counter.show(1);
  counter.show(2);
  counter.show(9);
  assert.equal(target.title, "(9) Whispee");
});

test("restoring puts the original back from any count", () => {
  const target = { title: "Whispee" };
  const counter = countUnreadInTitle(target);

  counter.show(5);
  counter.restore();
  assert.equal(target.title, "Whispee");
});

/**
 * `show` runs on every render of a list that re-renders on every poll. Assigning `document.title`
 * is a DOM write, and an unchanged count must not produce one.
 */
test("an unchanged count writes nothing", () => {
  let writes = 0;
  const target = {
    stored: "Whispee",
    get title() {
      return this.stored;
    },
    set title(value: string) {
      writes += 1;
      this.stored = value;
    },
  };

  const counter = countUnreadInTitle(target);
  counter.show(3);
  counter.show(3);
  counter.show(3);

  assert.equal(writes, 1);
  assert.equal(target.title, "(3) Whispee");
});
