import assert from "node:assert/strict";
import { test } from "node:test";

import { ALIVE_TIMEOUT_MS, Calls, RING_TIMEOUT_MS, type CallPorts } from "./session-call.ts";
import type { Call } from "./call.ts";

/**
 * Drains the microtask queue.
 *
 * `tick` and the media callbacks start work with `void`, deliberately: neither a timer nor a
 * media event has anywhere to report a failure to. So the tests wait for the queue rather than
 * for a promise nobody returns.
 */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

/** What went out, in order, so a test can assert on the sequence rather than on a final state. */
interface Recorder {
  calls: Calls;
  signals: string[];
  announced: string[];
  /** Moves the clock. Nothing here waits on real time. */
  advance: (ms: number) => void;
  /** Reports a participant list, as the media layer would. */
  observe: (peers: string[]) => void;
  joins: number;
  left: () => number;
}

function harness(options: { failJoin?: boolean } = {}): Recorder {
  let now = 1_000_000;
  let left = 0;
  let announce: ((peers: string[]) => void) | undefined;

  const recorder = {
    signals: [] as string[],
    announced: [] as string[],
    joins: 0,
  };

  const room: Call = {
    mute: async () => {},
    rekey: async () => {},
    leave: async () => {
      left += 1;
    },
    peers: () => [],
  };

  const ports: CallPorts = {
    media: {
      join: async (join) => {
        recorder.joins += 1;
        if (options.failJoin) throw new Error("no media server");
        announce = join.onPeers;
        return room;
      },
    },
    now: () => now,
    signal: (_group, event, call) => recorder.signals.push(`${event}:${call.slice(0, 4)}`),
    announce: async (_group, event) => {
      recorder.announced.push(event);
    },
    admit: async () => ({
      join: {
        admission: { url: "wss://media.test", token: "t" },
        key: new Uint8Array(32),
        onPeers: () => {},
        onClosed: () => {},
      },
    }),
    changed: () => {},
  };

  const calls = new Calls(ports);

  return {
    calls,
    ...recorder,
    get signals() {
      return recorder.signals;
    },
    get announced() {
      return recorder.announced;
    },
    get joins() {
      return recorder.joins;
    },
    advance: (ms: number) => {
      now += ms;
    },
    observe: (peers: string[]) => announce?.(peers),
    left: () => left,
  };
}

test("an outgoing call rings before it is a call", async () => {
  const h = harness();
  await h.calls.place("group", "alice");

  // In the room, and nobody has answered. Reporting that as a call in progress would start a
  // duration counter over a phone that is still ringing.
  assert.equal(h.calls.current().phase, "ringing");
  assert.equal(h.calls.current().connectedAt, 0);
  assert.deepEqual(h.announced, ["invite"]);
});

/**
 * **What promotes a call is the media layer, never a frame.**
 *
 * The ephemeral channel authenticates the group and not the member, so "somebody answered" taken
 * from a frame is a claim any member could make about any other. Only what the media layer
 * observes may start a call.
 */
test("a call becomes a call when somebody else is actually in the room", async () => {
  const h = harness();
  await h.calls.place("group", "alice");

  h.observe(["peer-1"]);

  assert.equal(h.calls.current().phase, "connected");
  assert.deepEqual(h.calls.current().peers, ["peer-1"]);
});

test("an accepted call sends nothing durable until it ends, and then its duration", async () => {
  const h = harness();
  await h.calls.place("group", "alice");
  h.observe(["peer-1"]);

  h.advance(65_000);
  await h.calls.hang();

  assert.deepEqual(h.announced, ["invite", "ended"]);
  assert.equal(h.calls.current().phase, "idle");
});

/**
 * A call nobody took has to leave a trace, or the person who was away learns nothing.
 *
 * It is the caller who writes it: the callee may never have been awake at all, which is exactly
 * the case the line exists for.
 */
test("a call nobody answers is announced as missed by the caller", async () => {
  const h = harness();
  await h.calls.place("group", "alice");

  h.advance(RING_TIMEOUT_MS);
  h.calls.tick();
  await settle();

  assert.deepEqual(h.announced, ["invite", "missed"]);
});

/** A refusal writes nothing: the caller's own `missed` covers it, and two lines for one call
 * would be two lines for one call. */
test("refusing a call writes nothing to the thread", async () => {
  const h = harness();
  h.calls.receive("group", "9f2c41ab", "bob");

  await h.calls.hang();

  assert.deepEqual(h.announced, []);
  assert.ok(h.signals.some((entry) => entry.startsWith("declined:")));
});

test("an incoming call is refused while another is in progress", async () => {
  const h = harness();
  await h.calls.place("group", "alice");
  h.observe(["peer-1"]);

  h.calls.receive("other", "aabbccdd", "carol");

  assert.equal(h.calls.current().group, "group", "the live call was replaced");
  assert.ok(h.signals.includes("declined:aabb"), "the second caller was left ringing");
});

/**
 * **The timeout that keeps a phone from ringing forever.**
 *
 * A "stop ringing" frame can be lost, so the callee runs its own clock. Without this, a caller
 * whose browser closed between the invitation and the answer leaves a phone ringing with nothing
 * able to stop it.
 */
test("a ringing device gives up on a caller that went quiet", async () => {
  const h = harness();
  h.calls.receive("group", "9f2c41ab", "bob");

  h.advance(ALIVE_TIMEOUT_MS);
  h.calls.tick();
  await settle();

  assert.equal(h.calls.current().phase, "idle");
});

test("a live call is not given up on for silence, only for a lost connection", async () => {
  const h = harness();
  await h.calls.place("group", "alice");
  h.observe(["peer-1"]);

  h.advance(ALIVE_TIMEOUT_MS * 10);
  h.calls.tick();
  await settle();

  assert.equal(h.calls.current().phase, "connected", "a quiet participant is not a gone one");
});

test("the last participant leaving ends the call", async () => {
  const h = harness();
  await h.calls.place("group", "alice");
  h.observe(["peer-1"]);

  h.observe([]);
  await settle();

  assert.equal(h.calls.current().phase, "idle");
  assert.deepEqual(h.announced, ["invite", "ended"]);
});

/**
 * A media server that is off, a token refused, a microphone the user declined: all of them land
 * here, and all of them have to end the call. A screen reading "connecting" until somebody closes
 * it is the failure this catches.
 */
test("a call that cannot reach the media server ends instead of hanging", async () => {
  const h = harness({ failJoin: true });
  await h.calls.place("group", "alice");

  assert.equal(h.calls.current().phase, "idle");
  assert.deepEqual(h.announced, ["invite", "missed"]);
});

test("hanging up twice is a thing interfaces do", async () => {
  const h = harness();
  await h.calls.place("group", "alice");
  h.observe(["peer-1"]);

  await h.calls.hang();
  await h.calls.hang();

  assert.deepEqual(h.announced, ["invite", "ended"], "the second hang-up wrote a second line");
});

test("a frame about another call is ignored", async () => {
  const h = harness();
  await h.calls.place("group", "alice");
  h.observe(["peer-1"]);

  h.calls.absorb("left", "not-this-call", "their-device", "our-device");

  assert.equal(h.calls.current().phase, "connected");
});

/**
 * Our own frames come back to us: the server relays a signal to every subscriber of the group,
 * the sender included. Acting on them would make a device hang up on itself.
 */
test("our own frames are ignored", async () => {
  const h = harness();
  h.calls.receive("group", "9f2c41ab", "bob");

  h.calls.absorb("declined", "9f2c41ab", "our-device", "our-device");

  assert.equal(h.calls.current().phase, "incoming");
});

/**
 * Once in a room, presence is the media layer's to report. A `left` frame is a claim, and any
 * member of the group can make one about any other — so it may end a ring, never a call.
 */
test("a left frame cannot end a call that is already connected", async () => {
  const h = harness();
  await h.calls.place("group", "alice");
  h.observe(["peer-1"]);

  h.calls.absorb("left", h.calls.current().call, "their-device", "our-device");
  await settle();

  assert.equal(h.calls.current().phase, "connected");
});

test("muting is announced and remembered", async () => {
  const h = harness();
  await h.calls.place("group", "alice");
  h.observe(["peer-1"]);

  await h.calls.mute(true);

  assert.equal(h.calls.current().muted, true);
  assert.ok(h.signals.some((entry) => entry.startsWith("muted:")));
});
