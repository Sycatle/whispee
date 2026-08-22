/**
 * What a call *is*, as far as this device is concerned.
 *
 * # Nothing here is persisted, and that is the design
 *
 * Every other slice beside `session.ts` contributes to the stored session through `snapshot()`.
 * This one has no `snapshot`, because a call restored from disk is a call that ended while the
 * page was closed: the media connection is gone, the other side stopped hearing anything, and
 * the only thing a saved state could produce is a screen showing a conversation nobody is in.
 * The durable trace of a call is its message in the thread — see `content.ts`, kind `call` —
 * which is where a call log belongs.
 *
 * # One call at a time, deliberately
 *
 * A second call arriving during one is refused rather than queued. Holding two would mean mixing
 * two audio streams and deciding which one a mute button acts on, and neither question has an
 * answer a user would guess. The refusal is a `missed` in the other conversation, which is
 * exactly what the caller needs to know.
 *
 * # Why the state machine takes ports and not a `Session`
 *
 * The rule `docs/ARCHITECTURE.md` states for every slice, and here it is what makes the file
 * testable at all: the media SDK cannot be loaded by `node --test`, so it arrives as {@link
 * Media} and the tests hand over a recording stub instead. Everything below — who is ringing,
 * when a call may be given up on, what a lost frame is allowed to cost — is then reachable
 * without a browser.
 */
import type { Call, Media } from "./call";
import type { CallEvent as CallSignalEvent } from "./signals";

/**
 * How long a ringing call waits before it is given up on.
 *
 * It is bounded by the caller's patience, not by the network: a phone that rings for a minute
 * has already told its owner everything it can. Thirty seconds is roughly where a mobile network
 * stops trying too.
 *
 * The number matters at both ends. The caller stops waiting; the callee stops ringing. They run
 * their own timers, because a frame saying "give up" is a frame that can be lost.
 */
export const RING_TIMEOUT_MS = 30_000;

/**
 * How often a participant says it is still there.
 *
 * The media layer reports departures on its own, and faster than this. What the heartbeat covers
 * is the case it cannot: a caller whose browser was closed between the invitation and the answer
 * — no media connection ever existed, so nothing can report its loss.
 */
export const ALIVE_INTERVAL_MS = 5_000;

/** How long without a heartbeat before a ringing device concludes the caller has gone. */
export const ALIVE_TIMEOUT_MS = ALIVE_INTERVAL_MS * 3;

/**
 * What this device is doing about a call.
 *
 * `dialling` is the window between deciding to call and being in the room. It exists as its own
 * phase because it is where a call can fail for a reason worth showing — no media server
 * configured, a token refused — and a failure shown as "the call ended" would be a lie.
 */
export type CallPhase = "idle" | "dialling" | "ringing" | "incoming" | "connected";

export interface CallState {
  phase: CallPhase;
  /** The call's own id. Empty when idle. */
  call: string;
  /** The conversation it belongs to, as hex. Empty when idle. */
  group: string;
  /** Who placed it, as an account id. Ours when we did. */
  from: string;
  /** When this phase began, for the ring timeout and for the duration. */
  since: number;
  /** When the media connection was established, for the duration. Zero until then. */
  connectedAt: number;
  /** Whether our own microphone is off. */
  muted: boolean;
  /** The other participants, as room identities — see `identityFor` in `call.ts`. */
  peers: string[];
}

const IDLE: CallState = {
  phase: "idle",
  call: "",
  group: "",
  from: "",
  since: 0,
  connectedAt: 0,
  muted: false,
  peers: [],
};

/** What the state machine needs from the rest of the application. */
export interface CallPorts {
  media: Media;
  /** Milliseconds since the epoch. A parameter so a test can move time without waiting for it. */
  now: () => number;
  /** Emits an ephemeral frame. Failure is not reported: this channel is allowed to lose frames. */
  signal: (group: string, event: CallSignalEvent, call: string) => void;
  /** Sends a durable call message. The invitation and the conclusion go through here. */
  announce: (group: string, event: "invite" | "ended" | "missed", call: string, seconds: number) => Promise<void>;
  /** Asks the server for admission, and derives the frame key. Throws when calls are not configured. */
  admit: (group: string, call: string) => Promise<{ join: Parameters<Media["join"]>[0] }>;
  /** Called whenever the state changed, so the interface repaints. */
  changed: () => void;
}

/**
 * The call this device is in, or on the way into, or being rung by.
 *
 * Holds no `Session`, writes nothing to disk, and knows nothing about conversations beyond the
 * group id it was handed — the three clauses `docs/ARCHITECTURE.md` makes the condition for a
 * slice to be a slice rather than a mixin with an extra indirection.
 */
export class Calls {
  private state: CallState = IDLE;
  private room: Call | undefined;
  /** When the last sign of life from the far side arrived. */
  private heard = 0;
  /**
   * Whether this device placed the call it is in.
   *
   * It decides one thing only, and it is not the conclusion of a call that happened — that goes
   * to whoever is last out of the room. It decides who writes `missed`, for a call that never
   * had a participant to be last. See {@link hang}.
   */
  private placed = false;
  /**
   * How many accounts this call is waiting on, and which of them have said no.
   *
   * A refusal ends a call between two people, and that is the only shape this used to handle: one
   * `declined` frame, one hang-up. In a group of three it is wrong — Bob refusing while Carol is
   * still ringing would end the call for Carol too, who would go on ringing into a room nobody
   * is left in.
   *
   * Counted by **account** rather than by device, because an account rings on all of its devices
   * and a busy one of them declines on its own. Three refusals from three devices of one person
   * are one person saying no.
   */
  private awaited = 0;
  private declined = new Set<string>();
  // Assigned in the body rather than declared as a parameter property: the test runner strips
  // types without transforming, and a parameter property is a transform.
  private ports: CallPorts;

  constructor(ports: CallPorts) {
    this.ports = ports;
  }

  current(): CallState {
    return { ...this.state, peers: [...this.state.peers] };
  }

  /** True while this device has no business accepting another call. */
  busy(): boolean {
    return this.state.phase !== "idle";
  }

  /**
   * Places a call.
   *
   * The invitation goes out **before** the media connection is attempted, and the order is the
   * point: the invitation is what rings the other side and what wakes a sleeping device, and
   * making it wait on a media server would mean a slow server delays the ring rather than the
   * audio.
   */
  async place(group: string, from: string, awaited: number): Promise<void> {
    if (this.busy()) return;

    const call = newCallId();
    this.placed = true;
    // How many accounts have to refuse before there is nobody left to wait for. Required rather
    // than optional: a caller that forgot it would get zero, and zero means the first refusal
    // ends the call — the group bug this exists to close, reintroduced by an omission.
    this.awaited = Math.max(1, awaited);
    this.declined = new Set();
    this.state = { ...IDLE, phase: "dialling", call, group, from, since: this.ports.now() };
    this.ports.changed();

    await this.ports.announce(group, "invite", call, 0);
    if (this.state.call !== call) return;

    this.state = { ...this.state, phase: "ringing", since: this.ports.now() };
    this.heard = this.ports.now();
    this.ports.changed();

    await this.enter(group, call);
  }

  /**
   * Records an invitation arriving from somebody else.
   *
   * Refused while busy, and the refusal is silent on this device: the caller learns it from the
   * `declined` frame, and a second ringing screen over a live call would be the interface
   * deciding for its user which conversation matters.
   */
  receive(group: string, call: string, from: string): void {
    if (this.busy()) {
      this.ports.signal(group, "declined", call);
      return;
    }

    this.placed = false;
    // A ringing device counts nobody: `from` is the one account it is waiting on, and `absorb`
    // compares against it directly. The counter belongs to the caller, who is the only one with
    // several people to hear back from.
    this.awaited = 1;
    this.declined = new Set();
    this.state = { ...IDLE, phase: "incoming", call, group, from, since: this.ports.now() };
    this.heard = this.ports.now();
    this.ports.signal(group, "ringing", call);
    this.ports.changed();
  }

  /** Answers a ringing call. */
  async accept(): Promise<void> {
    if (this.state.phase !== "incoming") return;

    const { group, call } = this.state;
    this.ports.signal(group, "accepted", call);
    await this.enter(group, call);
  }

  /**
   * Refuses a ringing call, or hangs up on one in progress.
   *
   * One verb for both, because the difference is entirely in what is written to the thread and
   * the caller of this method has no way of knowing which applies. What it must never do is ask
   * the interface to decide.
   *
   * # The conclusion belongs to whoever is last out of the room
   *
   * The thread is shared, so a line written by one member is read by all of them, and the rule
   * has to name exactly one writer per call. Two rules were tried before this one, and a real
   * call broke each:
   *
   *  * *whoever was connected writes it* — one line per participant. A call between two browsers
   *    ended twice in both threads.
   *  * *the caller writes it* — one line, at the wrong moment. In a call of three, the caller
   *    hanging up first wrote `Appel · 44 s` into a thread whose other two members went on
   *    talking for minutes. A conclusion is a statement about the call, not about the writer's
   *    own departure, and the caller is only the last to leave by coincidence.
   *
   * So it is the last participant out who writes it: the one who, at the moment of leaving, has
   * nobody left to leave behind. That is one writer by construction — a room empties once — and
   * the duration it reports is the one the call actually lasted rather than the writer's share
   * of it.
   *
   * A call **nobody joined** has no last participant, so `missed` stays with the caller. That is
   * what {@link placed} is still for, and it is the only thing it is for.
   *
   * What this gives up: a call whose participants all vanish at once — every browser closed, a
   * network partition — leaves nobody holding an empty room, and so writes no line at all. A
   * thread missing a conclusion is a thread a reader can still make sense of; one stating that a
   * live call ended three minutes ago is not.
   */
  async hang(): Promise<void> {
    const { phase, group, call, connectedAt, peers } = this.state;
    if (phase === "idle") return;

    const placed = this.placed;
    this.ports.signal(group, phase === "incoming" ? "declined" : "left", call);
    await this.close();

    if (connectedAt !== 0) {
      // Somebody is still in there. They will write it when the room empties under them.
      if (peers.length > 0) return;

      const seconds = Math.round((this.ports.now() - connectedAt) / 1000);
      await this.ports.announce(group, "ended", call, seconds);
    } else if (placed && (phase === "dialling" || phase === "ringing")) {
      await this.ports.announce(group, "missed", call, 0);
    }
  }

  /** Silences or restores the microphone. */
  async mute(muted: boolean): Promise<void> {
    if (this.state.phase !== "connected") return;

    await this.room?.mute(muted);
    this.state = { ...this.state, muted };
    this.ports.signal(this.state.group, muted ? "muted" : "unmuted", this.state.call);
    this.ports.changed();
  }

  /**
   * Absorbs an ephemeral frame about a call.
   *
   * Everything here is a report, never an instruction: a frame for another call is ignored, and
   * a frame that never arrives costs at most a timeout. The channel authenticates the group and
   * not the member — see `signals.ts` — so nothing below may be allowed to matter more than that.
   */
  absorb(
    event: CallSignalEvent,
    call: string,
    device: string,
    ours: string,
    account: string,
  ): void {
    if (call !== this.state.call || device === ours) return;

    this.heard = this.ports.now();

    switch (event) {
      case "declined":
      case "left":
        // Only meaningful while nobody has connected: once in a room, the media layer is what
        // says who is present, and it says it from what it observes rather than from a claim.
        if (this.state.connectedAt !== 0) return;

        // **A refusal only speaks for the person who made it, and only to the person waiting.**
        //
        // A ringing device is waiting on one account: the one that called it. Another guest
        // saying no is news about that guest, not about whether this phone should stop ringing —
        // and taking it as a reason to stop is how a call of three fell apart on the first
        // refusal, with the two who had not answered yet both going quiet at once.
        //
        // The caller's own giving-up arrives here as `left` under the same account, and that one
        // does end the ring.
        if (!this.placed) {
          if (account === this.state.from) void this.hang();
          return;
        }

        // **One refusal is not the end of a group call.** Bob saying no while Carol is still
        // ringing has to leave Carol ringing; ending it there would hang up on a person who was
        // about to answer, on behalf of somebody who declined for themselves.
        //
        // The set is what makes this idempotent: a repeated frame, or two devices of one account
        // declining, must not count twice — with two correspondents that would end the call on
        // one person's refusal, which is the bug written the other way round.
        this.declined.add(account);
        if (this.declined.size >= this.awaited) void this.hang();
        return;

      case "accepted":
      case "ringing":
      case "alive":
      case "muted":
      case "unmuted":
        return;
    }
  }

  /**
   * Hands a live call the key of the new epoch.
   *
   * Called on every commit. A member who has just been removed cannot derive this key, so they
   * stop hearing the call at the same instant they stop reading the conversation — the property
   * comes from MLS, and this line is what stops it costing everybody else the call.
   */
  async rekey(key: Uint8Array): Promise<void> {
    await this.room?.rekey(key);
  }

  /**
   * The periodic tick: emits the heartbeat, and gives up on what has gone quiet.
   *
   * Both timeouts are local, and both ends run their own. A frame saying "stop ringing" could be
   * lost, and a phone that then rang forever would be the one failure a user cannot work around.
   */
  tick(): void {
    const { phase, group, call, since } = this.state;
    if (phase === "idle") return;

    const now = this.ports.now();

    if (phase === "connected") {
      this.ports.signal(group, "alive", call);
      return;
    }

    if (now - since >= RING_TIMEOUT_MS || now - this.heard >= ALIVE_TIMEOUT_MS) {
      void this.hang();
      return;
    }

    // Still ringing, at either end. The caller says it is still waiting, the callee that it is
    // still ringing — each is what stops the other from ringing out over a caller who closed
    // their browser before anybody could answer.
    this.ports.signal(group, phase === "incoming" ? "ringing" : "alive", call);
  }

  /** Joins the room. Any failure ends the call rather than leaving it half-open. */
  private async enter(group: string, call: string): Promise<void> {
    try {
      const { join } = await this.ports.admit(group, call);
      const room = await this.ports.media.join({
        ...join,
        onPeers: (peers) => this.observed(call, peers),
        onClosed: () => void this.hang(),
      });

      // The call was hung up while the connection was being made. Leaving immediately is the
      // only correct move: the room would otherwise hold a participant nothing on this device
      // knows about.
      if (this.state.call !== call) {
        await room.leave();
        return;
      }

      // **Being in the room is not being in a call.** The caller joins before anybody has
      // answered — that is what a room is for — so the phase stays `ringing` until somebody else
      // is heard from. `observed` is what promotes it, from what the media layer reports rather
      // than from a claim on the ephemeral channel.
      this.room = room;
      this.heard = this.ports.now();
      this.observed(call, room.peers());
    } catch {
      // A refused token, a media server that is not configured, a microphone the user declined.
      // All of them end here, and all of them end the call — the alternative is a screen that
      // says "connecting" until somebody closes it.
      await this.hang();
    }
  }

  /**
   * The participant list, as the media layer sees it. It is the only thing that decides whether
   * a call is happening.
   *
   * The ephemeral channel could claim as much, and deliberately does not get to: it authenticates
   * the group rather than the member, so "somebody answered" taken from a frame is a claim any
   * member could make about any other. What the media layer reports is what it observes.
   */
  private observed(call: string, peers: string[]): void {
    if (this.state.call !== call) return;

    const now = this.ports.now();
    this.heard = now;

    if (peers.length > 0 && this.state.connectedAt === 0) {
      this.state = { ...this.state, phase: "connected", since: now, connectedAt: now, peers };
      this.ports.changed();
      return;
    }

    this.state = { ...this.state, peers };
    this.ports.changed();

    // Everybody left. The media layer reports it, and taking it from here rather than from a
    // frame means it also covers the participant who lost their network instead of hanging up,
    // who emits nothing at all.
    if (peers.length === 0 && this.state.phase === "connected") void this.hang();
  }

  private async close(): Promise<void> {
    const room = this.room;
    this.room = undefined;
    this.placed = false;
    this.state = IDLE;
    this.ports.changed();

    // After the state is cleared, so that a slow disconnection cannot leave the interface
    // showing a call that this device has already given up on.
    await room?.leave();
  }
}

/**
 * A fresh call id: sixteen hex characters of randomness.
 *
 * It has to be unpredictable, not merely unique. It is one of the two inputs to the room name,
 * and a guessable one would let anybody who knows a group id name the room its calls happen in.
 */
export function newCallId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
