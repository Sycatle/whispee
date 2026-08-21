/**
 * Gateway session: one connection, every conversation.
 *
 * # What this module is not
 *
 * It is **not** a source of truth. An `envelope` frame only says "go and look"; the normal poll
 * is what reads, checks membership and advances the cursor. A session that never opens leaves the
 * application fully functional, only less responsive.
 *
 * That property is not a luxury: a connection whose failure would lose messages would be a
 * connection we had to make reliable, and we would have reinvented transport on top of transport.
 * It also explains why the cursors sent on open are only an optimisation — ignoring them costs a
 * poll, not a message.
 *
 * # What it takes away from the server
 *
 * Polling every 1.5 seconds sent one signed request per conversation per round: an activity log
 * accurate to the second. Catching up by cursors additionally removes the wake-up poll — the
 * server only answers when it has something to say.
 *
 * # What it gives it
 *
 * A regular heartbeat, hence presence. Same trade-off the SSE stream already documented, except
 * that here it is explicit: the heartbeat is a frame, not a side effect.
 *
 * # Dynamic scope
 *
 * Unlike the SSE stream it replaces, the scope is no longer frozen at open time. A conversation
 * discovered along the way is added with a `subscribe` frame, without reopening the connection or
 * signing another challenge.
 */
import { BASE_URL, type Api, type GatewayChallenge } from "./api";
import { fromBase64, fromHex, toBase64, toHex } from "./keys";

export interface GatewayHandlers {
  onEnvelope(groupId: Uint8Array, seq: number): void;
  onSignal(groupId: Uint8Array, payload: Uint8Array): void;
}

/** Reconnection delay ceiling. Beyond it, we hammer a server that is already struggling. */
const MAX_BACKOFF_MS = 30_000;

/** Last known sequence of a conversation, as announced on open. */
export interface Cursor {
  groupId: Uint8Array;
  seq: number;
}

export class Gateway {
  private socket?: WebSocket;
  private closed = false;
  private attempt = 0;
  private heartbeat?: ReturnType<typeof setInterval>;

  /** Pace imposed by the server, overwritten by the value announced in `hello`. */
  private heartbeatMs = 30_000;

  /**
   * Groups this session must cover.
   *
   * Held here rather than derived on every reconnection: the server subscribes us automatically
   * to the groups the device belongs to, but the local set is what lets us replay the
   * `subscribe` frames after a drop without waiting for the next poll.
   */
  private readonly scope = new Set<string>();

  constructor(
    private readonly api: Api,
    private readonly handlers: GatewayHandlers,
    /**
     * Cursors at the moment of (re)connection.
     *
     * A function, not a value: between two attempts the poll may have advanced, and sending a
     * stale cursor would re-announce sequences already read.
     */
    private readonly cursors: () => Cursor[],
    /**
     * Builds the signed message, provided by the WebAssembly module.
     *
     * Injected rather than imported, for the same reason as in `api.ts`: this module must not
     * depend on loading the WASM, which is asynchronous and does not happen at the same time.
     */
    private readonly challengeFormat: GatewayChallenge,
  ) {}

  start(): void {
    this.closed = false;
    void this.loop();
  }

  close(): void {
    this.closed = true;
    this.stopHeartbeat();
    this.socket?.close();
    this.socket = undefined;
  }

  /**
   * Adds a conversation to the session's scope.
   *
   * Idempotent, and safe while offline: the scope is remembered and replayed on the next
   * reconnection. This is what replaces the full reopen the SSE stream required.
   */
  subscribe(groupId: Uint8Array): void {
    const key = toHex(groupId);
    if (this.scope.has(key)) return;

    this.scope.add(key);
    this.send({ op: "subscribe", group_id: key });
  }

  unsubscribe(groupId: Uint8Array): void {
    const key = toHex(groupId);
    if (!this.scope.delete(key)) return;

    this.send({ op: "unsubscribe", group_id: key });
  }

  /**
   * Relays an ephemeral signal over the session rather than over an HTTP request.
   *
   * The group MAC remains what authenticates it: the session knows our identity, but using it
   * here would undo sealed sender. The server applies exactly the same check as on the HTTP path.
   *
   * Returns `false` when the session is closed, the caller then falling back to the HTTP route.
   * That route is **anonymous too**: the fallback degrades nothing in the threat model, it merely
   * costs a request where a frame would have done.
   */
  signal(groupId: Uint8Array, nonce: Uint8Array, mac: Uint8Array, payload: Uint8Array): boolean {
    return this.send({
      op: "signal",
      group_id: toHex(groupId),
      nonce: toBase64(nonce),
      mac: toBase64(mac),
      payload: toBase64(payload),
    });
  }

  /** True while the socket is open — used to decide whether a signal can go out. */
  get live(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  private send(frame: Record<string, unknown>): boolean {
    if (!this.live) return false;

    this.socket?.send(JSON.stringify(frame));
    return true;
  }

  private async loop(): Promise<void> {
    while (!this.closed) {
      try {
        await this.session();
        // Clean termination on the server side: we start over without penalty.
        this.attempt = 0;
      } catch {
        // Deliberately silent. A dropped session is an ordinary event — network switch, device
        // sleep, server restart — and reporting it to the user would wrongly suggest that
        // something was lost.
      }

      if (this.closed) return;

      const delay = Math.min(MAX_BACKOFF_MS, 500 * 2 ** this.attempt);
      this.attempt += 1;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  /** One session, from open to close. Resolves on close, rejects on error. */
  private session(): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = `${BASE_URL.replace(/^http/, "ws")}/v1/gateway`;
      const socket = new WebSocket(url);
      socket.binaryType = "arraybuffer";
      this.socket = socket;

      socket.onerror = () => reject(new Error("gateway session refused"));

      socket.onclose = () => {
        this.stopHeartbeat();
        if (this.socket === socket) this.socket = undefined;
        resolve();
      };

      socket.onmessage = (event) => {
        if (typeof event.data !== "string") return;

        let frame: Record<string, unknown>;
        try {
          frame = JSON.parse(event.data) as Record<string, unknown>;
        } catch {
          // An unreadable frame is ignored. The session is only a shortcut: whatever it drops,
          // the periodic poll picks up.
          return;
        }

        void this.dispatch(socket, frame);
      };
    });
  }

  private async dispatch(socket: WebSocket, frame: Record<string, unknown>): Promise<void> {
    switch (frame.op) {
      case "hello":
        await this.identify(socket, frame);
        return;

      case "ready": {
        // The connection holds: subsequent attempts start again from a short delay.
        this.attempt = 0;

        // The server subscribed us to the groups it knows we belong to. Those we know about and
        // it left out are claimed explicitly — otherwise a conversation created during an outage
        // would stay silent until the next poll.
        const served = new Set((frame.groups as string[] | undefined) ?? []);
        for (const key of this.scope) {
          if (!served.has(key)) this.send({ op: "subscribe", group_id: key });
        }
        for (const key of served) this.scope.add(key);

        this.startHeartbeat();
        return;
      }

      case "envelope":
        this.handlers.onEnvelope(fromHex(frame.group_id as string), frame.seq as number);
        return;

      case "signal":
        this.handlers.onSignal(
          fromHex(frame.group_id as string),
          fromBase64(frame.payload as string),
        );
        return;

      // `heartbeat_ack` and `error` ask for nothing: the server closes the socket when an error
      // is fatal, and the reconnection loop takes over. Reacting to an error reason would mean
      // treating normal operation as a failure.
      default:
    }
  }

  /**
   * Answers the challenge issued by the server.
   *
   * The nonce comes from the server and is valid only once: unlike HTTP authentication, there is
   * **no** window during which a captured signature would stay usable. That is what a session
   * gains in exchange for authenticating only once for its whole lifetime.
   */
  private async identify(socket: WebSocket, hello: Record<string, unknown>): Promise<void> {
    const nonce = fromBase64(hello.nonce as string);

    // The pace is dictated by the server, not chosen here: it is the one that knows after how
    // much silence it closes. Hardcoding it on both sides would make them diverge the first time
    // one of the two changed.
    const announced = hello.heartbeat_ms;
    if (typeof announced === "number" && announced > 0) this.heartbeatMs = announced;

    socket.send(
      JSON.stringify({
        op: "identify",
        device_id: this.api.deviceId,
        nonce: hello.nonce,
        signature: await this.api.signGatewayChallenge(nonce, this.challengeFormat),
        cursors: this.cursors().map((cursor) => ({
          group_id: toHex(cursor.groupId),
          seq: cursor.seq,
        })),
      }),
    );
  }

  /**
   * Beats at the pace announced by the server, halved.
   *
   * The heartbeat is not just a sign of life: it is what triggers the server-side re-check of our
   * memberships. Skipping it would let the session serve groups we have just been removed from.
   */
  private startHeartbeat(): void {
    this.stopHeartbeat();
    // Twice as fast as the announced pace: one beat lost on a network switch must not cost a
    // reconnection, with its challenge and its catch-up.
    this.heartbeat = setInterval(() => this.send({ op: "heartbeat" }), this.heartbeatMs / 2);
  }

  private stopHeartbeat(): void {
    if (this.heartbeat === undefined) return;

    clearInterval(this.heartbeat);
    this.heartbeat = undefined;
  }
}
