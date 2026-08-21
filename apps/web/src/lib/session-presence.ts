/**
 * Who was last seen when.
 *
 * # Why this left `Session`
 *
 * Because it is the one piece of session state that `persist` never touches. `session.ts` said so
 * in prose already — "**never persisted** […] it comes back on its own at the first poll" — and a
 * field the writer does not know about is a field that can leave without the writer changing.
 *
 * What it buys is the same thing every extraction here buys: a unit `node --test` can interrogate.
 * The rules worth checking are small and easy to get wrong — that the server's clock is kept and
 * not the browser's, that seconds become milliseconds on the way in, that turning the setting off
 * empties the map rather than merely stopping the refresh — and none of them could be checked at
 * all while they lived on a class that needs WASM to exist.
 *
 * # What stays behind
 *
 * The decisions, all of them. **When** to refresh — inside the existing thirty-second poll rather
 * than on a timer of its own, which would hand the server back the second-by-second activity log
 * the stream had taken away from it, for one coloured dot. **Whether** to refresh, which is the
 * user's setting. And **who** to ask about, which means reading `conversations`, and this file
 * does not know what a conversation is. It is given a list of handles.
 *
 * # What it does not solve
 *
 * The register itself. Presence is the one cross-conversation fact the server keeps about an
 * account, and moving the client's copy of it into its own file changes nothing about that —
 * `docs/THREAT-MODEL.md` §2.2.1 argues the bounds, and the only thing that actually stops the
 * recording is the opt-out reaching the server.
 */

/**
 * What this needs from the delivery service, and nothing more.
 *
 * A structural type rather than `Api`, so a test can hand it a recorded answer and so this file
 * cannot reach for a route it was not given. Seconds, as the server sends them.
 */
export interface PresenceSource {
  presence(accounts: string[]): Promise<{
    now: number;
    accounts: { account: string; last_seen: number }[];
  }>;
}

/**
 * How many accounts one request may ask about.
 *
 * The server's cap. Beyond it we poll the first ones: a visible limit beats a silent 400, and an
 * address book that size would need a different split anyway.
 */
const MAX_PER_REQUEST = 64;

/** Seconds on the wire, milliseconds everywhere above it. */
const MS = 1000;

export class PresenceTracker {
  /**
   * Last known activity of each peer, in milliseconds.
   *
   * Never persisted, for the same reason as receipts and typing indicators: presence restored
   * across sessions would show as online someone nobody has seen since.
   */
  private seen = new Map<string, number>();

  /**
   * Server clock at the last poll.
   *
   * Kept because freshness is judged by comparing two timestamps, and the browser's can be
   * anything at all.
   */
  private now = 0;

  /** Last activity of an account, or `undefined` if the server has nothing to say about it. */
  lastSeen(account: string): number | undefined {
    return this.seen.get(account);
  }

  /** Server clock at the last poll: the reference for judging freshness. */
  get clock(): number {
    return this.now;
  }

  /**
   * Asks about a batch of accounts and replaces what is known.
   *
   * Replaces rather than merges: an account the server stopped answering about has opted out, and
   * merging would leave its last known position on screen for good — the one state the setting
   * exists to remove.
   */
  async refresh(source: PresenceSource, of: string[]): Promise<void> {
    if (of.length === 0) return;

    const { now, accounts } = await source.presence(of.slice(0, MAX_PER_REQUEST));

    this.now = now * MS;
    this.seen = new Map(accounts.map((entry) => [entry.account, entry.last_seen * MS]));
  }

  /**
   * Forgets everything.
   *
   * Called when the user turns presence off: what the server has just erased must not stay on
   * screen until the next poll.
   */
  clear(): void {
    this.seen = new Map();
  }
}
