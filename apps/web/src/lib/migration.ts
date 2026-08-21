/**
 * Moving a desktop install over to native storage.
 *
 * # The problem, which has no simple solution
 *
 * An existing install keeps its keys in IndexedDB. They are non-extractable there — that is
 * their whole purpose — so **it cannot move them**. And the server refuses to change the
 * authentication key of an already-registered device (the `auth_key` clause in
 * `register_device`), which closes the last door: this device will never be native.
 *
 * Moving only the MLS state would be pointless. A saved state whose authentication key is gone
 * is unusable: the device can no longer issue a request. The half-measure would look like
 * protection without being one, which is worse than doing nothing.
 *
 * # What we do instead
 *
 * We do not try to save the device: we register a new, native one, attested by the account seed
 * — which is in the session and therefore available. The old one is revoked. This is the
 * existing pairing mechanism applied to oneself, and it needs no new server feature.
 *
 * The price is real and paid once: the MLS identity changes, so groups have to be rejoined and
 * history re-read from the vault.
 *
 * # Hence the prerequisite
 *
 * **No vault, no migration.** History then exists nowhere but in the current device's MLS state,
 * and the new device cannot inherit it: the ratchet destroyed the keys as it went. Migrating
 * without a vault would trade a *possible* eviction for a *certain* loss. The install stays on
 * IndexedDB, which is what it was doing already.
 *
 * # Why the migration state is not remembered
 *
 * It follows from what exists: a web session alone is a migration to do, both together a
 * migration begun, a native session alone a migration finished. A marker would add a third
 * source of truth, which an interruption could put at odds with the other two — precisely in the
 * case where it is being relied on.
 */

/** What is known about a session already kept somewhere, without having opened it. */
export interface Presence {
  handle: string;
  /**
   * Is the vault on?
   *
   * Three values, and the distinction is decisive here: `false` is an explicit refusal that
   * forbids migration, `undefined` is the absence of a decision, hence the default, hence on.
   * Confusing them would refuse to migrate every account predating the flag.
   */
  vaultEnabled?: boolean;
}

export type Decision =
  /** Nothing kept: the install is new, it starts natively with nothing to migrate. */
  | { kind: "fresh" }
  /** Migration finished, or install already native. */
  | { kind: "native" }
  /** To do, from the start. */
  | { kind: "start"; handle: string }
  /**
   * Begun, then interrupted.
   *
   * This is not a degraded state: the account simply has two devices, which it is entitled to.
   * Resuming means finishing the propagation and then revoking the old one.
   */
  | { kind: "resume"; handle: string }
  /**
   * We stay on IndexedDB, and we say why.
   *
   * `reason` is meant for the user: a migration silently abandoned would suggest a protection
   * that does not exist.
   */
  | { kind: "fallback"; reason: string };

const NO_VAULT =
  "History backup is turned off: migrating to app storage would permanently lose your " +
  "conversations, which the new device could not re-read anywhere. The app keeps working as " +
  "before.";

const CONFLICT =
  "App storage already holds another account's session. No migration is attempted: overwriting " +
  "it would destroy an identity the server still knows about and that nothing could prove any more.";

/**
 * What to do at startup, under Tauri.
 *
 * A pure function: it looks only at what exists, and that is what makes it verifiable. All the
 * difficulty of the migration is in this table of cases, not in the network calls.
 */
export function decide(web: Presence | undefined, native: Presence | undefined): Decision {
  if (web === undefined) {
    return native === undefined ? { kind: "fresh" } : { kind: "native" };
  }

  if (native === undefined) {
    // The refusal is checked before anything else: it is the only case where migrating would be
    // destructive.
    if (web.vaultEnabled === false) return { kind: "fallback", reason: NO_VAULT };
    return { kind: "start", handle: web.handle };
  }

  // Two sessions from different accounts are not a half-finished migration. Getting this wrong
  // would overwrite an identity the server still knows about and that nothing could prove.
  if (native.handle !== web.handle) return { kind: "fallback", reason: CONFLICT };

  return { kind: "resume", handle: web.handle };
}

/**
 * The steps, as `session.ts` knows how to run them.
 *
 * Isolated behind an interface so that the sequence — the only place an interruption can do
 * damage — is testable without a server, without MLS and without a webview.
 */
export interface Steps {
  /**
   * Registers a new native device, attested by the account seed, and stores its session.
   *
   * Called only if no native session exists. The server declines a name on collision, so a
   * second call would create one more device instead of failing — which is why idempotence is
   * carried by the decision, not by this function.
   */
  registerNativeDevice(): Promise<string>;

  /**
   * Has the old device add the new one to every conversation.
   *
   * This is `propagateOwnDevices`, already idempotent and already called on every poll: MLS does
   * not catch up a member missing from the tree, so the operation is designed to be repeated.
   */
  propagateFromOld(): Promise<void>;

  /** How many conversations the new device has joined, out of how many the old one has. */
  progress(): Promise<{ joined: number; expected: number }>;

  /** Re-reads the archived history, conversation by conversation. */
  restoreHistory(): Promise<void>;

  /**
   * Revokes the old device, from the new one.
   *
   * In that direction and not the other: a device does not revoke itself, and above all the
   * revocation must be the **last** act before erasure. Doing it earlier would cut the old
   * device off from the groups before it had finished introducing the new one there.
   */
  revokeOld(old: string): Promise<void>;

  /** Erases the web session. The only irreversible act, and therefore the last one. */
  forgetWeb(): Promise<void>;

  /** Reports progress to the interface: the migration takes several round trips. */
  onProgress?(step: string): void;
}

/**
 * How many waiting rounds before giving up on propagation.
 *
 * Giving up leaves two active devices — a healthy state, merely redundant — and the next startup
 * picks up from there. Waiting forever, on the other hand, would block the app on a silent
 * server.
 */
const MAX_ROUNDS = 20;

/** Signals that propagation did not complete in the time allowed. */
export class PropagationIncomplete extends Error {
  constructor(joined: number, expected: number) {
    super(
      `Migration unfinished: ${joined} of ${expected} conversation(s) joined. ` +
        "It will resume on the next start; both devices stay active until then.",
    );
    this.name = "PropagationIncomplete";
  }
}

/**
 * Runs the migration, or resumes it.
 *
 * The order is not negotiable, and every step tolerates being replayed: an interruption leaves
 * the account with two active devices, which works, and the next startup picks up where this one
 * stopped.
 *
 * `wait` is injected so tests do not actually wait.
 */
export async function migrate(
  decision: Decision,
  steps: Steps,
  old: string,
  wait: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
): Promise<void> {
  if (decision.kind !== "start" && decision.kind !== "resume") return;

  const say = (step: string) => steps.onProgress?.(step);

  if (decision.kind === "start") {
    say("Registering the device…");
    await steps.registerNativeDevice();
  }

  say("Transferring conversations…");
  await steps.propagateFromOld();

  // Propagation is asynchronous end to end: the old device posts commits, the new one has to
  // pick them up. We wait for the result rather than the act — otherwise we would revoke the old
  // device before the new one was really in the groups, and the conversations would become
  // unreachable from this side.
  for (let round = 0; ; round += 1) {
    const { joined, expected } = await steps.progress();
    if (joined >= expected) break;

    if (round >= MAX_ROUNDS) throw new PropagationIncomplete(joined, expected);

    await wait(1500);
    await steps.propagateFromOld();
  }

  say("Restoring history…");
  await steps.restoreHistory();

  say("Removing the old device…");
  await steps.revokeOld(old);

  // Last, and only last: as long as the web session exists, everything above can be replayed.
  // Once erased, nothing can be.
  await steps.forgetWeb();
}
