/**
 * Client-side verification of the auditable key log.
 *
 * # The hole this module closes
 *
 * Attestations stop the server from **adding** a device to an account. They do not stop it from
 * lying about the account key **on first contact**: when you ask for someone's account for the
 * first time, you have nothing to compare against. The server can serve its own key and relay in
 * the clear between two perfectly encrypted sessions.
 *
 * An inclusion proof in an append-only Merkle tree cannot be forged. The server has to publish the
 * key it serves, and it can no longer take it back afterwards.
 *
 * # The three checks, and why three are needed
 *
 * 1. **Head signature** — it really does come from the log.
 * 2. **Inclusion** — the key I am served is the log's, not another one.
 * 3. **Consistency** — today's log extends the one I saw yesterday.
 *
 * Without the third, the server replaces an already published key and serves a log that is just as
 * consistent: the first two pass, and the log no longer proves anything about the past.
 *
 * # What none of the three catches
 *
 * A server that keeps **two logs** and serves one to each side. Each victim sees a signed,
 * consistent log in which their own view is perfect. Only comparing heads between clients — the
 * gossip, inside encrypted messages the server can neither read nor forge — reveals the fork. See
 * `Session.gossip`.
 */
import type { Api, SignedHead } from "./api";
import type { Crypto } from "./wasm";

/** The last accepted head, kept from one session to the next. */
export interface SeenHead {
  size: number;
  root: Uint8Array;
  logKey: Uint8Array;
}

export type Verdict =
  | { ok: true }
  /**
   * The server failed to prove what it claims. This is not a network error to retry: it is the
   * signal the whole mechanism exists to produce.
   */
  | { ok: false; reason: string };

/**
 * Verifies the signature of a head served by the server.
 *
 * The log's public key is itself served by the server — an accepted stopgap, see the `SignedHead`
 * comment on the server side. What we do refuse is for it to **change** along the way: a log that
 * starts signing with another key is another log.
 */
export function acceptHead(
  crypto: Crypto,
  head: SignedHead,
  seen: SeenHead | undefined,
  /**
   * The log key this build was compiled against, if it was compiled against one.
   *
   * This is the only check here that works on **first contact**. Everything else compares the
   * server against its own past: with no anchor and no pin, a client meeting a hostile server for
   * the first time has nothing to hold it to, and the server can sign a log of its own invention
   * with a key of its own choosing. A key that shipped with the application did not come from it.
   *
   * Passed in rather than read from the environment here, so this module stays testable without a
   * bundler. See `pinning.ts` for where the value comes from and what it is worth on each target.
   */
  pinned?: Uint8Array,
): Verdict {
  if (pinned && !equal(pinned, head.logKey)) {
    return {
      ok: false,
      reason: "the log is signed by a key this application was not built to trust.",
    };
  }

  if (seen && !equal(seen.logKey, head.logKey)) {
    return { ok: false, reason: "the log key changed: this is no longer the same log." };
  }

  const valid = crypto.verifyTreeHead(
    head.logKey,
    BigInt(head.size),
    head.root,
    BigInt(head.timestamp),
    head.signature,
  );

  if (!valid) return { ok: false, reason: "badly signed log head." };

  // A log does not shrink. A head smaller than the last one seen is either a replay or an
  // amputation — both deserve the same refusal.
  if (seen && head.size < seen.size) {
    return { ok: false, reason: "the log shrank: entries have disappeared." };
  }

  return { ok: true };
}

/**
 * Verifies that an account key appears in the log, and that the log extends what we already knew.
 *
 * Returns the new head to remember on success. On failure **nothing is remembered**: accepting a
 * head we have just refused would amount to endorsing it.
 */
export async function verifyAccount(
  api: Api,
  crypto: Crypto,
  handle: string,
  identityKey: Uint8Array,
  seen: SeenHead | undefined,
  pinned?: Uint8Array,
): Promise<{ verdict: Verdict; head?: SeenHead }> {
  const proof = await api.logProof(handle);

  const head = acceptHead(crypto, proof.head, seen, pinned);
  if (!head.ok) return { verdict: head };

  // The leaf is **recomputed** from the handle and the key we are served. Using the server's would
  // amount to letting it prove its claims with its claims.
  const leaf = crypto.logLeaf(handle, identityKey);

  if (
    !crypto.verifyInclusion(leaf, proof.index, proof.head.size, proof.proof, proof.head.root)
  ) {
    return {
      verdict: {
        ok: false,
        reason: `the key served for @${handle} does not appear in the log.`,
      },
    };
  }

  if (!equal(identityKey, proof.identityKey)) {
    return {
      verdict: {
        ok: false,
        reason: `the log publishes a different key for @${handle} than the one we are served.`,
      },
    };
  }

  if (seen) {
    const consistency = await verifyExtends(api, crypto, seen, proof.head);
    if (!consistency.ok) return { verdict: consistency };
  }

  return {
    verdict: { ok: true },
    head: { size: proof.head.size, root: proof.head.root, logKey: proof.head.logKey },
  };
}

/**
 * Verifies that the current log extends a given head.
 *
 * Serves two uses that are really one: our own previous head, and **the one a correspondent handed
 * us**. In the second case, this is what detects a server keeping two logs — it cannot prove that
 * ours extends a view it never served.
 */
export async function verifyExtends(
  api: Api,
  crypto: Crypto,
  anchor: SeenHead,
  current: SignedHead,
): Promise<Verdict> {
  if (anchor.size > current.size) {
    return { ok: false, reason: "the log is shorter than the reference view." };
  }

  const { proof } = await api.logConsistency(anchor.size);

  if (
    !crypto.verifyConsistency(anchor.size, anchor.root, current.size, current.root, proof)
  ) {
    return {
      ok: false,
      reason: "the log does not extend the reference view: keys have been rewritten.",
    };
  }

  return { ok: true };
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
