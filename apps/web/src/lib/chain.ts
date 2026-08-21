/**
 * Reading an account's rotation chain, and deciding whether to believe it.
 *
 * # What this answers
 *
 * "The server says account `a1b2…` currently uses this key. Is that the same account it was
 * yesterday, and is it the account that id names at all?"
 *
 * Three checks, all local, none of which requires the server to be honest:
 *
 * 1. **The anchor.** The first key in the chain fingerprints to the account id. This is what
 *    makes an id self-authenticating rather than something the directory asserts — a server
 *    substituting an account's whole chain would have to produce a first key hashing to an id it
 *    does not control.
 * 2. **The links.** Each later key is signed by the key before it, over `wac-rotate-v2`. That is
 *    what proves a rotation was the account's own doing rather than the server's.
 * 3. **The tree.** Each entry is in the transparency log, via the inclusion proof — checked
 *    elsewhere, by `lib/transparency.ts`, and deliberately not here.
 *
 * # Withholding stays possible, and stays visible
 *
 * The server cannot forge a link: it holds no account key. It can drop one, and that is what
 * makes a chain fail check 2 rather than quietly appear shorter — the reported failure names the
 * position, so a caller can say "the chain has a hole at 3" instead of "something is wrong".
 *
 * # Why the verification is not written here
 *
 * `verifyRotation` crosses the wasm boundary. The signed message has a canonical format — a
 * domain label and length-prefixed fields — held once in the `attest` crate, and a second
 * implementation of it in TypeScript is a second thing that can drift by a byte. When it drifts,
 * every chain looks broken, which reads as "the server is lying".
 */

/** One published key of an account, as the server serves it. */
export interface Link {
  seq: number;
  identityKey: Uint8Array;
  /** Absent on the genesis entry, which has no predecessor to be authorised by. */
  rotation?: Uint8Array;
  rotatedAt?: number;
}

/** What a chain turned out to be. */
export type Verdict =
  | { readonly ok: true; readonly current: Uint8Array }
  /** The chain was empty: the server claims an account with no published key, which is not a state. */
  | { readonly ok: false; readonly why: "empty" }
  /** The first key does not fingerprint to the id. This chain belongs to a different account. */
  | { readonly ok: false; readonly why: "wrong-anchor" }
  /** A link is missing its signature, or the signature does not verify. `at` is its position. */
  | { readonly ok: false; readonly why: "broken-link"; readonly at: number };

/** The two things this needs from the wasm module, as a structural type so a test can fake them. */
export interface Verifier {
  accountId(identityKey: Uint8Array): string;
  verifyRotation(
    previousIdentityKey: Uint8Array,
    account: string,
    newIdentityKey: Uint8Array,
    rotatedAt: bigint,
    rotation: Uint8Array,
  ): boolean;
}

/**
 * Walks a chain and returns the key the account may currently be believed to use.
 *
 * The failure cases are separate values rather than one boolean, because they mean different
 * things to whoever is looking: a wrong anchor is the server pointing at somebody else, a broken
 * link is the server hiding a step, and an empty chain is the server answering about an account
 * that does not exist. Collapsing them would leave an interface saying "could not verify", which
 * is the sentence people learn to ignore.
 */
export function walk(account: string, links: readonly Link[], verifier: Verifier): Verdict {
  const first = links[0];
  if (first === undefined) return { ok: false, why: "empty" };

  // The anchor. Checked before anything else: if this fails, the rest of the chain is a
  // well-formed answer about a different account, and verifying its links would produce a
  // confident yes about the wrong person.
  if (verifier.accountId(first.identityKey) !== account) return { ok: false, why: "wrong-anchor" };

  let previous = first.identityKey;

  for (let at = 1; at < links.length; at += 1) {
    const link = links[at]!;
    if (link.rotation === undefined || link.rotatedAt === undefined) {
      return { ok: false, why: "broken-link", at };
    }

    const signed = verifier.verifyRotation(
      previous,
      account,
      link.identityKey,
      BigInt(link.rotatedAt),
      link.rotation,
    );
    if (!signed) return { ok: false, why: "broken-link", at };

    previous = link.identityKey;
  }

  return { ok: true, current: previous };
}

/**
 * Whether a string is shaped like an account id: thirty-two lowercase hexadecimal characters.
 *
 * Shape only. It says nothing about whether such an account exists, and nothing about whether
 * the id matches the key it is presented with — `walk` answers the second, and only the server
 * can answer the first. This exists so a malformed id is refused at a boundary rather than
 * becoming a record key nobody can ever match.
 *
 * Duplicated from `attest::is_account_id` rather than crossing the wasm boundary, and the reason
 * is where it is used: `Session.open` calls it **before** the crypto module has loaded, to decide
 * whether the stored state is from before accounts had ids. A check that needed wasm could not
 * run at the one moment it is needed.
 */
export function isAccountId(value: string): boolean {
  return /^[0-9a-f]{32}$/.test(value);
}
