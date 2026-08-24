/**
 * Recovery escrow: getting back in with no device left.
 *
 * # The thing to understand before reading the code
 *
 * Until this existed, the twelve-word phrase was the only way back and the server had **never
 * held the account seed in any form**. A stolen database gave an attacker unreadable envelopes
 * and public keys, and no path to an account.
 *
 * Enabling an escrow changes that, permanently and by design. The seed is sealed under a key
 * derived from a password and handed to the server. Whoever obtains that ciphertext can attack
 * the password offline: the operator, a database dump, a backup. Argon2id at 256 MiB makes each
 * attempt expensive; it does not make a guessable password safe. And because the history vault's
 * key comes from the same seed, winning that attack opens every archived message too.
 *
 * That is why nothing here happens unless the user asked for it, why the screen that offers it
 * says all of the above before the field, and why `ESCROW_POLICY` in `password.ts` is stricter
 * than the local lock's floor.
 *
 * The passkey factor does not carry this cost — its key is 32 uniform bytes from an
 * authenticator, so there is nothing to guess. See `passkey.ts` for what it costs instead.
 *
 * # How the blob is found without making it downloadable
 *
 * The recovery route cannot be authenticated: the caller has lost every device, which is the
 * situation being answered. Indexing escrows by handle would therefore publish everybody's
 * ciphertext to everybody.
 *
 * So one expensive derivation produces two keys — one names the row, the other opens it — and
 * the server only ever sees a hash of the first. Asking for a blob already requires knowing the
 * password. The server answers 404 both to a wrong guess and to an account with no escrow,
 * because it genuinely cannot tell them apart.
 *
 * The consequence, stated rather than discovered: a failed attempt names no account, so nothing
 * can be locked after N tries. The bound is a per-address rate limit and only that.
 */
import { Api, type RecoveryKind } from "./api";
import { createPasskeyFactor, readPasskeyFactor } from "./passkey";
import { loadCrypto, type RecoveryFactor } from "./wasm";

/** A factor and the parameters it was derived under, ready to seal or to open. */
interface Derived {
  factor: RecoveryFactor;
  params: Uint8Array;
}

/**
 * Stretches a password into its two keys.
 *
 * **This blocks the calling thread** — Argon2id, 256 MiB, four passes. Measured at 1.1 s in this
 * WebAssembly build on a desktop, and several times that on a phone. The caller owns showing
 * that something is happening; there is no way to make it cheap, and a cheap version would be
 * the defect rather than an optimisation.
 */
async function derivePassword(handle: string, password: string): Promise<Derived> {
  const crypto = await loadCrypto();
  const params = crypto.escrowParams("password");
  return { factor: crypto.derivePasswordFactor(handle, password, params), params };
}

async function derivePrf(secret: Uint8Array): Promise<Derived> {
  const crypto = await loadCrypto();
  return { factor: crypto.derivePrfFactor(secret), params: crypto.escrowParams("passkey") };
}

async function deposit(
  api: Api,
  kind: RecoveryKind,
  derived: Derived,
  accountId: string,
  seed: Uint8Array,
): Promise<void> {
  const crypto = await loadCrypto();
  const sealed = crypto.sealEscrow(seed, derived.factor, accountId, kind, derived.params);

  await api.setRecovery({
    kind,
    lookup: derived.factor.lookupId(),
    params: derived.params,
    sealed,
  });
}

/**
 * Seals the account seed under a password and deposits it.
 *
 * The handle is the Argon2id salt, so it must be the one the account currently answers to. A
 * rename therefore breaks this escrow beyond repair — the owner's own password would produce a
 * different lookup — which is why `Session.renameHandle` deletes it rather than leaving a row
 * nobody can open and everybody can grind. Re-sealing there is impossible: it needs the password.
 * See the module header in `crates/crypto-core/src/escrow.rs` for why the salt cannot be random.
 */
export async function enablePasswordRecovery(
  api: Api,
  accountId: string,
  handle: string,
  password: string,
  seed: Uint8Array,
): Promise<void> {
  await deposit(api, "password", await derivePassword(handle, password), accountId, seed);
}

/**
 * Creates a passkey, derives its secret, and deposits the escrow.
 *
 * Returns `false` when the authenticator will not do PRF, which is a normal answer on plenty of
 * machines and not an error: the caller offers the password factor instead.
 */
export async function enablePasskeyRecovery(
  api: Api,
  accountId: string,
  handle: string,
  seed: Uint8Array,
): Promise<boolean> {
  const prf = await createPasskeyFactor(accountId, handle);
  if (prf === null) return false;

  await deposit(api, "passkey", await derivePrf(prf.secret), accountId, seed);
  return true;
}

/** Why a recovery attempt did not produce a seed. */
export type RecoveryFailure =
  /**
   * No escrow answered that secret.
   *
   * Reported for a wrong password **and** for an account that never enabled recovery, because
   * the server returns the same 404 to both and cannot do otherwise. Copy shown for this must
   * not claim to know which it was.
   */
  | "unknown"
  /** The server answered, and the ciphertext did not open under the derived key. */
  | "tampered"
  /** The user cancelled the platform prompt, or no passkey does PRF here. */
  | "cancelled"
  /** Too many attempts from this address, recently. */
  | "throttled";

export type RecoveryResult =
  | { ok: true; accountId: string; handle: string | null; seed: Uint8Array }
  | { ok: false; reason: RecoveryFailure };

async function claim(derived: Derived, expected: RecoveryKind): Promise<RecoveryResult> {
  let claimed;
  try {
    claimed = await Api.claimRecovery(derived.factor.lookupId());
  } catch (error) {
    if (error instanceof Error && "status" in error && error.status === 429) {
      return { ok: false, reason: "throttled" };
    }
    throw error;
  }

  if (claimed === null) return { ok: false, reason: "unknown" };

  // The kind is checked here as well as inside the seal's AAD. Belt and braces on purpose: the
  // AAD makes a substitution fail to decrypt, and this makes it fail without spending a second
  // of Argon2id on a blob that was never going to open.
  if (claimed.kind !== expected) return { ok: false, reason: "tampered" };

  const crypto = await loadCrypto();
  try {
    // The parameters come from the server. They are inside the AAD, and the Rust side refuses
    // anything below its own floor, so a server that lies about them produces a clean failure
    // rather than a cheaper derivation.
    const seed = crypto.openEscrow(
      claimed.sealed,
      derived.factor,
      claimed.account,
      claimed.kind,
      claimed.params,
    );
    return { ok: true, accountId: claimed.account, handle: claimed.handle, seed };
  } catch {
    // A wrong password cannot reach here — it produces a different lookup, hence a 404 above.
    // What reaches here is a blob that was served under the right lookup and did not open:
    // corruption, or a server substituting one account's ciphertext for another's.
    return { ok: false, reason: "tampered" };
  }
}

/**
 * Recovers the account seed from a handle and a password.
 *
 * **Blocks before the network call**, not after it: the lookup value *is* the output of the
 * derivation, so there is nothing to ask the server until Argon2id has finished. A wrong password
 * therefore costs exactly what a right one does, which is part of what makes the 404
 * uninformative — there is no timing to read either.
 */
export async function recoverWithPassword(
  handle: string,
  password: string,
): Promise<RecoveryResult> {
  return claim(await derivePassword(handle, password), "password");
}

/**
 * Recovers the account seed from a passkey.
 *
 * No handle is asked for: the credential is discoverable, so the platform lists the passkeys it
 * holds and the account id arrives with the escrow.
 */
export async function recoverWithPasskey(): Promise<RecoveryResult> {
  const prf = await readPasskeyFactor();
  if (prf === null) return { ok: false, reason: "cancelled" };

  return claim(await derivePrf(prf.secret), "passkey");
}
