/**
 * The passkey factor: a recovery secret held by an authenticator rather than by a memory.
 *
 * # What the PRF extension gives, and why it is the interesting half
 *
 * A passkey on its own authenticates. It does not hand back key material, so it cannot encrypt
 * anything — which is the whole problem for an application whose server must never hold a
 * readable secret. WebAuthn's `prf` extension closes exactly that gap: the authenticator
 * evaluates a pseudo-random function over a caller-chosen salt and returns 32 bytes, stable for
 * a given credential and a given origin, and unobtainable without the authenticator.
 *
 * Those 32 bytes are **uniform**. That is the entire argument for this factor existing beside
 * the password one: an escrow sealed under a full-entropy key cannot be attacked by guessing,
 * so the offline attack that shapes `escrow.ts` simply does not apply to it. Whoever steals the
 * database gets nothing from a passkey escrow, ever.
 *
 * # What it costs, said before it is offered
 *
 * **The authenticator becomes a thing you can lose.** A synced passkey — iCloud Keychain,
 * Google Password Manager, 1Password — survives losing a laptop, because the provider replicates
 * it. A device-bound one does not: it dies with the device, and so does this factor. The
 * application cannot tell which kind the user just created; the platform does not say.
 *
 * **It is bound to the origin.** The PRF output depends on the RP ID, so a passkey created
 * against one deployment is worthless against another. Self-hosting on a second domain means a
 * second passkey, and moving a deployment's domain invalidates every one of them.
 *
 * **It is not available everywhere.** Support is a per-browser, per-authenticator matter and it
 * cannot be established except by asking. Everything here therefore degrades to "no" rather than
 * throwing: the password factor and the twelve-word phrase are what cover the rest.
 *
 * # Why an empty `allowCredentials`
 *
 * A recovering user has no device, hence no stored credential id to allow, and — for the passkey
 * path — has not even typed a handle. A discoverable credential with an empty allowlist puts the
 * choice in the platform's own UI: the user picks their passkey from the operating system, and
 * the application learns which account it belongs to only after the escrow opens.
 */

/**
 * The salt the PRF is evaluated over. Fixed and public: it selects *which* secret this
 * application gets out of the credential, not how hard it is to guess. The entropy is the
 * authenticator's, not the salt's.
 */
const PRF_SALT = new TextEncoder().encode("wac-escrow-prf-v1");

/** Relying-party name shown by the platform's own prompt. */
const RP_NAME = "Whispee";

/**
 * Whether this browser can do the whole of what is needed.
 *
 * Deliberately conservative, and deliberately not a promise: it reports that the API surface
 * exists, which is a necessary condition and not a sufficient one. The authenticator can still
 * decline `prf` at creation time, which is why {@link createPasskeyFactor} checks the extension
 * result rather than trusting this.
 */
export function passkeysAvailable(): boolean {
  return (
    typeof PublicKeyCredential !== "undefined" &&
    typeof navigator !== "undefined" &&
    typeof navigator.credentials?.create === "function"
  );
}

/** What a successful PRF evaluation yields. */
export interface PrfSecret {
  /** Exactly 32 bytes, uniform. */
  secret: Uint8Array;
}

/**
 * `getClientExtensionResults()` is typed as an open bag in the DOM lib, and `prf` is not in it.
 * Narrowed here rather than cast at each use, so the shape assumed is written down once.
 */
interface PrfResults {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
}

function firstResult(credential: PublicKeyCredential): Uint8Array | null {
  const results = credential.getClientExtensionResults() as PrfResults;
  const first = results.prf?.results?.first;
  return first === undefined ? null : new Uint8Array(first);
}

/**
 * Creates a passkey and derives this application's secret from it.
 *
 * # Why the credential is created and then immediately used a second time
 *
 * Several authenticators accept `prf` at creation and return no output there — the specification
 * allows it, and Chrome's platform authenticator did it for a long time. The only reliable way
 * to obtain the value is an assertion, so a creation that reports `enabled` but no `results` is
 * followed by a `get()`. A user sees at most two prompts, once, on the screen that sets this up.
 *
 * Returns `null` when the authenticator will not do PRF at all. That is a refusal to report, not
 * an error to throw: the caller's answer is to offer the password factor instead.
 *
 * `userId` is the account id and nothing else. It is stored by the authenticator and shown in
 * the platform's account picker, so it must not be anything the user would rather not see listed
 * on a shared machine — which is the reason the handle is passed separately as the display name
 * and can be omitted.
 */
export async function createPasskeyFactor(
  accountId: string,
  displayName: string,
): Promise<PrfSecret | null> {
  if (!passkeysAvailable()) return null;

  const credential = (await navigator.credentials.create({
    publicKey: {
      // Not verified by anything: there is no server-side WebAuthn ceremony here. The passkey
      // is used as a key holder, not as an authentication protocol — the account is proven by
      // the seed that comes out of the escrow, which is a stronger statement than an assertion
      // this server could be lied to about. A random challenge is sent because the API requires
      // one, and treating it as meaningful would be the misleading part.
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: RP_NAME },
      user: {
        id: new TextEncoder().encode(accountId),
        name: displayName,
        displayName,
      },
      // ES256 then RS256, the two every authenticator implements. The algorithm is irrelevant
      // to what this is for — no signature is ever verified — but the list is mandatory.
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        // Discoverable, so recovery needs no handle: the platform lists the passkey itself.
        residentKey: "required",
        requireResidentKey: true,
        // Required rather than preferred. Without a user-verification gesture the passkey opens
        // to whoever holds the unlocked device, which for a *recovery* factor means the account
        // travels with the laptop. That is precisely what the local lock exists to prevent.
        userVerification: "required",
      },
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  })) as PublicKeyCredential | null;

  if (credential === null) return null;

  const atCreation = firstResult(credential);
  if (atCreation !== null) return { secret: atCreation };

  const results = credential.getClientExtensionResults() as PrfResults;
  if (results.prf?.enabled !== true) return null;

  // Enabled but not evaluated: ask again through an assertion, restricted to the credential
  // just created so the user is not made to choose among passkeys they did not just make.
  return readPasskeyFactor(new Uint8Array(credential.rawId));
}

/**
 * Evaluates the PRF of an existing passkey.
 *
 * With no `credentialId`, the allowlist is empty and the platform asks the user which passkey to
 * use — the recovery case, where the application knows nothing at all yet.
 *
 * Returns `null` when the user cancels, when no passkey matches, or when the authenticator
 * declines the extension. Those are three different events and this reports one answer on
 * purpose: none of them is actionable differently, and the caller that most wants to tell them
 * apart is a script probing what is on the machine.
 */
export async function readPasskeyFactor(
  credentialId?: Uint8Array,
): Promise<PrfSecret | null> {
  if (!passkeysAvailable()) return null;

  try {
    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials:
          credentialId === undefined
            ? []
            : [{ type: "public-key", id: credentialId as unknown as BufferSource }],
        userVerification: "required",
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    })) as PublicKeyCredential | null;

    if (assertion === null) return null;

    const secret = firstResult(assertion);
    if (secret === null || secret.length !== 32) return null;
    return { secret };
  } catch {
    // A cancelled prompt throws `NotAllowedError`, which is the ordinary outcome of a user
    // changing their mind. Letting it propagate would turn "no thanks" into an error screen.
    return null;
  }
}
