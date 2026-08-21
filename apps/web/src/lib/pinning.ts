/**
 * What this build was compiled to trust.
 *
 * # The hole this closes, and only on one target
 *
 * The transparency log's public key is served by the very server the log exists to watch. Every
 * other check is the server against its own past: a consistency proof needs an anchor, and a
 * changed key is only detectable against a key seen before. On a **first** contact with a hostile
 * server there is nothing to compare against, and it can sign a log of its own invention.
 *
 * A key compiled into the application did not come from the server. `docs/THREAT-MODEL.md` has
 * listed this as a limitation from the beginning — "it should ship with the application" — and
 * this is that.
 *
 * # Where it actually closes it
 *
 * In the **desktop binary**, whose interface is packaged inside a signed, reproducible artefact.
 * There, "compiled in" means something the server cannot reach.
 *
 * On the **web** it is worth much less, and pretending otherwise would be the dishonest part: the
 * server ships this JavaScript on every load, so it ships the pin too, and a server willing to
 * serve a forged log is willing to serve a build that trusts it. What it still buys there is not
 * nothing — a pin that disagrees with the served key is a mismatch the operator has to notice, so
 * it turns a silent substitution into one that breaks every deployed client at once — but it is
 * not a defence against the party that builds the bundle.
 *
 * # Why it is optional
 *
 * A self-hosted deployment generates its own log key on first boot, and there is no key to
 * compile in until it has. An unset pin therefore leaves behaviour exactly as it was, which is
 * the same rule the push waker follows: a deployment that has configured nothing stays fully
 * functional.
 */
import { fromBase64 } from "./keys";

/**
 * The pinned key, or `undefined` when this build was compiled without one.
 *
 * Read once. A malformed value is a build-time mistake and it is loud: refusing to start beats
 * running with a pin that silently checks nothing, which is the failure this whole module exists
 * to avoid — a check that looks present and is not.
 */
export const PINNED_LOG_KEY: Uint8Array | undefined = readPin();

function readPin(): Uint8Array | undefined {
  const raw = import.meta.env.VITE_LOG_PUBKEY;
  if (typeof raw !== "string" || raw === "") return undefined;

  const key = fromBase64(raw);
  if (key.length !== 32) {
    throw new Error(
      `VITE_LOG_PUBKEY must be 32 bytes of base64 Ed25519 public key, got ${key.length}`,
    );
  }
  return key;
}
