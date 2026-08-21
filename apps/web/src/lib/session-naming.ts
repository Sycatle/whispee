/**
 * What people are called: by themselves, and by this device.
 *
 * # Why this left `Session`
 *
 * Same reason as `session-preferences.ts`, and more urgently. These three fields were written in
 * `composeStored` and read three hundred lines away in `Session.open`, with nothing relating the
 * two halves — and two of them are `Record<handle, …>`, so they are exactly what a change to how
 * an account is keyed has to travel through. A record written under one key and read under
 * another does not fail: it comes back empty. Names simply vanish, and nothing says why.
 *
 * Both directions live here now, next to each other, and a round-trip test can assert they agree.
 *
 * # Three kinds of name, and they do not rank the same
 *
 * `mine` is what this account shows to the people it talks to. `profiles` is what other people
 * declare about themselves — **self-declared, therefore not evidence**: two people can claim the
 * same name, and one of them can pick it precisely because the other has it. `petnames` is what
 * the reader decided to call somebody, and it outranks both on screen, because it is the one
 * string in the chain that no peer and no server can influence.
 *
 * # What stays behind
 *
 * Everything that talks or writes. Announcing a name to a group, persisting, and bumping the
 * per-view revision counter so the change is drawn everywhere the person appears — all of that is
 * `session.ts`, because all of it is ordered against the MLS state or the poll loop. This file
 * decides what a name *is*; it never decides when anyone hears about it.
 *
 * # What it does not solve
 *
 * The identity the records are keyed by. Bringing the two halves together makes a rekey a
 * substitution in one file instead of a hunt through two, and makes the round-trip test fail
 * loudly if a stored state stops being readable. It does not perform the rekey, and it does not
 * decide what happens to a state written under the old key — see `session-codec.ts`, which is the
 * only version gate that exists, and note that it guards the native file only.
 */
import { sanitize, validate } from "./display-name.ts";
import type { StoredSession } from "./storage";

/** What a peer has declared about itself, and when. */
export interface Profile {
  name: string;
  at: number;
}

export class Names {
  private own: string | undefined;
  private declared: Record<string, Profile> = {};
  private given: Record<string, string> = {};

  /**
   * Rebuilds the names a stored session was carrying.
   *
   * `?? {}` for the two records, because a missing record is an empty one and there is no third
   * state. `displayName` is left `undefined` when absent rather than defaulted to a string: the
   * absence is what the display falls back on, and `@handle` — which always exists — is the thing
   * that actually identifies somebody.
   */
  static hydrate(stored: StoredSession | undefined): Names {
    const names = new Names();
    if (!stored) return names;

    names.own = stored.displayName;
    names.declared = stored.profiles ?? {};
    names.given = stored.petnames ?? {};

    return names;
  }

  /**
   * What this contributes to the stored session. The mirror of `hydrate`, and tested against it.
   *
   * Written only when there is something to write, so that an account which never named itself
   * and never received a name keeps the exact on-disk shape it had before these fields existed.
   * That is what makes an unchanged `VERSION` honest rather than merely tolerated.
   */
  snapshot(): Partial<StoredSession> {
    return {
      ...(this.own === undefined ? {} : { displayName: this.own }),
      ...(Object.keys(this.declared).length === 0 ? {} : { profiles: this.declared }),
      ...(Object.keys(this.given).length === 0 ? {} : { petnames: this.given }),
    };
  }

  /** The name this account shows, if it has set one. */
  get mine(): string | undefined {
    return this.own;
  }

  /** What other people declare about themselves. Handed out live, and read-only in practice. */
  get profiles(): Record<string, Profile> {
    return this.declared;
  }

  /** What this device calls other people. Never emitted, and no code path could. */
  get petnames(): Record<string, string> {
    return this.given;
  }

  /**
   * Sets — or clears — the name this account shows.
   *
   * Cleaned before it is judged, because a name is refused for what it means and not for what the
   * keyboard put in it: rejecting "Charlie " for a trailing space the user cannot see would be an
   * error message about nothing. `validate` then answers with a code, and the code is thrown as
   * is — the caller is at the display boundary and knows what language to say it in.
   *
   * An empty result clears the name rather than failing. Announcing the clear is the caller's
   * business, and it must: not doing so would leave the old name standing on every peer's screen
   * for as long as their session lives, which is the one outcome somebody removing their name is
   * trying to avoid.
   */
  setMine(name: string): void {
    this.own = clean(name);
  }

  /**
   * Sets — or clears — the name this device gives somebody else.
   *
   * The counterpart to `setMine`, and its opposite in every way that matters. A display name is
   * asserted by its subject and broadcast; a petname is asserted by the reader and goes nowhere.
   *
   * Cleaned and bounded by the same rules, because it lands in the same slots of the same
   * layouts — a petname that overflowed a bubble author would be a petname that broke a thread.
   *
   * An empty result removes the entry rather than storing an empty string, so that "no petname"
   * has one representation and `naming.ts` has one thing to test for.
   */
  setPetname(handle: string, name: string): void {
    const cleaned = clean(name);

    if (cleaned === undefined) delete this.given[handle];
    else this.given[handle] = cleaned;
  }

  /**
   * Takes in a name a peer declared about itself.
   *
   * `sanitize` runs here rather than where the bytes are decoded: a name from a peer is not less
   * hostile than one typed locally, it is more so — nobody chose those code points by accident.
   *
   * Last writer wins on the **clamped** time, so a peer cannot pin their name by dating it far
   * ahead. Ties keep what is already stored, which makes a replayed message a no-op rather than a
   * flicker. A name that cleans away to nothing removes the entry: the absence is what the display
   * falls back on, and one representation of "no name" is enough.
   *
   * Refused rather than truncated, on the same grounds as the input field: cutting somebody's name
   * to fit would show a name they never chose.
   *
   * Returns whether anything changed, so the caller can decide whether a redraw is owed. It
   * deliberately does not write: this runs inside the poll loop, which persists once the whole
   * page of envelopes has been applied, and it has to be that one write.
   */
  absorb(handle: string, declared: string, at: number): boolean {
    const known = this.declared[handle];
    if (known && known.at >= at) return false;

    const name = sanitize(declared);
    if (name !== "" && validate(name) !== null) return false;

    if (name === "") delete this.declared[handle];
    else this.declared[handle] = { name, at };

    return true;
  }

  /** Drops everything. Called when the local identity is erased. */
  forget(): void {
    this.own = undefined;
    this.declared = {};
    this.given = {};
  }
}

/**
 * Cleans a name and judges it, or reports that there is none.
 *
 * `undefined` rather than `""` for the empty case, so that "no name" has one representation on
 * both sides of this module: absent in the record, absent on disk.
 */
function clean(name: string): string | undefined {
  const cleaned = sanitize(name);
  if (cleaned === "") return undefined;

  const error = validate(cleaned);
  if (error !== null) throw new Error(error);

  return cleaned;
}
