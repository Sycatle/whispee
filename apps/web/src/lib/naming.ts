/**
 * What to call somebody on screen.
 *
 * # Why one module and not thirty call sites
 *
 * Before this file, every place that showed a person wrote `@{handle}` by hand — the rail, the
 * conversation header, the bubbles, the detail panel, the group screen, the verification
 * banners, the notification body. That was correct while a handle was the only string a person
 * had. It stops being correct the moment a display name exists, because the rules below are not
 * the kind of thing thirty independent expressions get right thirty times.
 *
 * So the `@` lives here, and callers reach it through `formatHandle`. Three places still write it
 * literally, and each is a decision rather than an oversight: `Verification.tsx`, whose banners
 * name the handle on purpose (see below); the handle suggestion in `Onboarding.tsx`, which offers
 * a handle rather than naming a person; and the error strings in `session.ts`, which are thrown
 * from pure modules that must not import a display rule.
 *
 * # The order, and why it is that order
 *
 * A petname wins, then a self-asserted display name, then the handle. The petname is the only
 * one of the three the reader chose themselves, so it is the only one an attacker cannot touch.
 * The display name arrives over MLS from the person it describes: it is authentic in the narrow
 * sense that the group knows which member sent it, and worth exactly nothing beyond that —
 * anybody can call themselves Charlie.
 *
 * That is why **the handle is never replaced, only moved into second position**. The anchor stays
 * on screen. A display name is a convenience laid over an identity, never a substitute for it.
 *
 * # The compact form is where the impersonation actually lives
 *
 * Two places have no room for a second line: the author of a bubble in a group thread, and a
 * notification. Those are also the two places a reader glances at without deliberation, which
 * makes them the natural target. `compactNameOf` therefore refuses to be ambiguous: if two people
 * in the same conversation would render identically, or if somebody's self-asserted name is
 * somebody else's handle, everybody involved falls back to their handle. A name that cannot be
 * trusted to identify is not shown where it would be the only thing shown.
 *
 * A petname collision does not trigger that fallback. If the reader gave two people the same
 * petname, the ambiguity is their own and not an attack, and overriding their choice would be
 * the wrong kind of paternalism.
 *
 * # What this does not solve
 *
 * The collision check compares folded strings, so it catches `Charlie` against `charlie ` and
 * misses `Charlle` against `Charlie`. Typographic near-collisions are not a problem string
 * comparison can solve, and pretending otherwise would be worse than leaving it stated: the
 * defence against a convincing lookalike is the handle underneath and, past that, the
 * fingerprint.
 *
 * It has no place in a security banner, and is not used in one. `Verification.tsx` names the
 * handle and nothing else: "Charlie's fingerprint has changed" is weaker than
 * "@charlie8295's fingerprint has changed" precisely because Charlie is the string an impersonator
 * controls. A warning is the last surface that should adopt the friendlier name.
 *
 * It also does nothing about a display name that impersonates a person who is **not** in the
 * conversation. `among` is the only set this module can see, and widening it to every account
 * ever heard of would make the rendering of one thread depend on unrelated threads.
 */

/** The two records `Session` holds, narrowed to what naming needs. */
export interface NameSources {
  /**
   * The handle each account claims for itself, keyed by account id.
   *
   * Arrives over MLS, never from the server's directory — see `TYPE_HANDLE` in `lib/content.ts`
   * for why that distinction is the whole point. Optional because an account we have not heard
   * from yet has none, and `handleOf` falls back to the short id rather than inventing one.
   */
  readonly handles?: Readonly<Record<string, string>>;
  /** Locally chosen nicknames, keyed by handle. Never leaves the device. */
  readonly petnames: Readonly<Record<string, string>>;
  /** Names people asserted about themselves over MLS, keyed by handle. */
  readonly profiles: Readonly<Record<string, { readonly name: string }>>;
}

export interface Name {
  /** The line to show. */
  readonly primary: string;
  /** The handle, when `primary` is not already it. Never omit this in a layout that has room. */
  readonly secondary: string | null;
  /** True when `primary` is the handle, so callers can style an unnamed person differently. */
  readonly isHandle: boolean;
}

/**
 * The one place the `@` sigil is written.
 *
 * It is a display convention, not part of the handle: the stored string, the MLS credential and
 * the device id prefix all carry `charlie8295`, never `@charlie8295`.
 */
export function formatHandle(handle: string): string {
  return `@${handle}`;
}

/**
 * What to print for an account: the handle it claims, or a short form of its id.
 *
 * # Why there is a fallback at all
 *
 * The handle no longer travels in the MLS credential — the credential names the account, and an
 * account is a key. So there is a real window in which a member of a room is known by id and
 * nothing else: before their first claim arrives, or if it never does. Printing nothing would
 * leave a blank where a person is; printing the whole id would put thirty-two hexadecimal
 * characters in a line of prose.
 *
 * So the fallback is the first 64 bits, grouped in fours, matching `attest::short_id`. It is
 * legible, it is comparable at a glance, and it is honest about being an identifier rather than
 * a name.
 *
 * # What 64 bits is worth, stated where somebody will read it
 *
 * A truncated fingerprint is grindable: an attacker generates account keys until the leading
 * characters of theirs match their target's. At 32 bits that is minutes; at 64 it is out of reach
 * of anybody attacking a chat handle. The full 128 bits live in the verification panel, and that
 * panel — not this string — is the proof. See `crates/attest/src/lib.rs::ID_SHORT_HEX_LEN`.
 */
export function handleOf(account: string, sources: NameSources): string {
  const claimed = sources.handles?.[account];
  if (claimed) return formatHandle(claimed);

  // Not an id either — a caller passing something else gets it back with the sigil, which is what
  // every pre-existing call site did and is still the least surprising answer.
  if (!/^[0-9a-f]{32}$/.test(account)) return formatHandle(account);

  return (account.slice(0, 16).match(/.{4}/g) ?? []).join(" ");
}

/**
 * Folds a name for comparison only.
 *
 * Lowercased and whitespace-collapsed, because `Charlie` and `charlie ` are the same claim as far
 * as a reader glancing at a bubble is concerned. The folded form is never displayed — it exists
 * so that two claims can be recognised as one.
 */
function fold(name: string): string {
  return name.trim().replace(/\s+/g, " ").toLowerCase();
}

/** The name somebody asserted about themselves, or null when they asserted nothing usable. */
function assertedName(handle: string, sources: NameSources): string | null {
  const asserted = sources.profiles[handle]?.name?.trim();
  return asserted ? asserted : null;
}

/**
 * The full two-line form, for anywhere with room for both.
 *
 * No ambiguity check here on purpose: this form always shows the handle, so a duplicate display
 * name is visible as a duplicate rather than passing for the wrong person.
 */
export function nameOf(handle: string, sources: NameSources): Name {
  const petname = sources.petnames[handle]?.trim();
  if (petname) {
    return { primary: petname, secondary: handleOf(handle, sources), isHandle: false };
  }

  const asserted = assertedName(handle, sources);
  if (asserted) {
    return { primary: asserted, secondary: handleOf(handle, sources), isHandle: false };
  }

  return { primary: handleOf(handle, sources), secondary: null, isHandle: true };
}

/**
 * The single-line form, for a bubble author or a notification.
 *
 * `among` is every handle rendered in the same context — the members of the conversation. It is
 * required rather than optional so that a caller cannot get the unguarded behaviour by
 * forgetting an argument; a context with genuinely one person passes a single-element list.
 */
export function compactNameOf(handle: string, sources: NameSources, among: Iterable<string>): string {
  const petname = sources.petnames[handle]?.trim();
  if (petname) return petname;

  const asserted = assertedName(handle, sources);
  if (!asserted) return handleOf(handle, sources);

  const claim = fold(asserted);
  // A claim is compared with and without a leading sigil, because `@charlie8295` and
  // `charlie8295` are the same impersonation attempt and only one of them looks like one.
  const bare = claim.replace(/^@/, "");
  for (const other of among) {
    if (other === handle) continue;

    // Somebody else wearing the same name. Both of them lose it: showing the handle for one and
    // the name for the other would still leave a reader unable to tell which is which.
    const rival = assertedName(other, sources);
    if (rival !== null && fold(rival).replace(/^@/, "") === bare) return handleOf(handle, sources);

    // A name that *is* another member's handle. Cheap to claim, and it reads as the anchor rather
    // than as the convenience laid over it, which is the whole trick.
    // Compared against what `other` is *shown* as, not against their id: the impersonation this
    // catches is a display name that reads as somebody else's anchor, and since the credential
    // stopped carrying the handle, the anchor on screen is what they claim rather than what
    // names them.
    if (fold(handleOf(other, sources)).replace(/^@/, "") === bare) return handleOf(handle, sources);
  }

  // Somebody whose asserted name is their own handle keeps it as they wrote it: `Charlie8295`
  // stays `Charlie8295` rather than being replaced by `@charlie8295`. There is no impersonation
  // to guard against — the name and the anchor are the same string, and the only thing the
  // substitution changed was the casing its owner chose and the sigil they did not.
  return asserted;
}

/**
 * Whether a person matches a search term.
 *
 * Searches the petname, the asserted name and the handle, because a reader who typed "charlie"
 * cannot be expected to know which of the three the interface happens to be showing them. A
 * leading `@` is dropped so that pasting a handle back in still finds it.
 */
export function nameMatches(handle: string, sources: NameSources, term: string): boolean {
  const needle = fold(term).replace(/^@/, "");
  if (!needle) return true;

  const candidates = [
    sources.handles?.[handle] ?? handle,
    sources.petnames[handle],
    sources.profiles[handle]?.name,
  ];
  return candidates.some((candidate) => candidate !== undefined && fold(candidate).includes(needle));
}

/**
 * The little a conversation needs to be named.
 *
 * Structural rather than an import of `ConversationView`, which is the rule `lib/thread.ts`
 * follows for the same reason: this module is pure, and typing it against the session's shape
 * would drag the whole conversation graph into a test that wants two objects.
 */
export interface Named {
  accounts: readonly { handle: string }[];
  peers: readonly { name: string }[];
}

/**
 * What a conversation is called, in one line.
 *
 * This was written out twice — once in the bar above the thread, once for every row of the rail
 * — as the same four-line expression with a different `among`. A third copy was about to be
 * written for the announcement made when the conversation changes, and three copies of a rule
 * about *which name is safe to show* is how one screen ends up calling somebody Charlie while
 * another calls them @charlie8295.
 *
 * `among` stays a parameter because it is the one thing that genuinely differs, and it is not a
 * detail: it is the set a name has to be unambiguous *within*. The bar compares against the
 * members of the conversation, the rail against every handle it draws — a display name that
 * could be mistaken for somebody in another conversation is ambiguous in a list of conversations
 * and perfectly clear inside one of them.
 *
 * Falls back to the handles the peers are known by, and then to a phrase, so a conversation is
 * never nameless: an empty title in the rail would be a row that cannot be described, and in the
 * announcement it would be silence where a name was expected.
 */
export function titleOf(
  view: Named,
  sources: NameSources,
  among: Iterable<string>,
  self?: string,
): string {
  /*
   * Our own handle joins the comparison set, not just the list of names.
   *
   * Ambiguity is symmetric: if somebody in the room asserts the same display name we do, then
   * *both* names are ambiguous and both have to fall back to their handle. Adding ourselves only
   * to the output would have produced "Sam, @me1234" — one of the two colliding names still
   * claiming the word, which is exactly the confusion `compactNameOf` exists to prevent.
   */
  // `self` is given only for a group — the caller decides what a group is, because it is a
  // property of the MLS context and not of the length of this array. Passing it for a one-to-one
  // would produce "Alice, you", which is two words for what one says.
  const group = self !== undefined;
  const listed = group ? [...among, self] : [...among];
  const named = view.accounts.map((account) => compactNameOf(account.handle, sources, listed));

  /*
   * A group is named by everybody in it, and we are in it.
   *
   * Left out, the title disagreed with the member list beside it and with the count above that
   * — a room of three read as "Bob, Bernard" while its own panel listed three people. Ours goes
   * last: the reader knows they are there, and the names they are scanning for are the others'.
   *
   * One-to-one is untouched. A thread with one other person is named after that person, and
   * "Alice, you" would be two words to say what one says.
   */
  if (group) named.push(compactNameOf(self, sources, listed));

  return (
    named.join(", ") ||
    [...new Set(view.peers.map((peer) => peer.name))]
      .map((name) => compactNameOf(name, sources, listed))
      .join(", ") ||
    "empty conversation"
  );
}
