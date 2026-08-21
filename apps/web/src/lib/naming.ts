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
    return { primary: petname, secondary: formatHandle(handle), isHandle: false };
  }

  const asserted = assertedName(handle, sources);
  if (asserted) {
    return { primary: asserted, secondary: formatHandle(handle), isHandle: false };
  }

  return { primary: formatHandle(handle), secondary: null, isHandle: true };
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
  if (!asserted) return formatHandle(handle);

  const claim = fold(asserted);
  // A claim is compared with and without a leading sigil, because `@charlie8295` and
  // `charlie8295` are the same impersonation attempt and only one of them looks like one.
  const bare = claim.replace(/^@/, "");
  for (const other of among) {
    if (other === handle) continue;

    // Somebody else wearing the same name. Both of them lose it: showing the handle for one and
    // the name for the other would still leave a reader unable to tell which is which.
    const rival = assertedName(other, sources);
    if (rival !== null && fold(rival).replace(/^@/, "") === bare) return formatHandle(handle);

    // A name that *is* another member's handle. Cheap to claim, and it reads as the anchor rather
    // than as the convenience laid over it, which is the whole trick.
    if (fold(other) === bare) return formatHandle(handle);
  }

  // Somebody whose asserted name is their own handle gets the handle, sigil and all, rather than
  // a bare copy of it that would read as a display name.
  if (bare === fold(handle)) return formatHandle(handle);

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

  const candidates = [handle, sources.petnames[handle], sources.profiles[handle]?.name];
  return candidates.some((candidate) => candidate !== undefined && fold(candidate).includes(needle));
}
