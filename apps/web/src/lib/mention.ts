import { type NameSources, compactNameOf, nameMatches } from "./naming.ts";

/**
 * `@somebody` in a message: what is being typed, who it could be, and who it turned out to be.
 *
 * Pure, like `lib/shortcode.ts` next door and for the same reason — the awkward parts of a
 * completion menu are the caret in the middle of a sentence and the sigil that is not one, and
 * neither of those needs a DOM to be got wrong.
 *
 * # The wire carries the handle; the screen shows the name
 *
 * A mention is the literal text `@charlie8295` inside an ordinary text message. No content type,
 * no span table, no byte reserved — `content.ts` does not learn a new shape, and a client that
 * predates this feature shows the sentence with a handle in it, which is what was written.
 *
 * Carrying the *display name* instead was the alternative, and it fails twice. Display names are
 * self-asserted and not unique, so `@Alice` in a group with two of them addresses nobody in
 * particular — the exact confusion `lib/naming.ts` exists to refuse. And a name is editable, so
 * every rename would orphan every mention ever written of that person. The handle is the anchor
 * the rest of the protocol already uses; resolving it to a name at render time is what keeps an
 * old message correct after its subject is renamed.
 *
 * The cost, stated: the composer is a plain `<textarea>` and can only hold a string, so the
 * writer sees `@charlie8295` in the field where the thread will show `@Charlie`. Closing that gap
 * means a `contenteditable` with an inline chip, and that is a rewrite of the caret handling, the
 * paste path, the IME and the completion hook — a batch of its own. The format on the wire is
 * already the one that batch would want, so nothing here is thrown away by doing it later.
 *
 * # Resolution is scoped to the conversation, always
 *
 * `runs` matches only against handles that are in *this* thread. `@alice` written in a group
 * Alice is not in stays plain text, because it addresses somebody who will never read it, and
 * drawing it as a live mention would be a promise the message cannot keep. It also means the
 * rendering of one conversation never depends on another one — the rule `lib/naming.ts` states
 * about `among`, applied to the same problem.
 */

/** The token under the caret, when the caret is inside one. */
export interface Typed {
  /** Index of the `@`. */
  from: number;
  /** Index just past the caret — where a replacement ends. */
  to: number;
  /** What follows the `@`, without it. Empty when the sigil was only just typed. */
  query: string;
}

/**
 * The sigil has to **open** a token: start of the text, or after whitespace or an opening
 * bracket.
 *
 * This is the whole of what keeps a menu off the screen while somebody types an email address.
 * `sam@example.com` has an `@` in it and is not a mention. The rule is copied from
 * `lib/shortcode.ts`, which needed it for `http://` and `10:30`.
 *
 * The query itself excludes whitespace and a second sigil — the latter so that `@@` is nothing
 * rather than a search for `@`. A display name may contain a space and this deliberately
 * will not follow it across one: a query allowed to swallow spaces turns the rest of the sentence
 * into a search term, and the menu never closes again. Searching on one word finds the person —
 * `@ali` reaches `Alice Smith` through `nameMatches` — so the limitation costs a keystroke and
 * buys a menu that goes away.
 */
const TOKEN = /(?:^|[\s([{])@([^\s@]*)$/;

/**
 * The `@query` immediately before the caret, if the caret is in one.
 *
 * A bare `@` opens the menu, where a bare `:` does not. The candidate set here is the members of
 * one conversation — a handful of rows — and listing them is a useful answer to "who is in this
 * room". `lib/shortcode.ts` needs two characters before it says anything because its catalogue
 * holds several thousand entries, and one character there is a wall rather than a suggestion.
 */
export function typed(text: string, caret: number): Typed | null {
  const match = TOKEN.exec(text.slice(0, caret));
  if (!match) return null;

  const query = match[1] ?? "";
  return { from: caret - query.length - 1, to: caret, query };
}

/**
 * Who the query could mean, best first.
 *
 * Four tiers, and the order is not cosmetic: the first row is what Enter takes, so it has to be
 * the least surprising answer. An exact handle beats everything — somebody who typed a handle in
 * full has named a specific account and is not browsing. Then handles by prefix, then people
 * whose *name* starts with it, then anything `nameMatches` will admit, which is the same
 * predicate the rail's filter uses so that one search term does not mean two things in one
 * application.
 *
 * The query is matched with a leading `@` tolerated, because pasting a handle back in is how
 * people quote one.
 */
export function completions(
  among: Iterable<string>,
  sources: NameSources,
  query: string,
  limit = 8,
): string[] {
  const needle = query.trim().replace(/^@/, "").toLowerCase();
  const seen = new Set<string>();
  const candidates = [...among];

  const exact: string[] = [];
  const byHandle: string[] = [];
  const byName: string[] = [];
  const loose: string[] = [];

  for (const handle of candidates) {
    if (seen.has(handle)) continue;
    seen.add(handle);

    if (!needle) {
      byHandle.push(handle);
      continue;
    }

    if (handle === needle) exact.push(handle);
    else if (handle.startsWith(needle)) byHandle.push(handle);
    // The *displayed* name and not the asserted one: `compactNameOf` is what the thread will
    // print, and offering a row under a name the reader will never see it drawn with would be a
    // suggestion that does not match its own result.
    else if (compactNameOf(handle, sources, candidates).toLowerCase().startsWith(needle)) {
      byName.push(handle);
    } else if (nameMatches(handle, sources, needle)) loose.push(handle);
  }

  // Sorted within each tier rather than left in roster order, which is the order the MLS tree
  // happens to hold and which moves under the cursor when a commit lands.
  for (const tier of [byHandle, byName, loose]) tier.sort((a, b) => a.localeCompare(b));

  return [...exact, ...byHandle, ...byName, ...loose].slice(0, limit);
}

/** A stretch of a message: prose, or somebody addressed by it. */
export type Run = { readonly text: string } | { readonly handle: string };

/**
 * Every `@handle` in a message, wherever it is a handle. Handles are `[a-z0-9_]{3,32}` — the rule
 * lives in `lib/handle.ts` and is duplicated here for the same reason `content.ts` duplicates the
 * name ceiling: this is a scanner over bytes a peer wrote, and reading its bounds out of a
 * validation module would change what it matches the day somebody relaxes a user-facing rule.
 */
const SCAN = /@([a-z0-9_]{3,32})/g;

/** Characters that cannot precede a mention, for the same reason `TOKEN` requires an opener. */
const WORD = /[\w@]/;

/**
 * Splits a message into prose and mentions.
 *
 * The run taken is **maximal and never backtracked**. If `alice` is a member and the text says
 * `@alicesmith`, the token is `alicesmith`, that names nobody, and the whole thing stays prose —
 * rather than drawing `@alice` and leaving `smith` dangling after it, which would attribute the
 * sentence to somebody the writer did not address.
 */
export function runs(text: string, among: Iterable<string>): Run[] {
  const known = among instanceof Set ? (among as Set<string>) : new Set(among);
  const out: Run[] = [];
  let cut = 0;

  SCAN.lastIndex = 0;
  for (let match = SCAN.exec(text); match !== null; match = SCAN.exec(text)) {
    const at = match.index;
    const handle = match[1] ?? "";

    // A lookbehind would say this in one character and is left out on purpose: this file is read
    // by `node --test` and by every browser the application supports, and an index into a string
    // works in all of them without anyone having to ask which.
    if (at > 0 && WORD.test(text[at - 1] ?? "")) continue;
    if (!known.has(handle)) continue;

    if (at > cut) out.push({ text: text.slice(cut, at) });
    out.push({ handle });
    cut = at + match[0].length;
  }

  if (cut < text.length) out.push({ text: text.slice(cut) });
  return out;
}

/**
 * Does this text address `handle`?
 *
 * Reads the runs rather than searching for the substring, so that every rule above — the opener,
 * the maximal token, membership of the conversation — applies once and applies here too. A
 * notification raised by a rule the renderer does not share is a notification for a mention the
 * reader cannot find.
 */
export function addresses(text: string, handle: string, among: Iterable<string>): boolean {
  return runs(text, among).some((run) => "handle" in run && run.handle === handle);
}

/**
 * Why a message might be for us in particular.
 *
 * Two ways, and they are one gesture: somebody wrote our handle, or somebody answered something
 * we said. A reply addresses a person as much as a sentence, and the message most likely to be
 * waiting on a reader is precisely the one that answers them.
 */
export type Address = "mention" | "reply";

/**
 * The little an arrival needs for this question to be asked of it.
 *
 * Structural rather than an import of `Message`, which is the rule `lib/thread.ts` follows for
 * the same reason: this module is pure, and typing it against the session's shape would drag the
 * whole conversation graph into a test that wants three objects.
 */
export interface Addressable {
  readonly seq: number;
  readonly mine: boolean;
  readonly content: { readonly kind: string; readonly text?: string; readonly target?: number };
}

/**
 * Whether anything newer than `after` addresses us, and how.
 *
 * The whole thread is passed and not just the new part, because a reply names its target by
 * sequence and deciding whose message that was means looking further back than the arrival.
 *
 * A mention outranks a reply when both are in the same batch: it is the more deliberate of the
 * two — somebody typed a name — and one notification has room for one reason.
 *
 * Our own messages are never an address. Quoting yourself and naming yourself are both ordinary,
 * and neither is somebody wanting your attention.
 */
export function addressedIn(
  messages: readonly Addressable[],
  after: number,
  self: string,
  among: Iterable<string>,
): Address | null {
  const known = new Set(among);
  const mine = new Set(messages.filter((message) => message.mine).map((message) => message.seq));

  let reply: Address | null = null;

  for (const message of messages) {
    if (message.seq <= after || message.mine) continue;

    const { kind, text, target } = message.content;
    if ((kind === "text" || kind === "reply") && text !== undefined) {
      if (addresses(text, self, known)) return "mention";
    }
    if (kind === "reply" && target !== undefined && mine.has(target)) reply = "reply";
  }

  return reply;
}

/**
 * Rewrites the handles a writer typed into the accounts they meant.
 *
 * # Why the conversion happens here and not in the composer
 *
 * The wire has to carry the account id: a handle can be given up and re-typed by nobody — see
 * `migrations/0014_account_identity.sql` — but it can be *renamed*, and a mention carrying a name
 * is orphaned by the next rename. That is the same argument this module already makes against
 * carrying a display name, one level down, and it became true the day handles stopped being
 * identities.
 *
 * What does **not** have to follow is the composer. An id is thirty-two hexadecimal characters;
 * a writer who accepted a suggestion would watch `@a1b2c3d4e5f6…` land in the middle of their
 * sentence, and a `<textarea>` — which is what the composer is, deliberately — has no way to draw
 * it as anything else. So the field keeps the handle, and this function does the substitution
 * once, on the way out.
 *
 * # What that costs
 *
 * A member who renames themselves between the keystroke and the send is resolved to whoever holds
 * the handle in the roster we are looking at. The window is the length of a sentence and the
 * lookup is against the conversation's own members rather than the server's directory, so the
 * mistake needs a rename inside that window *and* somebody else to have taken the freed name —
 * which the tombstone rule makes impossible. The residual case is a member renaming mid-sentence
 * and the mention landing on the account they no longer answer for, which is the right account.
 *
 * # It only ever rewrites members
 *
 * `directory` is this conversation's handles, not the server's. `@alice` written where no member
 * answers to `alice` stays exactly as typed, for the reason `runs` gives: it addresses somebody
 * who will never read it, and inventing an id for them would be worse than leaving prose.
 */
export function resolve(text: string, directory: ReadonlyMap<string, string>): string {
  const parts = runs(text, directory.keys());
  if (!parts.some((run) => "handle" in run)) return text;

  return parts
    .map((run) => ("text" in run ? run.text : `@${directory.get(run.handle) ?? run.handle}`))
    .join("");
}
