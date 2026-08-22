/**
 * The five shapes this application can be in, as a string and back.
 *
 * # Why a hand-written router, and not one of the good ones
 *
 * There are five route patterns. A general-purpose router brings dynamic segments, nested
 * routes, lazy loading, data loaders and route guards — none of which would be used. What is
 * left after removing all of that is the `switch` below.
 *
 * The second reason is the test harness. `parse` and `format` are pure functions over strings,
 * which is **exactly** what this repository knows how to test: `node --test`, no DOM, no
 * transpiler. An imported router is not testable here at all, so its behaviour would be checked
 * by clicking, which is how routing bugs survive.
 *
 * The third is supply chain. The token batch has just added around forty transitive packages for
 * accessibility primitives, on a client that runs the user's cryptography. That was paid for
 * because writing focus traps by hand had already gone wrong in seven places. Nothing comparable
 * is at stake here, so nothing more is added.
 *
 * # Why the hash and not the path
 *
 * **There is no SPA fallback anywhere in this repository.** Checked: `release/` holds a single
 * public key, `scripts/` holds three shell scripts about building and verifying releases, the
 * repository root has no `Dockerfile`, no `nginx.conf`, no `_redirects`, no `vercel.json`, and
 * the server crate serves no static files at all — it has no `ServeDir` and no `index.html`
 * fallback. `pnpm run build` produces a `dist/` that someone drops on a static host. On such a
 * host `/c/abc` is a request for a file that does not exist, so `Ctrl+R` — the explicit
 * requirement — would be a 404. Vite's dev server and `vite preview` do fall back to
 * `index.html`, which is precisely what makes the trap dangerous: a path router would work all
 * through development and break only once deployed.
 *
 * Under Tauri the same URL is resolved against the packaged files (`frontendDist:
 * "../web/dist"`, `apps/desktop/tauri.conf.json`), and `dist/` contains no `c/abc`. What has
 * *not* been verified here is whether Tauri v2's asset protocol has an `index.html` fallback of
 * its own; the claim is only that the hash makes the question moot, because a fragment never
 * reaches the asset resolver in the first place.
 *
 * And the fragment is never sent to the server. On an end-to-end encrypted client that is a
 * substantive argument rather than a technicality: a conversation identifier in a path travels
 * in the request line on every single reload, and therefore into whatever access log sits in
 * front of the static host. This repository already sets `<meta name="referrer"
 * content="no-referrer">` in `index.html` out of the same concern; keeping the identifier in the
 * fragment carries it one step further.
 *
 * # What ends up on disk, and what it says
 *
 * `<key>` is `toHex(groupId)` — the MLS group identifier. It lands in the address bar, in the
 * browser's history database, and in whatever session-restore file the browser keeps. It is not
 * a handle: it does not say *who* is being talked to, and it is meaningless to anyone without
 * the conversation. But it does outlive "forget this identity", which clears this application's
 * storage and cannot clear the browser's history. That is a real cost. It is small, and it is
 * written here rather than left to be discovered.
 *
 * # What is not a route
 *
 * `busy`, `locked` and `onboarding` (`App.tsx:329-346`). They are not destinations, they are
 * gates: the absence of a session is not a place one navigates to, it is a state that makes all
 * navigation moot. They stay as `if`s in front of the router.
 *
 * One consequence comes for free and is the behaviour we want: a user re-locked while on
 * `#/c/abc` (`relock()`, `App.tsx:81-85`) sees the unlock screen **without the URL changing**,
 * and lands back in their conversation once the password is accepted. Nothing had to be written
 * to obtain that; it follows from the lock not being a route.
 *
 * # What `parse` does not check
 *
 * It validates the *shape* of a key, never its existence. `#/c/00ff` parses into a conversation
 * route whether or not such a conversation exists — this module has no access to the session and
 * should not acquire one, or it would stop being testable without a DOM. Deciding what to show
 * for a well-formed key that names nothing belongs to the shell.
 */

/** The panels reachable under `#/settings`. Also the validation list for `parse`. */
export const SETTINGS_SECTIONS = [
  "profile",
  "devices",
  "pairing",
  "lock",
  "backup",
  "receipts",
  "notifications",
  "blocked",
  "appearance",
] as const;

export type SettingsSection = (typeof SETTINGS_SECTIONS)[number];

/**
 * Where the application is.
 *
 * A discriminated union, so that a `switch` over `kind` that forgets a case is a `tsc --noEmit`
 * error rather than a blank panel. That matters more here than it usually would: there are no
 * component tests in this repository, so the type checker is the only automatic net under the
 * rendering code.
 */
export type Route =
  | { kind: "home" }
  | { kind: "new" }
  | {
      kind: "conversation";
      /** `toHex(groupId)`: lowercase hexadecimal, URL-safe without escaping. */
      key: string;
    }
  | {
      kind: "settings";
      /** `null` is the settings index — `#/settings` with no section chosen yet. */
      section: SettingsSection | null;
    };

const HOME: Route = { kind: "home" };

/**
 * Is this a key we produced?
 *
 * Lowercase because `toHex` (`keys.ts:141`) emits lowercase and nothing else writes these
 * strings; accepting uppercase would mean two URLs for one conversation, and `format(parse(x))`
 * would stop being the identity on canonical input. Even length because a hexadecimal byte
 * string has one. No upper bound on length: nothing downstream indexes by it, and a key that is
 * merely absurd already resolves to no conversation.
 *
 * The point of rejecting rather than passing it through: a malformed key would otherwise produce
 * a conversation route that matches nothing, which renders as an empty panel with no way back
 * except the address bar. Falling back to home is the honest answer to a URL we did not write.
 */
function isKey(value: string): boolean {
  return value.length > 0 && value.length % 2 === 0 && /^[0-9a-f]+$/.test(value);
}

function isSection(value: string): value is SettingsSection {
  return (SETTINGS_SECTIONS as readonly string[]).includes(value);
}

/**
 * Reads a route out of a location hash, with or without its leading `#`.
 *
 * Anything unrecognised is home. There is no "not found" screen and there should not be one: the
 * only way to reach an unknown hash is a stale bookmark or a typed URL, and both are better
 * served by the list of conversations than by an apology.
 */
export function parse(hash: string): Route {
  const path = hash.startsWith("#") ? hash.slice(1) : hash;
  const trimmed = path.startsWith("/") ? path.slice(1) : path;
  // Empty segments are kept rather than filtered: `#/c/k/info/` must not read as `#/c/k/info`
  // with a handle, and the only way to tell them apart is the trailing empty string.
  const segments = trimmed === "" ? [] : trimmed.split("/");

  if (segments.length === 0) return HOME;

  if (segments[0] === "new" && segments.length === 1) return { kind: "new" };

  if (segments[0] === "c" && segments.length >= 2 && isKey(segments[1])) {
    const key = segments[1];
    if (segments.length === 2) return { kind: "conversation", key };

    // `/info` and `/info/<handle>` used to name the detail column, and are now read as a
    // conversation with something after it — which is what they are. Kept as a redirect rather
    // than a rejection because these URLs are in people's history and in their open tabs, and
    // answering an address this application itself minted with the home screen would be a worse
    // welcome than dropping the part that no longer means anything. See `state/detail.tsx` for
    // why the column stopped being a place one navigates to.
    if (segments[2] === "info" && segments.length <= 4) return { kind: "conversation", key };

    return HOME;
  }

  if (segments[0] === "settings") {
    // An unknown section falls back to the settings index rather than to home. The prefix is
    // information the user gave us and it was recognised; discarding it too would answer a
    // half-wrong URL by ignoring the half that was right.
    if (segments.length === 1) return { kind: "settings", section: null };
    if (segments.length === 2) {
      return { kind: "settings", section: isSection(segments[1]) ? segments[1] : null };
    }
    return HOME;
  }

  return HOME;
}

/**
 * Writes a route back out, leading `#` included, so the result can be assigned to a `href` or
 * handed to `history.pushState` unchanged.
 *
 * Total over the type — the `switch` has no `default`, which is what makes a new route kind a
 * compile error here rather than a silently empty string.
 */
export function format(route: Route): string {
  switch (route.kind) {
    case "home":
      return "#/";
    case "new":
      return "#/new";
    case "conversation":
      return `#/c/${route.key}`;
    case "settings":
      return route.section === null ? "#/settings" : `#/settings/${route.section}`;
  }
}

/**
 * Do two routes name the same place?
 *
 * Compared through `format` rather than field by field: the strings are the canonical form
 * already, and a structural comparison would have to be revisited every time a field is added to
 * the union — the kind of maintenance that is forgotten exactly once and then produces a
 * duplicated history entry nobody can reproduce.
 */
export function same(a: Route, b: Route): boolean {
  return format(a) === format(b);
}
