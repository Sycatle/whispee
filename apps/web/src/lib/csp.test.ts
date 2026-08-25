import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { csp } from "./csp.ts";

/**
 * The policy is written twice — computed here for the web, typed by hand into
 * `apps/desktop/tauri.conf.json` for the shell — and the copies have already drifted once, in a
 * way that took a blocked image and produced no error message anywhere.
 *
 * This compares them directive by directive and allows exactly the differences the desktop target
 * genuinely needs. Anything else fails, which is the whole point: an undeclared divergence should
 * be loud, and the only place it can be made loud is here.
 */

/**
 * The API origin the desktop configuration is pinned to.
 *
 * It is a **desktop-only** source now. The web policy names no origin at all — the API is reached
 * on the page's own origin, so `'self'` covers it — while the packaged shell is loaded from
 * `tauri://` and has to be told where the server is. That difference is a transport difference,
 * exactly like `ipc:`, which is why it belongs in the list below rather than in both policies.
 */
const DESKTOP_API = "http://127.0.0.1:8787";

/**
 * Sources the desktop policy is allowed to have and the web policy is not.
 *
 * Each one is a Tauri transport with no web equivalent: `ipc:` and `http://ipc.localhost` carry
 * the calls into Rust, `asset:` and `http://asset.localhost` serve files out of the packaged
 * bundle. Adding to this list is a deliberate act; that is why it is a list and not a filter.
 */
const DESKTOP_ONLY: Record<string, string[]> = {
  "connect-src": [
    "ipc:",
    "http://ipc.localhost",
    // The two forms of the API origin. The web build stopped naming them when the client began
    // asking its own origin; the desktop cannot, because its own origin is `tauri://`.
    DESKTOP_API,
    DESKTOP_API.replace(/^http/, "ws"),
  ],
  "img-src": ["asset:", "http://asset.localhost"],
};

function parse(policy: string): Map<string, Set<string>> {
  return new Map(
    policy
      .split(";")
      .map((directive) => directive.trim())
      .filter((directive) => directive.length > 0)
      .map((directive) => {
        const [name, ...sources] = directive.split(/\s+/);
        return [name, new Set(sources)] as const;
      }),
  );
}

function desktopPolicy(): string {
  const raw: unknown = JSON.parse(
    readFileSync(new URL("../../../desktop/tauri.conf.json", import.meta.url), "utf8"),
  );
  const security = (raw as { app?: { security?: { csp?: unknown } } }).app?.security?.csp;

  assert.equal(typeof security, "string", "tauri.conf.json has no app.security.csp");
  return security as string;
}

test("both targets declare exactly the same set of directives", () => {
  const web = [...parse(csp()).keys()].sort();
  const desktop = [...parse(desktopPolicy()).keys()].sort();

  assert.deepEqual(
    desktop,
    web,
    "a directive exists on one target and not the other, which no allowance covers",
  );
});

test("every directive allows the same sources, apart from the declared desktop transports", () => {
  const web = parse(csp());
  const desktop = parse(desktopPolicy());

  for (const [name, webSources] of web) {
    const desktopSources = desktop.get(name);
    assert.ok(desktopSources, `${name} is missing from the desktop policy`);

    const allowed = new Set([...webSources, ...(DESKTOP_ONLY[name] ?? [])]);
    const unexpected = [...desktopSources].filter((source) => !allowed.has(source));
    const missing = [...webSources].filter((source) => !desktopSources.has(source));

    assert.deepEqual(unexpected, [], `${name} allows something on desktop that the web does not`);
    assert.deepEqual(missing, [], `${name} allows something on the web that desktop does not`);
  }
});

/**
 * The regression that prompted this file. Stated on its own so that a future edit to the
 * comparison above cannot quietly stop covering it.
 */
test("the desktop policy allows the blob urls the image previews are made of", () => {
  assert.ok(
    parse(desktopPolicy()).get("img-src")?.has("blob:"),
    "image previews are canvas re-encodings served over blob:, and desktop would block them",
  );
});

test("neither target ever allows a script source beyond this origin", () => {
  for (const [target, policy] of [
    ["web", csp()],
    ["desktop", desktopPolicy()],
  ] as const) {
    assert.deepEqual(
      [...(parse(policy).get("script-src") ?? [])].sort(),
      ["'self'", "'wasm-unsafe-eval'"],
      `${target} widened script-src, which is the one directive nothing here is allowed to relax`,
    );
  }
});

/**
 * `media-src` is the directive most likely to be widened by somebody solving a different problem
 * — a remote sound, a notification tone, a streamed voice note — and the widening would not look
 * dangerous. It is, in the narrow sense that matters here: this application never plays anything
 * it did not decrypt itself, so a network origin in this directive means a media element pointing
 * somewhere the rest of the design says it cannot point.
 */
test("media-src is blob: and nothing else, on both targets", () => {
  for (const [target, policy] of [
    ["web", csp()],
    ["desktop", desktopPolicy()],
  ] as const) {
    assert.deepEqual(
      [...(parse(policy).get("media-src") ?? [])],
      ["blob:"],
      `${target} allows a media source other than the blob: urls this code mints itself`,
    );
  }
});

/**
 * The PDF viewer parses in a worker. pdf.js falls back to wrapping its worker in a `blob:` when it
 * decides the configured source is cross-origin, and that fallback is silent — it works, which is
 * the problem. This pins the intent independently of `script-src`, which is what the directive
 * would otherwise inherit from.
 */
test("workers come from this origin and nowhere else, on both targets", () => {
  for (const [target, policy] of [
    ["web", csp()],
    ["desktop", desktopPolicy()],
  ] as const) {
    assert.deepEqual(
      [...(parse(policy).get("worker-src") ?? [])],
      ["'self'"],
      `${target} allows a worker source beyond this origin`,
    );
  }
});

/**
 * Stated as its own assertion because the two comparison tests above would still pass if somebody
 * added `media-src` to `DESKTOP_ONLY`. There is no transport argument for that: unlike `ipc:` and
 * `asset:`, a media element behaves identically on both targets, so a difference here would be a
 * difference nobody needs and one target would be playing something the other refuses.
 */
/**
 * A build with no media server must not carry its origin.
 *
 * The directive is the deployment's own attack surface: widening it for a host that will never
 * be contacted is a permission granted for nothing, and it is granted to every deployment at
 * once because it would live in the default.
 */
test("the media origin appears only when a build asks for one", () => {
  const without = parse(csp()).get("connect-src") ?? new Set();
  const with_ = parse(csp("https://media.example")).get("connect-src") ?? new Set();

  assert.ok(with_.has("wss://media.example"), "the signalling socket has no origin to reach");
  // The HTTP form is not redundant, and this assertion is here because the first version of this
  // test claimed it was. The SDK asks the media server over HTTP why a connection failed; without
  // the origin, a call that breaks reports a vaguer reason than the browser has.
  assert.ok(with_.has("https://media.example"), "a failed call cannot say why it failed");
  assert.deepEqual(
    [...with_].filter((source) => !source.includes("media.example")),
    [...without],
    "configuring a media server changed something other than the media origin",
  );
});

/**
 * **The regression that made `bothSchemes` exist.**
 *
 * The pair was derived with `media.replace(/^http/, "ws")`, which only works on a variable spelled
 * `http://`. `.env.example` recommends `ws://127.0.0.1:7880` for a local media server, and a
 * LiveKit URL is written that way everywhere — given one, the replacement matched nothing, the
 * policy listed the same origin twice, and the HTTP form the test above insists on was absent.
 *
 * The test above did not catch it because it only ever passed `https://`. This one passes the
 * other spelling, which is the one a deployment is most likely to write.
 */
test("both forms are derived however the media origin is spelled", () => {
  for (const [written, expected] of [
    ["ws://127.0.0.1:7880", ["http://127.0.0.1:7880", "ws://127.0.0.1:7880"]],
    ["wss://media.example", ["https://media.example", "wss://media.example"]],
    ["http://127.0.0.1:7880", ["http://127.0.0.1:7880", "ws://127.0.0.1:7880"]],
    ["https://media.example", ["https://media.example", "wss://media.example"]],
  ] as const) {
    const sources = parse(csp(written)).get("connect-src") ?? new Set();

    for (const origin of expected) {
      assert.ok(sources.has(origin), `${written} does not allow ${origin}`);
    }

    // A `Set` would hide a duplicate, so the raw directive is what is counted.
    const directive = csp(written).split("; ").find((part) => part.startsWith("connect-src")) ?? "";
    const occurrences = directive.split(" ").filter((source) => source === written).length;
    assert.equal(occurrences, 1, `${written} appears ${occurrences} times in connect-src`);
  }
});

test("media-src is not among the differences the desktop target is allowed", () => {
  assert.equal(
    DESKTOP_ONLY["media-src"],
    undefined,
    "an allowance was added for media-src, which has no desktop transport to justify it",
  );
});
