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

/** The API origin the desktop configuration is pinned to, so both sides describe the same server. */
const DESKTOP_API = "http://127.0.0.1:8787";

/**
 * Sources the desktop policy is allowed to have and the web policy is not.
 *
 * Each one is a Tauri transport with no web equivalent: `ipc:` and `http://ipc.localhost` carry
 * the calls into Rust, `asset:` and `http://asset.localhost` serve files out of the packaged
 * bundle. Adding to this list is a deliberate act; that is why it is a list and not a filter.
 */
const DESKTOP_ONLY: Record<string, string[]> = {
  "connect-src": ["ipc:", "http://ipc.localhost"],
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
  const web = [...parse(csp(DESKTOP_API)).keys()].sort();
  const desktop = [...parse(desktopPolicy()).keys()].sort();

  assert.deepEqual(
    desktop,
    web,
    "a directive exists on one target and not the other, which no allowance covers",
  );
});

test("every directive allows the same sources, apart from the declared desktop transports", () => {
  const web = parse(csp(DESKTOP_API));
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
    ["web", csp(DESKTOP_API)],
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
    ["web", csp(DESKTOP_API)],
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
    ["web", csp(DESKTOP_API)],
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
test("media-src is not among the differences the desktop target is allowed", () => {
  assert.equal(
    DESKTOP_ONLY["media-src"],
    undefined,
    "an allowance was added for media-src, which has no desktop transport to justify it",
  );
});
