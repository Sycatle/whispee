import assert from "node:assert/strict";
import { test } from "node:test";

import { type Link, type Verifier, walk } from "./chain.ts";

const ACCOUNT = "a".repeat(32);

/**
 * A stand-in for the wasm module.
 *
 * The real derivation and the real signature check are exercised in Rust, where they are defined
 * once — see `crates/attest`. What is tested here is the walk: which failure is reported, in
 * which order, and what happens at the edges.
 */
function verifier(options: { anchors?: string; links?: boolean } = {}): Verifier {
  return {
    accountId: () => options.anchors ?? ACCOUNT,
    verifyRotation: () => options.links ?? true,
  };
}

const key = (byte: number) => new Uint8Array(32).fill(byte);

const CHAIN: Link[] = [
  { seq: 1, identityKey: key(1) },
  { seq: 2, identityKey: key(2), rotation: key(9), rotatedAt: 1_700_000_000 },
  { seq: 3, identityKey: key(3), rotation: key(9), rotatedAt: 1_700_000_100 },
];

test("a chain that verifies gives back the key in use now", () => {
  assert.deepEqual(walk(ACCOUNT, CHAIN, verifier()), { ok: true, current: key(3) });
});

test("a chain of one is the genesis key, and needs no signature", () => {
  // A fresh account has published exactly one key and nothing authorises it but the anchor.
  assert.deepEqual(walk(ACCOUNT, [CHAIN[0]!], verifier()), { ok: true, current: key(1) });
});

test("an empty chain is refused rather than read as an account with no key", () => {
  assert.deepEqual(walk(ACCOUNT, [], verifier()), { ok: false, why: "empty" });
});

test("a chain anchored elsewhere is refused", () => {
  // The server pointing at somebody else. This is the check that makes an id self-authenticating.
  assert.deepEqual(walk(ACCOUNT, CHAIN, verifier({ anchors: "b".repeat(32) })), {
    ok: false,
    why: "wrong-anchor",
  });
});

test("the anchor is checked before the links", () => {
  // Otherwise a chain whose links all verify would produce a confident yes about the wrong
  // account — the links are internally consistent, they are simply somebody else's.
  assert.deepEqual(walk(ACCOUNT, CHAIN, verifier({ anchors: "b".repeat(32), links: true })), {
    ok: false,
    why: "wrong-anchor",
  });
});

test("a link that does not verify names its position", () => {
  assert.deepEqual(walk(ACCOUNT, CHAIN, verifier({ links: false })), {
    ok: false,
    why: "broken-link",
    at: 1,
  });
});

test("a withheld signature is a broken link, not a shorter chain", () => {
  // What the server can still do. Reporting it as a hole is what stops a caller from assuming
  // continuity across a step somebody chose not to show them.
  const holed: Link[] = [CHAIN[0]!, { seq: 2, identityKey: key(2) }];
  assert.deepEqual(walk(ACCOUNT, holed, verifier()), { ok: false, why: "broken-link", at: 1 });
});

test("a timestamp without its signature is also a hole", () => {
  // Half a link looks like evidence and is not: the timestamp is part of what was signed, so
  // without the signature there is nothing to check it against.
  const half: Link[] = [CHAIN[0]!, { seq: 2, identityKey: key(2), rotatedAt: 1 }];
  assert.deepEqual(walk(ACCOUNT, half, verifier()), { ok: false, why: "broken-link", at: 1 });
});

test("each link is checked against the one before it, not against the anchor", () => {
  const seen: Uint8Array[] = [];
  const recording: Verifier = {
    accountId: () => ACCOUNT,
    verifyRotation: (previous) => {
      seen.push(previous);
      return true;
    },
  };

  walk(ACCOUNT, CHAIN, recording);
  // Verifying everything against the genesis key would accept a chain whose middle was replaced.
  assert.deepEqual(seen, [key(1), key(2)]);
});
