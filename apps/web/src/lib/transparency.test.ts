import assert from "node:assert/strict";
import { test } from "node:test";

import { acceptHead, verifyAccount, verifyExtends, type SeenHead } from "./transparency.ts";
import type { Api, SignedHead } from "./api.ts";
import type { Crypto } from "./wasm.ts";

/**
 * Doubles rather than the real WebAssembly module.
 *
 * The verdicts are the subject here, not the Merkle arithmetic — that is verified where it is
 * written, in `crates/transparency`, against RFC 6962. What this file pins is the decision each
 * combination of answers leads to, which is the part that now blocks a conversation from opening
 * and therefore the part whose regression would be silent in both directions: a check that stops
 * refusing, or one that starts refusing an honest server.
 */
const bytes = (...values: number[]) => new Uint8Array(values);

const KEY = bytes(0xaa);
const ROOT = bytes(0x01, 0x02);

function head(extra: Partial<SignedHead> = {}): SignedHead {
  return {
    size: 4,
    root: ROOT,
    logKey: KEY,
    timestamp: 1,
    signature: bytes(0xff),
    ...extra,
  } as SignedHead;
}

/** Everything answers yes. Individual tests override the one answer they are about. */
function crypto(extra: Partial<Crypto> = {}): Crypto {
  return {
    verifyTreeHead: () => true,
    verifyInclusion: () => true,
    verifyConsistency: () => true,
    logLeaf: () => bytes(0x42),
    ...extra,
  } as unknown as Crypto;
}

function api(proof: Record<string, unknown>, consistency = bytes()): Api {
  return {
    logProof: () => Promise.resolve(proof),
    logConsistency: () => Promise.resolve({ proof: consistency }),
  } as unknown as Api;
}

const seen = (extra: Partial<SeenHead> = {}): SeenHead => ({
  size: 4,
  root: ROOT,
  logKey: KEY,
  ...extra,
});

test("a well-signed head with no prior anchor is accepted", () => {
  assert.deepEqual(acceptHead(crypto(), head(), undefined), { ok: true });
});

test("a badly signed head is refused", () => {
  const verdict = acceptHead(crypto({ verifyTreeHead: () => false }) , head(), undefined);

  assert.equal(verdict.ok, false);
});

/** A log that starts signing with another key is another log, whatever it proves about itself. */
test("a changed log key is refused", () => {
  const verdict = acceptHead(crypto(), head({ logKey: bytes(0xbb) }), seen());

  assert.equal(verdict.ok, false);
});

/**
 * The case the persisted anchor exists for. Without a remembered size this comparison has nothing
 * to run against, and an amputated log passes as a fresh one.
 */
test("a log shorter than the anchor is refused", () => {
  const verdict = acceptHead(crypto(), head({ size: 3 }), seen({ size: 4 }));

  assert.equal(verdict.ok, false);
});

test("a key absent from the log is refused", async () => {
  const { verdict, head: remembered } = await verifyAccount(
    api({ head: head(), index: 0, proof: [], identityKey: KEY }),
    crypto({ verifyInclusion: () => false }),
    "bob",
    KEY,
    undefined,
  );

  assert.equal(verdict.ok, false);
  // Nothing is remembered on refusal: endorsing a head we just rejected would validate it.
  assert.equal(remembered, undefined);
});

/**
 * The inclusion proof can be valid for a key that is not the one being served: the server proves
 * something true about a leaf nobody asked for. Comparing the two is what closes that.
 */
test("a proof for a different key than the one served is refused", async () => {
  const { verdict } = await verifyAccount(
    api({ head: head(), index: 0, proof: [], identityKey: bytes(0xcc) }),
    crypto(),
    "bob",
    KEY,
    undefined,
  );

  assert.equal(verdict.ok, false);
});

test("an inconsistent log is refused even when the key is properly included", async () => {
  const { verdict } = await verifyAccount(
    api({ head: head({ size: 6 }), index: 0, proof: [], identityKey: KEY }),
    crypto({ verifyConsistency: () => false }),
    "bob",
    KEY,
    seen(),
  );

  assert.equal(verdict.ok, false);
});

test("a sound proof returns the head to remember", async () => {
  const { verdict, head: remembered } = await verifyAccount(
    api({ head: head({ size: 6 }), index: 0, proof: [], identityKey: KEY }),
    crypto(),
    "bob",
    KEY,
    seen(),
  );

  assert.deepEqual(verdict, { ok: true });
  assert.deepEqual(remembered, { size: 6, root: ROOT, logKey: KEY });
});

/**
 * Gossip runs through the same function with a peer's head as the anchor. A log shorter than the
 * view a correspondent handed us is a fork, and it is refused before any proof is even fetched.
 */
test("a log shorter than a peer's view is refused without asking for a proof", async () => {
  const refuses = {
    logConsistency: () => Promise.reject(new Error("should not be reached")),
  } as unknown as Api;

  const verdict = await verifyExtends(refuses, crypto(), seen({ size: 9 }), head({ size: 4 }));

  assert.equal(verdict.ok, false);
});

/**
 * The only check that works on a **first** contact. Everything else compares the server against
 * its own past, which a server meeting a client for the first time has none of.
 */
test("a log signed by a key this build was not compiled for is refused", () => {
  const verdict = acceptHead(crypto(), head(), undefined, bytes(0xbb));

  assert.equal(verdict.ok, false);
});

test("the pinned key accepts the log it was pinned to", () => {
  assert.deepEqual(acceptHead(crypto(), head(), undefined, KEY), { ok: true });
});

/**
 * A deployment generates its own log key on first boot, so there is nothing to compile in until
 * it has. An unset pin must therefore leave behaviour exactly as it was.
 */
test("no pin leaves the first contact exactly as it was", () => {
  assert.deepEqual(acceptHead(crypto(), head(), undefined, undefined), { ok: true });
});

/** The pin is checked before the anchor: a wrong key is wrong whatever else agrees with it. */
test("the pin outranks a matching anchor", () => {
  const verdict = acceptHead(crypto(), head(), seen(), bytes(0xbb));

  assert.equal(verdict.ok, false);
});
