/**
 * The shared wire vectors, run against the TypeScript implementation.
 *
 * The same `crates/wire/vectors.json` is executed by the Rust crate. Two encoders that only
 * round-trip against themselves agree on nothing: the disagreement surfaces the day a client
 * written on the other side sends a real message, and by then it is a protocol break rather
 * than a failing test.
 *
 * The vectors were written from the format description, not dumped from either implementation,
 * so neither side is marking its own homework.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { decode as decodeContent, encode as encodeContent, isControl } from "./content.ts";
import { decode as decodeEnvelope, encodeMls, encodeWelcome } from "./envelope.ts";
import { pad, unpad } from "./padding.ts";

interface ContentVector {
  name: string;
  body: Record<string, unknown>;
  sentAt: number | null;
  hex: string;
}

interface EnvelopeVector {
  name: string;
  kind: "mls" | "welcome";
  payload?: string;
  welcome?: string;
  ratchetTree?: string;
  hex: string;
}

interface PaddingVector {
  length: number;
  paddedLength: number;
  marker: number;
}

const vectors = JSON.parse(
  readFileSync(new URL("../../../../crates/wire/vectors.json", import.meta.url), "utf8"),
) as { content: ContentVector[]; envelope: EnvelopeVector[]; padding: PaddingVector[] };

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const fromHex = (hex: string): Uint8Array =>
  new Uint8Array((hex.match(/../g) ?? []).map((pair) => Number.parseInt(pair, 16)));

/** Turns the vector's description of a body into what `content.ts` expects. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function bodyFrom(value: any): any {
  switch (value.kind) {
    case "gossip":
      return { kind: "gossip", head: { size: value.head.size, root: fromHex(value.head.root) } };
    case "posting-key":
      return { kind: "posting-key", key: fromHex(value.key) };
    case "signals":
      return { kind: "signals", sealed: fromHex(value.sealed) };
    default:
      return value;
  }
}

test("every content vector encodes to its bytes", () => {
  assert.ok(vectors.content.length > 0, "an empty vector file would pass silently");

  for (const vector of vectors.content) {
    const encoded = encodeContent(bodyFrom(vector.body), vector.sentAt ?? undefined);
    assert.equal(toHex(encoded), vector.hex, `encoding disagrees with the shared vector: ${vector.name}`);
  }
});

test("every content vector decodes back", () => {
  for (const vector of vectors.content) {
    const decoded = decodeContent(fromHex(vector.hex));
    assert.deepEqual(decoded.body, bodyFrom(vector.body), `wrong body for ${vector.name}`);

    // Control traffic drops its stamp on encode, so the vector's `sentAt` is what was offered,
    // not what survives.
    const expected = isControl(decoded.body) ? undefined : (vector.sentAt ?? undefined);
    assert.equal(decoded.sentAt, expected, `wrong stamp for ${vector.name}`);
  }
});

test("every envelope vector matches", () => {
  assert.ok(vectors.envelope.length > 0);

  for (const vector of vectors.envelope) {
    const encoded =
      vector.kind === "mls"
        ? encodeMls(fromHex(vector.payload ?? ""))
        : encodeWelcome(fromHex(vector.welcome ?? ""), fromHex(vector.ratchetTree ?? ""));
    assert.equal(toHex(encoded), vector.hex, `envelope vector ${vector.name}`);

    const parsed = decodeEnvelope(fromHex(vector.hex));
    if (parsed.kind === "mls") {
      assert.equal(toHex(parsed.payload), vector.payload);
    } else {
      assert.equal(toHex(parsed.welcome), vector.welcome);
      assert.equal(toHex(parsed.ratchetTree), vector.ratchetTree);
    }
  }
});

test("every padding vector matches", () => {
  assert.ok(vectors.padding.length > 0);

  for (const vector of vectors.padding) {
    const body = new Uint8Array(vector.length).fill(0x41);
    const padded = pad(body);

    assert.equal(padded.length, vector.paddedLength, `padded length for ${vector.length} bytes`);
    assert.equal(padded[vector.length], vector.marker, `marker position for ${vector.length} bytes`);
    assert.deepEqual(unpad(padded), body);
  }
});
