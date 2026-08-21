import assert from "node:assert/strict";
import { test } from "node:test";

import qrcode from "qrcode-generator";

/**
 * The pairing code as `encodePairingCode` produces it: 48 bytes in base64url, so 64 characters.
 * It is the only data this project ever puts in a QR.
 */
const CODE = "A".repeat(64);

function grid(value: string) {
  const qr = qrcode(0, "M");
  qr.addData(value);
  qr.make();
  return qr;
}

/**
 * The three finder patterns are there.
 *
 * That is what a reader looks for first: without them it does not even locate the code in the
 * image. A square missing one would be undetectable — and the only symptom would be a user who
 * "cannot scan", with nothing on screen to explain it.
 */
test("the square carries its three finder patterns", () => {
  const qr = grid(CODE);
  const n = qr.getModuleCount();

  for (const [row, column] of [
    [0, 0],
    [0, n - 7],
    [n - 7, 0],
  ]) {
    // A finder pattern is a solid 7×7 square framed by a light ring: checking its corners and its
    // center is enough to tell a pattern apart from any ordinary data area.
    assert.ok(qr.isDark(row, column), `corner ${row},${column} missing`);
    assert.ok(qr.isDark(row + 6, column + 6));
    assert.ok(qr.isDark(row + 3, column + 3));
    assert.ok(!qr.isDark(row + 1, column + 1), "the light ring is missing");
  }
});

/**
 * The chosen version stays small.
 *
 * An over-dense QR is not unreadable in theory, it is unreadable in practice: more modules on the
 * same patch of screen, so a camera that has to come closer, for a gesture the user performs once
 * and without knowing why it fails.
 *
 * The current 64 characters land in version 5, that is 37 modules — measured, not deduced. The
 * threshold is there to flag data that grows: a longer pairing code would raise the version, and
 * the worse scanning would be blamed on the camera rather than on that change.
 */
test("the pairing code fits in a low version", () => {
  const modules = grid(CODE).getModuleCount();

  // Version n → 17 + 4n modules. Version 5 makes 37 of them.
  assert.ok(modules <= 37, `${modules} modules: the data has grown`);
});

/** Two different payloads give two different squares — the encoder really does encode. */
test("the square depends on the data", () => {
  const a = grid(CODE);
  const b = grid("B".repeat(64));

  const fingerprint = (qr: ReturnType<typeof grid>) => {
    const n = qr.getModuleCount();
    let bits = "";
    for (let r = 0; r < n; r += 1) for (let c = 0; c < n; c += 1) bits += qr.isDark(r, c) ? "1" : "0";
    return bits;
  };

  assert.notEqual(fingerprint(a), fingerprint(b));
});
