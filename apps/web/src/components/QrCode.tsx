import qrcode from "qrcode-generator";

/**
 * Modules of blank margin on every side, mandated by the QR standard.
 *
 * Four is the specified minimum, not a stylistic choice: a reader locates the three finder
 * patterns by their light surround, and without it many scans fail with no feedback at all —
 * the camera simply never locks on. It is expressed once here and used twice below, because the
 * viewBox and the cell offsets have to agree or the margin silently lands on two sides only.
 */
const QUIET_ZONE = 4;

/**
 * Rendered edge, in CSS pixels.
 *
 * Not one of the `--spacing-*` tokens, and it should not become one: those describe distances
 * between interface elements, and this is the size at which a camera has to resolve individual
 * modules across a room. 240 keeps a typical 25-module version at roughly 8 px a module, which
 * is comfortably above what a phone camera needs at arm's length.
 */
const DEFAULT_SIZE = 240;

/**
 * The pairing code, as a square to scan.
 *
 * # Why a dependency here, in a project that distrusts them
 *
 * Writing a QR encoder means Reed-Solomon, the eight masks and their penalties: a few hundred
 * lines that no test available here could validate, for lack of a reader — Chrome on Linux does
 * not expose `BarcodeDetector`. A subtly wrong square would only show up in a user's hands.
 *
 * The content costs nothing to entrust: an id and an ephemeral public key, both public by
 * construction. A compromised library could not steal a secret — at worst display a code leading
 * elsewhere, which is exactly what the confirmation code shown on both sides is there to catch.
 *
 * # Rendered as SVG, not canvas
 *
 * Sharp at any size, so readable by a camera whatever the screen, and with no pixel readback — a
 * canvas would have to be sized by hand to avoid a blurry square on a dense display, precisely
 * where scanning has to work.
 */
export function QrCode({ value, size = DEFAULT_SIZE }: { value: string; size?: number }) {
  // Version 0: the library picks the smallest one that fits the data. Correction level "M", the
  // usual trade-off — a QR shown on a clean screen does not need "H", which would densify the
  // modules and make scanning harder from a distance.
  const qr = qrcode(0, "M");
  qr.addData(value);
  qr.make();

  const modules = qr.getModuleCount();
  const side = modules + QUIET_ZONE * 2;

  const cells: string[] = [];
  for (let row = 0; row < modules; row += 1) {
    for (let column = 0; column < modules; column += 1) {
      if (qr.isDark(row, column)) {
        cells.push(`M${column + QUIET_ZONE},${row + QUIET_ZONE}h1v1h-1z`);
      }
    }
  }

  return (
    <svg
      viewBox={`0 0 ${side} ${side}`}
      width={size}
      height={size}
      role="img"
      aria-label="Pairing code to scan"
      // White background and black modules hardcoded, outside the theme: a reader expects
      // contrast, and black on white. A QR in dark-theme colors is unreadable to many cameras,
      // which would make a display flaw look like a pairing failure.
      //
      // The background is on the `<svg>` itself and not on a wrapper, which is what makes the
      // quiet zone survive the dark palette: the margin is white because the element under it is
      // white, in both themes, whatever the pane behind it happens to be. Painting the modules
      // on a transparent square would leave the margin the colour of the surface, and a QR with
      // a dark margin is as unscannable as one with dark modules.
      className="rounded-control bg-white"
    >
      <path d={cells.join("")} fill="#000" shapeRendering="crispEdges" />
    </svg>
  );
}
