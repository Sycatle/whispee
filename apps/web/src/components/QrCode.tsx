import qrcode from "qrcode-generator";

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
export function QrCode({ value, size = 240 }: { value: string; size?: number }) {
  // Version 0: the library picks the smallest one that fits the data. Correction level "M", the
  // usual trade-off — a QR shown on a clean screen does not need "H", which would densify the
  // modules and make scanning harder from a distance.
  const qr = qrcode(0, "M");
  qr.addData(value);
  qr.make();

  const modules = qr.getModuleCount();
  // A four-module quiet zone is required by the standard: without it, a reader cannot tell the
  // pattern from the background and many scans fail silently.
  const side = modules + 8;

  const cells: string[] = [];
  for (let row = 0; row < modules; row += 1) {
    for (let column = 0; column < modules; column += 1) {
      if (qr.isDark(row, column)) cells.push(`M${column + 4},${row + 4}h1v1h-1z`);
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
      className="rounded-md bg-white"
    >
      <path d={cells.join("")} fill="#000" shapeRendering="crispEdges" />
    </svg>
  );
}
