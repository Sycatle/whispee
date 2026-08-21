/**
 * Reading a QR code with the camera.
 *
 * # What the browser provides, and where it provides nothing
 *
 * `BarcodeDetector` decodes natively, with no library: Chrome on Android exposes it, so Tauri's
 * WebView does too. WKWebView does not, and neither does Firefox.
 *
 * On those platforms there is no scanning — and **that is acceptable**, because typing the code
 * in is still there. Shipping a JavaScript decoder would cost one more dependency in a client
 * whose whole argument is that it has few, to replace a fallback that already works. This is not
 * the same trade-off as for display: there, no fallback existed.
 *
 * # Scanning does not replace verification
 *
 * It replaces typing, nothing more. Pairing security is **physical**: it rests on the user only
 * scanning the screen they are holding, and the confirmation code shown on both sides is what
 * tells them so. A camera does not know which screen it is looking at.
 */

/** Is native decoding available? */
export function scanAvailable(): boolean {
  return "BarcodeDetector" in globalThis;
}

interface QrDetector {
  detect(source: CanvasImageSource): Promise<{ rawValue: string }[]>;
}

/**
 * Opens the camera, reads until the first code, and returns what it contains.
 *
 * Also returns a way to stop everything: the video stream has to be cut whatever happens — an
 * abandoned scan that leaves the camera on is a light that stays green on the phone, which is at
 * best unsettling and at worst a privacy leak.
 */
export async function scan(video: HTMLVideoElement): Promise<{
  read: Promise<string>;
  stop: () => void;
}> {
  const Detector = (globalThis as unknown as {
    BarcodeDetector: new (options: { formats: string[] }) => QrDetector;
  }).BarcodeDetector;

  // `facingMode: environment` asks for the rear camera: that is the one aimed at the other
  // screen. An `ideal` rather than an `exact` — a laptop has only one camera, and demanding the
  // rear one would fail to open instead of taking the one that exists.
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: "environment" } },
  });

  let alive = true;
  const stop = () => {
    alive = false;
    for (const track of stream.getTracks()) track.stop();
  };

  video.srcObject = stream;
  await video.play();

  const detector = new Detector({ formats: ["qr_code"] });

  const read = (async () => {
    // A loop and not a `requestVideoFrameCallback`: the latter does not exist everywhere, and
    // the rate does not matter here — the user is aiming at a still screen, not a moving object.
    while (alive) {
      const codes = await detector.detect(video).catch(() => []);
      const found = codes.find((code) => code.rawValue.length > 0);
      if (found) {
        stop();
        return found.rawValue;
      }

      await new Promise((resolve) => setTimeout(resolve, 200));
    }

    throw new Error("Scan interrupted.");
  })();

  return { read, stop };
}
