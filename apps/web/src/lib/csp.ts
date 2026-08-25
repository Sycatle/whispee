/**
 * The Content-Security-Policy, in one place.
 *
 * # Why it lives here rather than in `vite.config.ts`
 *
 * Because it is written twice. The web build computes it from the function below; the desktop
 * shell repeats it by hand in `apps/desktop/tauri.conf.json`, because Tauri reads its policy from
 * configuration and nothing lets that file call a function.
 *
 * Two hand-maintained copies of a security policy drift, and this pair already had: `blob:`
 * reached `img-src` on the web and never reached the desktop, so every image preview was blocked
 * there — silently, for as long as previews have existed, since a blocked image reports no reason
 * and nothing was listening for one.
 *
 * Living under `src/lib` is what catches the next one. `csp.test.ts` imports this, reads the
 * desktop configuration off disk, and fails when the two disagree in a way nobody declared. The
 * module is imported by `vite.config.ts` and by that test, and by nothing that ships.
 *
 * # What it does not solve
 *
 * The duplication itself. The desktop copy is still typed by a human; this only makes an
 * undeclared difference loud instead of silent, and says nothing about a difference somebody
 * declares wrongly.
 */

/**
 * Content security policy, derived from the API's actual origin.
 *
 * # Why it is computed and not written into `index.html`
 *
 * Because a hard-coded CSP and a configurable `VITE_API_URL` diverge on the first deployment, and
 * the symptom is a "Failed to fetch" the browser raises **before** sending anything: the server
 * sees nothing, and the message does not name the cause. Same trap as the one documented on the
 * CORS header list, server side.
 *
 * # Why `connect-src` carries two origins
 *
 * `connect-src` does **not** infer the `ws://` origin from the matching `http://` one. Either one
 * alone would cut half the client — requests or the real-time session — without the other
 * signalling it.
 *
 * # No nonce, and that is hardening
 *
 * This build emits no inline script, so `'self'` alone suffices: it allows only files from this
 * origin, where a nonce allows whatever the server designates.
 *
 * What it still does not fix: the server serves this JavaScript and can serve a hostile version.
 * No browser policy stands in the way — only the desktop app, whose code is packaged into the
 * installed binary, closes that path.
 */
export function csp(api: string, media?: string): string {
  const websocket = api.replace(/^http/, "ws");
  // The media server is a second origin, and it is absent from most deployments: a build with no
  // media server must not widen its policy for a host it will never contact. Empty rather than a
  // default, so the directive is exactly as wide as the deployment is.
  //
  // **Both forms, and the HTTP one is not redundant.** The `ws://` origin carries the signalling
  // socket, which is what a call needs to happen at all — that much was obvious and was all this
  // line used to allow. The `http://` origin carries the request the SDK makes to ask the server
  // *why* a connection failed. Blocking it does not break a working call; it makes a broken one
  // report a vaguer reason than the browser actually has, at the one moment somebody is trying to
  // find out what went wrong. That is precisely the class of omission this whole file exists to
  // catch — see the note on `media-src`, which went unnoticed for the same reason.
  //
  // The audio itself travels over WebRTC, which no directive here can constrain — see
  // `lib/call.ts` for what does.
  const relay = media ? ` ${media} ${media.replace(/^http/, "ws")}` : "";

  return [
    "default-src 'self'",
    // `wasm-unsafe-eval` is required to instantiate the WebAssembly module; it does not allow
    // `eval()` on JavaScript.
    "script-src 'self' 'wasm-unsafe-eval'",
    // Tailwind injects its styles at runtime. The residual risk of a CSS injection is nowhere
    // near that of a script.
    "style-src 'self' 'unsafe-inline'",
    `connect-src 'self' ${api} ${websocket}${relay}`,
    // `blob:` is for image previews, and it is not a hole reopening.
    //
    // What a received image gets displayed as is a canvas re-encoding of what an image decoder
    // produced from it (`lib/preview.ts`), never the bytes that arrived. `blob:` is what a URL
    // minted by this document's own JavaScript looks like: it is not a network origin, nothing
    // outside this document can produce one, and the server cannot inject one. It permits this
    // page to show a picture it drew itself.
    //
    // What it still does not fix, and what `object-src 'none'` and `script-src 'self'` are
    // carrying instead: a `blob:` URL is same-origin, so a `blob:` document would inherit this
    // origin. `img-src` cannot navigate to one — it can only decode it as an image — and no
    // other directive here allows `blob:`, which is why it is added to this one and not to
    // `default-src`.
    "img-src 'self' data: blob:",
    // `media-src` exists for the audio player, and it is the one place in this application where
    // bytes a peer chose reach a decoder without this code re-emitting them first.
    //
    // `lib/audio.ts` carries that argument in full. What belongs here is the narrower one: an
    // `<audio>` element does not navigate. Bytes that are not a media stream raise an `error`
    // event, never a document, so nothing on this path can become script on the origin holding
    // the keys — which is the property `img-src blob:` is also relying on, one directive up.
    //
    // Without this line the player falls back to `default-src 'self'` and is blocked, silently:
    // a blocked media element reports no reason, which is exactly how the `blob:`/`img-src`
    // divergence this file was written to catch went unnoticed for as long as it did.
    //
    // No `'self'`: nothing in this build plays a media file served by this origin. A directive
    // that lists only what is actually used is a directive that documents.
    "media-src blob:",
    "object-src 'none'",
    // Redundant today and deliberately written anyway: with no `worker-src` and no `child-src`,
    // a worker falls back to `script-src`, which already resolves to this origin. What this line
    // buys is that the fallback stops being load-bearing — the day somebody adds a source to
    // `script-src`, it will not silently become a place workers may be loaded from.
    //
    // The PDF viewer is what makes this concrete: pdf.js parses in a worker, and it reaches for a
    // `blob:` wrapper whenever it judges its `workerSrc` cross-origin. `lib/pdf.ts` hands it a
    // same-origin `workerPort` precisely so that never happens; this is the second lock.
    "worker-src 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; ");
}
