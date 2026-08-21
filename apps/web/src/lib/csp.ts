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
export function csp(api: string): string {
  const websocket = api.replace(/^http/, "ws");

  return [
    "default-src 'self'",
    // `wasm-unsafe-eval` is required to instantiate the WebAssembly module; it does not allow
    // `eval()` on JavaScript.
    "script-src 'self' 'wasm-unsafe-eval'",
    // Tailwind injects its styles at runtime. The residual risk of a CSS injection is nowhere
    // near that of a script.
    "style-src 'self' 'unsafe-inline'",
    `connect-src 'self' ${api} ${websocket}`,
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
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; ");
}
