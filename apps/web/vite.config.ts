import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";

/**
 * Client build.
 *
 * # Why Vite rather than Next
 *
 * The project used exactly one thing from Next: middleware setting a per-request CSP nonce. That
 * nonce was itself needed **only because Next injects inline scripts** (bootstrap, RSC
 * streaming). Without those scripts there is nothing inline to allow, and `script-src 'self'`
 * suffices — which is stricter than a nonce, not looser.
 *
 * The rest of what Next brings went unused: no server rendering (everything is encrypted
 * locally, there is nothing to pre-render), no API route (the server is in Rust), a single page.
 *
 * This static output feeds all three targets — web, desktop and mobile — without being built
 * twice.
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
function csp(api: string): string {
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

export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    tailwindcss(),
    {
      name: "csp",
      transformIndexHtml: {
        order: "pre" as const,
        handler: (html: string) => {
          const api =
            loadEnv(mode, process.cwd(), "VITE_").VITE_API_URL ?? "http://127.0.0.1:8787";

          return html.replace("%CSP%", csp(api));
        },
      },
    },
  ],

  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },

  build: {
    // **The setting that justifies the whole migration.** Vite injects a small inline polyfill
    // for `modulepreload` by default; leaving it would reintroduce exactly the inline script we
    // just removed, and with it the need for a nonce. Target browsers support it natively.
    modulePreload: { polyfill: false },

    // The WebAssembly module is already compressed and over a megabyte: the warning would teach
    // nothing and would hide the ones that matter.
    chunkSizeWarningLimit: 2048,
  },
}));
