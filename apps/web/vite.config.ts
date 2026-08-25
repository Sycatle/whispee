import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { csp } from "./src/lib/csp";
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
export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    tailwindcss(),
    {
      name: "csp",
      transformIndexHtml: {
        order: "pre" as const,
        handler: (html: string) => {
          const environment = loadEnv(mode, process.cwd(), "VITE_");

          // The API's origin is no longer read here, and that is the point: it used to be
          // substituted into this file, so two deployments produced two different `index.html`
          // and no published manifest of hashes could describe more than one of them. The policy
          // says `'self'` now — see `src/lib/csp.ts`.
          //
          // The media server is the one origin still able to vary, and a deployment that sets it
          // gives up matching the published build. That trade is written down in
          // `docs/THREAT-MODEL.md` rather than left here.
          return html.replace("%CSP%", csp(environment.VITE_MEDIA_URL || undefined));
        },
      },
    },
  ],

  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },

  server: {
    // The port belongs to the branch, not to Vite: `scripts/dev-env.sh` hands out one per
    // branch so that several checkouts can run at once, and starts the server with a matching
    // `ALLOWED_ORIGINS`. Unset — a plain `pnpm run dev` — keeps the historical 5173.
    port: Number(process.env.WEB_PORT) || 5173,

    // **`strictPort` is the point of the pair.** Vite's default on a taken port is to slide to
    // the next free one, silently. That port is in nobody's CORS list and in no CSP, so the
    // client comes up looking healthy and every request dies as "Failed to fetch" — the failure
    // mode `src/lib/csp.ts` describes, arrived at by convenience rather than by misconfiguration.
    // Refusing to start says which port is taken, which is a sentence somebody can act on.
    strictPort: true,

    /**
     * Development reaches the API through here rather than across origins.
     *
     * The client no longer carries the server's address: it asks its own origin, because in a
     * deployment Caddy serves both. Without this proxy that would be true everywhere except on
     * the machine where the code is written — one code path in production and another in
     * development is how a bug ships that nobody could reproduce.
     *
     * `ws: true` because `/v1/gateway` is a WebSocket upgrade, and a proxy that forwards the
     * requests but not the upgrade leaves the real-time session failing while everything else
     * looks well.
     *
     * `WHISPEE_API` for the branch-scoped port `scripts/dev-env.sh` hands out; the default is the
     * one a plain `pnpm run dev` expects.
     */
    proxy: {
      "/v1": {
        target: process.env.WHISPEE_API ?? "http://127.0.0.1:8787",
        changeOrigin: true,
        ws: true,
      },
    },
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
