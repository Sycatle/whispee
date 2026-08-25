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
          const api = environment.VITE_API_URL ?? "http://127.0.0.1:8787";

          // Absent by default: a deployment with no media server must not carry its origin.
          return html.replace("%CSP%", csp(api, environment.VITE_MEDIA_URL || undefined));
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
