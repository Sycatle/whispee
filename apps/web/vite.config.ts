import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";

/**
 * Build du client.
 *
 * # Pourquoi Vite plutôt que Next
 *
 * Le projet n'utilisait de Next qu'une seule chose : un middleware posant un nonce CSP par
 * requête. Ce nonce n'était lui-même nécessaire **que parce que Next injecte des scripts
 * inline** (amorçage, streaming RSC). Sans ces scripts, il n'y a rien d'inline à autoriser et
 * `script-src 'self'` suffit — ce qui est plus strict qu'un nonce, pas moins.
 *
 * Le reste de ce que Next apporte était inutilisé : pas de rendu serveur (tout est chiffré
 * localement, il n'y a rien à prégénérer), pas de route d'API (le serveur est en Rust), une
 * seule page.
 *
 * Cette sortie statique alimente les trois cibles — web, bureau et mobile — sans être
 * construite deux fois.
 */
/**
 * Politique de sécurité de contenu, dérivée de l'origine réelle de l'API.
 *
 * # Pourquoi elle est calculée et non écrite dans `index.html`
 *
 * Parce qu'une CSP en dur et une `VITE_API_URL` configurable divergent au premier déploiement,
 * et que le symptôme est un « Failed to fetch » que le navigateur émet **avant** d'envoyer quoi
 * que ce soit : le serveur ne voit rien, et le message ne désigne pas la cause. C'est le même
 * piège que celui documenté sur la liste des en-têtes CORS, côté serveur.
 *
 * # Pourquoi `connect-src` porte deux origines
 *
 * `connect-src` ne déduit **pas** l'origine `ws://` de l'origine `http://` correspondante. Une
 * seule des deux suffirait à couper la moitié du client — les requêtes ou la session temps
 * réel — sans que l'autre ne le signale.
 *
 * # Pas de nonce, et c'est un durcissement
 *
 * Aucun script inline n'est produit par ce build, donc `'self'` seul suffit : il n'autorise que
 * les fichiers de cette origine, là où un nonce autorise ce que le serveur désigne.
 *
 * Ce qu'elle ne corrige toujours pas : le serveur livre ce JavaScript et peut en livrer une
 * version hostile. Aucune politique navigateur ne s'y oppose — seule l'application de bureau,
 * dont le code est empaqueté dans le binaire installé, ferme cette voie.
 */
function csp(api: string): string {
  const websocket = api.replace(/^http/, "ws");

  return [
    "default-src 'self'",
    // `wasm-unsafe-eval` est requis pour instancier le module WebAssembly ; il n'autorise pas
    // `eval()` sur du JavaScript.
    "script-src 'self' 'wasm-unsafe-eval'",
    // Tailwind injecte ses styles à l'exécution. Le risque résiduel d'une injection CSS est sans
    // commune mesure avec celui d'un script.
    "style-src 'self' 'unsafe-inline'",
    `connect-src 'self' ${api} ${websocket}`,
    "img-src 'self' data:",
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
    // **Le réglage qui justifie toute la migration.** Vite injecte par défaut un petit polyfill
    // inline pour `modulepreload` ; le laisser réintroduirait exactement le script inline qu'on
    // vient de supprimer, et avec lui le besoin d'un nonce. Les navigateurs visés le supportent
    // nativement.
    modulePreload: { polyfill: false },

    // Le module WebAssembly est déjà compressé et fait plus d'un mégaoctet : l'avertissement
    // n'apprendrait rien, il masquerait ceux qui comptent.
    chunkSizeWarningLimit: 2048,
  },
}));
