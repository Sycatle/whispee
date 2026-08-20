import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Content-Security-Policy avec un nonce par requête.
 *
 * Next injecte des scripts inline (amorçage, streaming RSC). Les autoriser via
 * `'unsafe-inline'` reviendrait à autoriser *tout* script inline, y compris celui qu'une
 * injection ferait passer — ce qui vide la CSP de son intérêt. Un nonce n'autorise que les
 * scripts que le serveur a lui-même émis.
 *
 * Next lit l'en-tête CSP de la requête et propage automatiquement le nonce à ses balises.
 *
 * # Ce que cela protège, et ce que cela ne protège pas
 *
 * Cela réduit la surface d'injection : pas de script tiers, pas d'`eval`, pas de connexion
 * sortante hors de l'API. Cela ne corrige **pas** la faiblesse structurelle du web — le
 * serveur livre ce JavaScript et peut en livrer une version hostile, signée de son propre
 * nonce. Aucune politique navigateur ne s'y oppose.
 */
export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const dev = process.env.NODE_ENV === "development";

  const api = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8787";

  // La session temps réel est une WebSocket, et `connect-src` ne déduit **pas** l'origine
  // `ws://` de l'origine `http://` correspondante : sans cette ligne, la gateway est bloquée en
  // production et nulle part ailleurs — le développement autorisant `ws:` en bloc. C'est la
  // panne silencieuse type, puisque tout le reste continue de fonctionner par la relève.
  const websocket = api.replace(/^http/, "ws");

  const csp = [
    "default-src 'self'",
    // `wasm-unsafe-eval` est requis pour instancier le module WebAssembly ; il n'autorise
    // pas `eval()` sur du JavaScript. `unsafe-eval` n'est concédé qu'au HMR en développement.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'${dev ? " 'unsafe-eval'" : ""}`,
    // Tailwind injecte ses styles à l'exécution ; un nonce sur les styles casserait le rendu.
    // Le risque résiduel d'une injection CSS est sans commune mesure avec celui d'un script.
    "style-src 'self' 'unsafe-inline'",
    `connect-src 'self' ${api} ${websocket}${dev ? " ws: http:" : ""}`,
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; ");

  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers } });
  response.headers.set("content-security-policy", csp);
  return response;
}

export const config = {
  matcher: [
    // Les assets statiques n'exécutent pas de script : les exclure évite de recalculer un
    // nonce pour chaque fichier et garde leur mise en cache intacte.
    {
      source: "/((?!_next/static|_next/image|favicon.ico|.*\\.wasm$).*)",
      missing: [{ type: "header", key: "next-router-prefetch" }],
    },
  ],
};
