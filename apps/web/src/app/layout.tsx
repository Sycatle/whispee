import type { Metadata } from "next";
import "./globals.css";

/**
 * Rendu dynamique obligatoire.
 *
 * La CSP de `src/middleware.ts` porte un nonce par requête, et Next ne peut pas l'injecter
 * dans un HTML prégénéré au build. Avec `'strict-dynamic'`, un script sans nonce est bloqué
 * — et `'self'` est ignoré dès que `'strict-dynamic'` est présent — donc une page statique
 * n'exécuterait aucun script du tout.
 *
 * Le coût est nul ici : toute l'application est cliente, il n'y a rien à prégénérer.
 */
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "whatsapp_clone — messagerie chiffrée de bout en bout",
  description: "Démonstration MLS (RFC 9420). Projet d'apprentissage, non audité.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body className="min-h-dvh antialiased">{children}</body>
    </html>
  );
}
