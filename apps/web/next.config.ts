import type { NextConfig } from "next";

const config: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          // La CSP est posée par `src/middleware.ts` : elle a besoin d'un nonce par
          // requête, que la configuration statique ne peut pas produire.
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          // Aucune de ces API n'est utilisée : les refuser réduit ce qu'un script injecté
          // pourrait atteindre.
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
          },
        ],
      },
    ];
  },
};

export default config;
