/**
 * Neutralise le chemin par défaut du glue généré par wasm-bindgen.
 *
 * wasm-bindgen émet `new URL('crypto_wasm_bg.wasm', import.meta.url)` comme valeur de repli.
 * Ce chemin n'est jamais emprunté — `loadCrypto()` passe toujours une URL explicite — mais
 * les bundlers l'analysent statiquement et échouent à résoudre le fichier, qui vit dans
 * `public/` et non à côté du module.
 *
 * On le remplace par une erreur parlante plutôt que de le supprimer : si quelqu'un appelle
 * un jour `init()` sans argument, il doit obtenir un message clair, pas un échec obscur.
 */
import { readFileSync, writeFileSync } from "node:fs";

const FILE = "src/lib/generated/crypto_wasm.js";
const NEEDLE = "module_or_path = new URL('crypto_wasm_bg.wasm', import.meta.url);";
const REPLACEMENT =
  "throw new Error('Le chemin du module WASM est obligatoire — voir loadCrypto() dans src/lib/wasm.ts');";

const source = readFileSync(FILE, "utf8");

if (!source.includes(NEEDLE)) {
  if (source.includes(REPLACEMENT)) process.exit(0);
  // Une montée de version de wasm-bindgen a changé le glue : mieux vaut casser le build
  // bruyamment que de laisser passer un patch devenu silencieusement inopérant.
  console.error(`Motif introuvable dans ${FILE} — le glue wasm-bindgen a changé.`);
  process.exit(1);
}

writeFileSync(FILE, source.replace(NEEDLE, REPLACEMENT));
