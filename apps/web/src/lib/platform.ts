/**
 * Sur quoi tourne-t-on.
 *
 * # Détection au moment de l'exécution, et non au build
 *
 * `apps/web` produit **un seul** `dist/`, servi à la fois par le web et empaqueté dans le binaire
 * de bureau (`frontendDist` dans `tauri.conf.json`). Produire deux bundles distincts imposerait
 * deux constructions, deux chaînes de vérification et deux artefacts à signer, pour trancher un
 * cas que trois octets suffisent à trancher.
 *
 * Le coût assumé : le code natif entre dans le bundle web, où il est mort. Il est petit.
 */

/**
 * Vrai quand la page est servie par Tauri.
 *
 * Teste la présence de l'objet que Tauri injecte dans la webview avant tout script de la page.
 * Volontairement pas `navigator.userAgent`, que les webviews maquillent, ni le protocole, qui
 * diffère selon le système — `tauri://localhost` sur Linux et macOS, `http://tauri.localhost`
 * sur Windows et Android.
 */
export function isTauri(): boolean {
  return "__TAURI_INTERNALS__" in globalThis;
}
