//! Application de bureau et mobile.
//!
//! # Pourquoi une bibliothèque et pas seulement un binaire
//!
//! Sur mobile, il n'y a pas de `main` : c'est le système qui démarre l'activité Android ou
//! l'application iOS, et le code Rust est chargé comme **bibliothèque native**. Tauri compile
//! donc la crate avec `--lib`, et une crate qui n'expose qu'un binaire échoue avec
//! `no library targets found` — au bout de plusieurs minutes de compilation croisée, ce qui rend
//! le diagnostic d'autant plus tardif.
//!
//! D'où cette structure : toute la logique vit ici, et `main.rs` n'est qu'un point d'entrée de
//! bureau qui l'appelle. C'est la convention de Tauri 2, et elle n'est pas cosmétique.
//!
//! # Ce que cette application change dans le modèle de menace
//!
//! Le README répète, à propos du client web, une réserve qu'aucune politique navigateur ne lève :
//! **le serveur livre le JavaScript, et peut en livrer une version qui exfiltre les clés.** La
//! Content-Security-Policy n'y peut rien — elle contraint ce que le code peut faire, pas qui
//! l'écrit.
//!
//! Ici, l'interface est empaquetée dans le binaire installé. Le serveur ne la livre plus, donc il
//! ne peut plus la remplacer. C'est la seule façon connue de fermer cette voie, et c'est ce qui
//! justifie l'existence de cette application — bien plus que le confort d'une fenêtre native.
//!
//! Ce que cela déplace plutôt que supprimer : la confiance va désormais au canal de distribution
//! du binaire. C'est à quoi répond la publication vérifiable de `scripts/release.sh` — build
//! reproductible d'abord, signature ensuite.
//!
//! # Ce que cela ne change pas encore
//!
//! La cryptographie tourne toujours en WebAssembly, dans la webview, exactement comme sur le web.
//! Les clés privées vivent donc dans la mémoire linéaire du module, accessible au JavaScript de
//! la page. Les faire passer côté Rust natif — où `zeroize` s'applique vraiment et où le
//! JavaScript n'a aucun accès — demande de rendre asynchrone chaque appel crypto du client, et
//! reste à faire. Tant que ce n'est pas fait, l'écrire ici évite de croire la propriété acquise.

/// Démarre l'application.
///
/// `mobile_entry_point` génère le symbole que l'activité Android et l'application iOS cherchent
/// au chargement de la bibliothèque. Sans lui, la compilation réussit et le lancement échoue —
/// la pire des deux façons d'échouer.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("l'application n'a pas pu démarrer");
}
