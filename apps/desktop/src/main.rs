//! Application de bureau.
//!
//! # Ce qu'elle change dans le modèle de menace, et c'est le point principal
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
//! du binaire. Une mise à jour non signée, ou signée par une clé volée, reproduit exactement le
//! problème. Ce projet ne fournit ni signature ni mise à jour automatique, et le prétendre serait
//! pire que de ne pas le faire.
//!
//! # Ce qu'elle ne change pas encore
//!
//! La cryptographie tourne toujours en WebAssembly, dans la webview, exactement comme sur le web.
//! Les clés privées vivent donc dans la mémoire linéaire du module, accessible au JavaScript de
//! la page. Les faire passer côté Rust natif — où `zeroize` s'applique vraiment et où le
//! JavaScript n'a aucun accès — demande de rendre asynchrone chaque appel crypto du client, et
//! reste à faire. Tant que ce n'est pas fait, l'écrire ici évite de croire la propriété acquise.

// Sur Windows, un binaire de bureau ne doit pas ouvrir de console derrière sa fenêtre. Sans
// effet ailleurs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("l'application de bureau n'a pas pu démarrer");
}
