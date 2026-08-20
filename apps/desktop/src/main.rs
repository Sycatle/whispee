//! Point d'entrée de bureau.
//!
//! Volontairement vide de logique : tout vit dans la bibliothèque, parce que le mobile n'a pas de
//! `main` et charge la crate comme bibliothèque native. Voir l'en-tête de `lib.rs`.

// Sur Windows, un binaire de bureau ne doit pas ouvrir de console derrière sa fenêtre. Sans
// effet ailleurs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    desktop_lib::run()
}
