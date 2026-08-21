//! Desktop entry point.
//!
//! Deliberately empty of logic: everything lives in the library, because mobile has no `main` and
//! loads the crate as a native library. See the header of `lib.rs`.

// On Windows, a desktop binary must not open a console behind its window. No effect elsewhere.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    desktop_lib::run()
}
