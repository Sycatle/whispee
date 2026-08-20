//! # ratchet-lab
//!
//! Réimplémentation pédagogique de X3DH et du Double Ratchet.
//!
//! ## Pourquoi cette crate existe
//!
//! Comprendre pourquoi un protocole est construit ainsi demande de l'écrire. Chaque module
//! documente non pas ce que fait le code — ça se lit — mais quelle attaque chaque étape
//! écarte, et ce qu'elle n'écarte pas.
//!
//! ## Pourquoi elle ne doit jamais tourner en production
//!
//! * aucun audit ;
//! * aucune résistance aux canaux auxiliaires (comparaisons non constant-time hors des
//!   primitives sous-jacentes, allocations dépendantes du secret) ;
//! * pas de multi-device, pas de groupes, pas de résistance quantique ;
//! * la persistance de l'état de session, où se logent la plupart des bugs exploitables,
//!   n'est pas traitée.
//!
//! Le chemin de production du projet passe exclusivement par OpenMLS, dans `crypto-core`.
//! Rien ici ne doit être importé par cette crate — et l'absence de dépendance vers
//! `ratchet-lab` dans le manifeste de `crypto-core` est un invariant à préserver.
//!
//! ## Ce que le protocole ne protège pas
//!
//! Même correctement implémenté, il ne cache **pas** qui parle à qui, quand, à quelle
//! fréquence, ni la taille des messages. Ces métadonnées sont souvent plus révélatrices
//! que le contenu.

pub mod error;
pub mod kdf;
pub mod keys;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use error::RatchetError;
pub use keys::{IdentityKeyPair, IdentityPublic, PreKeyBundle, PreKeyStore};
pub use ratchet::{Header, Message};
pub use session::{Session, safety_number};
pub use x3dh::InitialMessage;
