//! Verrou local : dérivation d'une clé à partir d'un mot de passe.
//!
//! # Ce que ce verrou protège, et ce qu'il ne protège pas
//!
//! Il protège l'état au repos sur **cet appareil** : sans le mot de passe, l'état MLS et la
//! graine du compte restent des octets illisibles, y compris pour qui obtient la base
//! IndexedDB ou le disque.
//!
//! Il ne protège **pas** contre un appareil compromis pendant qu'il est déverrouillé, et il
//! n'est **pas** un facteur de récupération : l'oublier ne fait rien perdre, la phrase de
//! douze mots reste le seul chemin de restauration. C'est délibéré — faire du mot de passe un
//! second facteur du coffre doublerait la surface de perte pour un gain nul contre le serveur.
//!
//! # Pourquoi Argon2id plutôt que PBKDF2
//!
//! Un mot de passe humain a rarement plus de 40 bits d'entropie. La seule défense est de
//! rendre chaque essai coûteux — et coûteux **en mémoire**, sinon un attaquant parallélise sur
//! GPU pour quelques centimes le milliard d'essais. PBKDF2, disponible dans WebCrypto, ne
//! coûte que du calcul : c'est précisément ce que le matériel dédié fait le mieux.
//!
//! Argon2id impose 64 Mio par essai, ce qui ramène un GPU au niveau d'un processeur. Il
//! n'existe pas dans WebCrypto, d'où cette dérivation côté Rust.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{CryptoError, Result};

/// Coût mémoire, en kibioctets. 64 Mio : le seuil au-delà duquel une attaque GPU perd son
/// avantage, et qui reste supportable sur un téléphone d'entrée de gamme.
const MEMORY_KIB: u32 = 64 * 1024;

/// Nombre de passes. Trois est la recommandation du RFC 9106 pour ce coût mémoire.
const ITERATIONS: u32 = 3;

/// Parallélisme. Un seul brin : WebAssembly n'a pas de threads par défaut, et en annoncer
/// plusieurs produirait une dérivation différente de celle effectivement calculée.
const LANES: u32 = 1;

/// Longueur du sel. Aléatoire par appareil, stocké en clair à côté de l'état : son rôle est
/// d'interdire les tables précalculées, pas de rester secret.
pub const SALT_LEN: usize = 16;

/// Dérive la clé de déverrouillage depuis un mot de passe.
///
/// Coûte environ une seconde et 64 Mio. C'est voulu : ce coût est payé une fois par
/// déverrouillage par l'utilisateur, et à chaque essai par un attaquant.
pub fn derive_unlock_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::Malformed("sel de longueur inattendue"));
    }

    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32))
        .map_err(|_| CryptoError::Malformed("paramètres Argon2 invalides"))?;

    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::Malformed("dérivation du verrou impossible"))?;

    Ok(key)
}
