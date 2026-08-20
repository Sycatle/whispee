use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    /// Erreur remontée par OpenMLS. Le détail est aplati en chaîne : les variantes d'erreur
    /// d'OpenMLS sont nombreuses et instables entre versions mineures, et les distinguer
    /// n'apporterait rien au code appelant, qui ne peut de toute façon que rejeter le message.
    #[error("opération MLS refusée : {0}")]
    Mls(String),

    #[error("message mal formé : {0}")]
    Malformed(&'static str),

    /// Reçu un type de message MLS là où un autre était attendu. Peut être bénin (message
    /// en retard) comme hostile (tentative de confusion de type).
    #[error("type de message inattendu")]
    UnexpectedMessage,

    #[error("état de session illisible : {0}")]
    Storage(String),

    /// Le membre visé n'est pas dans l'arbre du groupe.
    ///
    /// Cas courant et bénin : deux membres retirent le même appareil en même temps, le second
    /// commit arrive après que le premier a déjà été appliqué. L'appelant doit le traiter
    /// comme un succès — l'état voulu est atteint — et non comme une erreur à réessayer.
    #[error("membre absent du groupe")]
    UnknownMember,

    /// Le commit reçu est cryptographiquement valide mais viole la politique du groupe.
    ///
    /// Distincte de [`CryptoError::Mls`] parce qu'elle ne dit pas la même chose : MLS a
    /// accepté le message, c'est **nous** qui refusons de l'appliquer. Le groupe est intact,
    /// et l'émetteur se retrouve seul avec son epoch. Voir `roles.rs`.
    #[error("commit refusé par la politique du groupe : {0}")]
    PolicyViolation(&'static str),
}

pub(crate) fn mls<E: std::fmt::Display>(err: E) -> CryptoError {
    CryptoError::Mls(err.to_string())
}

pub type Result<T> = std::result::Result<T, CryptoError>;
