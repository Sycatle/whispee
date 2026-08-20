use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RatchetError {
    #[error("signature du signed prekey invalide")]
    BadPreKeySignature,

    #[error("échec du déchiffrement (clé, nonce ou données associées incorrectes)")]
    DecryptionFailed,

    #[error("message trop ancien : la clé a déjà été consommée et effacée")]
    MessageKeyGone,

    #[error("saut de {0} messages refusé (limite : {1})")]
    TooManySkipped(u32, u32),

    #[error("message reçu avant l'établissement de la session")]
    NoSession,

    #[error("encodage invalide : {0}")]
    Malformed(&'static str),
}
