//! X3DH — établissement de session asynchrone.
//!
//! Le point clé : Alice dérive un secret partagé avec Bob **sans que Bob soit en ligne**,
//! en n'utilisant que le bundle qu'il a laissé sur le serveur. C'est ce qui rend la
//! messagerie asynchrone possible ; tout le reste du protocole en découle.
//!
//! Chacun des quatre DH a un rôle distinct :
//!   DH1 = IK_A · SPK_B  authentifie Alice auprès de Bob
//!   DH2 = EK_A · IK_B   authentifie Bob auprès d'Alice
//!   DH3 = EK_A · SPK_B  apporte la forward secrecy
//!   DH4 = EK_A · OPK_B  renforce la FS du tout premier message (si une OPK est disponible)
//!
//! Aucun DH n'est signé : le secret n'est prouvable par personne d'autre que les deux
//! participants. C'est la *deniability*, et c'est délibéré.

use rand_core::{CryptoRng, RngCore};
use x25519_dalek::PublicKey;

use crate::error::RatchetError;
use crate::kdf::{RootKey, kdf_x3dh};
use crate::keys::{EphemeralKeyPair, IdentityKeyPair, IdentityPublic, PreKeyBundle, PreKeyStore};

/// Ce qu'Alice joint à son premier message pour que Bob puisse rejouer le même calcul.
#[derive(Clone)]
#[derive(Debug)]
pub struct InitialMessage {
    pub identity: IdentityPublic,
    pub ephemeral: PublicKey,
    /// Indique à Bob s'il doit inclure sa one-time prekey dans le calcul.
    pub used_one_time_prekey: bool,
}

pub struct X3dhOutcome {
    pub shared_secret: RootKey,
    /// Liées à chaque message via l'AEAD : un attaquant ne peut pas rejouer un chiffré
    /// dans une conversation entre d'autres identités.
    pub associated_data: Vec<u8>,
}

fn associated_data(initiator: &IdentityPublic, responder: &IdentityPublic) -> Vec<u8> {
    let mut ad = Vec::with_capacity(128);
    ad.extend_from_slice(&initiator.encode());
    ad.extend_from_slice(&responder.encode());
    ad
}

/// Côté Alice.
pub fn initiate<R: RngCore + CryptoRng>(
    rng: &mut R,
    identity: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<(X3dhOutcome, InitialMessage), RatchetError> {
    // Sans cette vérification, un serveur malveillant substitue sa propre signed prekey
    // et lit toute la conversation.
    bundle.verify()?;

    let ephemeral = EphemeralKeyPair::generate(rng);

    let mut dhs = vec![
        identity.dh.diffie_hellman(&bundle.signed_prekey).to_bytes(),
        ephemeral.secret.diffie_hellman(&bundle.identity.dh).to_bytes(),
        ephemeral.secret.diffie_hellman(&bundle.signed_prekey).to_bytes(),
    ];
    if let Some(opk) = &bundle.one_time_prekey {
        dhs.push(ephemeral.secret.diffie_hellman(opk).to_bytes());
    }

    let shared_secret = kdf_x3dh(&dhs);
    let outcome = X3dhOutcome {
        shared_secret,
        associated_data: associated_data(&identity.public(), &bundle.identity),
    };
    let initial = InitialMessage {
        identity: identity.public(),
        ephemeral: ephemeral.public(),
        used_one_time_prekey: bundle.one_time_prekey.is_some(),
    };

    Ok((outcome, initial))
}

/// Côté Bob. Rejoue les mêmes DH dans le même ordre, chaque paire prise dans l'autre sens.
pub fn respond(store: &PreKeyStore, initial: &InitialMessage) -> Result<X3dhOutcome, RatchetError> {
    let mut dhs = vec![
        store.signed_prekey.secret.diffie_hellman(&initial.identity.dh).to_bytes(),
        store.identity.dh.diffie_hellman(&initial.ephemeral).to_bytes(),
        store.signed_prekey.secret.diffie_hellman(&initial.ephemeral).to_bytes(),
    ];
    if initial.used_one_time_prekey {
        let opk = store
            .one_time_prekey
            .as_ref()
            .ok_or(RatchetError::Malformed("one-time prekey réclamée mais absente"))?;
        dhs.push(opk.secret.diffie_hellman(&initial.ephemeral).to_bytes());
    }

    Ok(X3dhOutcome {
        shared_secret: kdf_x3dh(&dhs),
        associated_data: associated_data(&initial.identity, &store.identity.public()),
    })
}
