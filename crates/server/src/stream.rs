//! Diffusion temps réel vers les clients connectés.
//!
//! # Ce que ce module change pour la vie privée
//!
//! Contre-intuitivement, il en **retire**. Le client relevait jusqu'ici sa boîte toutes les
//! 1,5 seconde, par une requête signée et par conversation : le serveur recevait donc un
//! journal détaillé de qui était éveillé, à la seconde près, pour chaque groupe. Une connexion
//! longue remplace ce flux par un seul point d'observation à l'ouverture.
//!
//! # Ce qui ne transite pas ici
//!
//! Aucun contenu. Un événement `envelope` ne porte que le numéro de séquence : le client va
//! ensuite chercher l'enveloppe par le chemin normal, qui revérifie son appartenance et
//! applique la pagination. Dupliquer ce chemin dans la diffusion aurait dupliqué son contrôle
//! d'accès — et c'est la copie oubliée qui devient la faille.
//!
//! # Rien n'est stocké
//!
//! Les signaux éphémères (indicateur de frappe) passent par ce hub **et n'atteignent jamais
//! le disque**. C'est la propriété qui justifie son existence : `envelopes` n'est jamais
//! purgée, et on ne peut pas la purger après coup sans trouer le ratchet applicatif.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

/// Profondeur de la file par groupe.
///
/// Un client trop lent est distancé plutôt que de faire grossir la mémoire du serveur.
/// L'événement perdu n'est pas une perte de données : la relève périodique le rattrape, et
/// c'est précisément pourquoi la diffusion peut se permettre d'être négligente.
const CAPACITY: usize = 64;

/// Ce qu'un abonné reçoit.
#[derive(Clone, Debug)]
pub enum Notice {
    /// Une enveloppe a été déposée. Ne porte **que** le numéro de séquence.
    Envelope { group_id: Vec<u8>, seq: i64 },
    /// Un signal éphémère, opaque, relayé tel quel et jamais écrit.
    Signal { group_id: Vec<u8>, payload: Vec<u8> },
}

/// Table des groupes ayant au moins un auditeur.
#[derive(Default)]
pub struct Hub {
    channels: Mutex<HashMap<Vec<u8>, broadcast::Sender<Notice>>>,
}

impl Hub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Ouvre une écoute sur un groupe, en créant le canal s'il n'existait pas.
    pub fn subscribe(&self, group_id: &[u8]) -> broadcast::Receiver<Notice> {
        let mut channels = self.channels.lock().expect("hub empoisonné");
        channels
            .entry(group_id.to_vec())
            .or_insert_with(|| broadcast::channel(CAPACITY).0)
            .subscribe()
    }

    /// Diffuse aux auditeurs du groupe concerné.
    ///
    /// L'absence d'auditeur n'est pas une erreur : c'est le cas courant, et il sert au
    /// nettoyage. Sans cette suppression, un serveur de longue durée garderait un canal par
    /// groupe ayant jamais été écouté — une fuite lente et silencieuse.
    pub fn publish(&self, notice: Notice) {
        let group_id = match &notice {
            Notice::Envelope { group_id, .. } | Notice::Signal { group_id, .. } => group_id.clone(),
        };

        let mut channels = self.channels.lock().expect("hub empoisonné");
        if let Some(sender) = channels.get(&group_id)
            && sender.send(notice).is_err()
        {
            channels.remove(&group_id);
        }
    }

    /// Nombre de groupes actuellement écoutés. Sert aux tests, pas au fonctionnement.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.channels.lock().expect("hub empoisonné").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn un_abonne_recoit_ce_qui_est_publie_dans_son_groupe() {
        let hub = Hub::new();
        let mut alice = hub.subscribe(b"groupe-a");

        hub.publish(Notice::Envelope { group_id: b"groupe-a".to_vec(), seq: 7 });

        match alice.recv().await.expect("le canal reste ouvert") {
            Notice::Envelope { seq, .. } => assert_eq!(seq, 7),
            autre => panic!("attendu une enveloppe, reçu {autre:?}"),
        }
    }

    #[tokio::test]
    async fn un_abonne_ne_recoit_rien_des_autres_groupes() {
        let hub = Hub::new();
        let mut alice = hub.subscribe(b"groupe-a");

        hub.publish(Notice::Envelope { group_id: b"groupe-b".to_vec(), seq: 1 });

        // `try_recv` plutôt qu'un délai : l'absence doit être constatée, pas attendue.
        assert!(alice.try_recv().is_err(), "le cloisonnement par groupe est la seule barrière");
    }

    #[test]
    fn un_groupe_sans_auditeur_est_oublie() {
        let hub = Hub::new();
        drop(hub.subscribe(b"groupe-a"));
        assert_eq!(hub.tracked(), 1);

        hub.publish(Notice::Envelope { group_id: b"groupe-a".to_vec(), seq: 1 });

        assert_eq!(hub.tracked(), 0, "sinon un serveur de longue durée fuit un canal par groupe");
    }
}
