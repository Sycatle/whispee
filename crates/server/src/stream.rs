//! Diffusion temps réel vers les clients connectés.
//!
//! # Ce que ce module change pour la vie privée
//!
//! Il en **retire** plus qu'il n'en ajoute, ce qui n'est pas la même chose que de ne rien
//! ajouter. Le client relevait jusqu'ici sa boîte toutes les 1,5 seconde, par une requête signée
//! et par conversation : le serveur recevait donc un journal détaillé de qui était éveillé, à la
//! seconde près, pour chaque groupe. Une connexion longue remplace ce flux par un seul point
//! d'observation à l'ouverture.
//!
//! Le solde s'est réduit depuis : ce flux est aussi le battement qui alimente le registre de
//! présence (`crate::presence`). Une observation par minute et par appareil, au lieu d'une par
//! seconde et par groupe, reste un progrès net — mais l'affirmation « il ne fait que retirer »
//! n'est plus exacte, et la laisser telle quelle serait un confort d'écriture.
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
//!
//! Une réserve depuis [`Hub::attach`] : la diffusion inter-instances fait traverser les signaux
//! par `pg_notify`. Ils n'y sont pas écrits en table — la file de notification vit en mémoire
//! partagée — mais un déploiement réglé sur `log_statement = all` les verrait passer dans ses
//! journaux. La propriété « rien n'atteint le disque » dépend donc désormais d'un réglage de la
//! base, ce qui n'est pas la même chose que d'être vraie par construction.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::{broadcast, mpsc};

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

/// Canal Postgres par lequel les instances se parlent.
///
/// Un seul canal pour tout le serveur, pas un par groupe : `LISTEN` s'exerce par canal, et
/// écouter dynamiquement un canal par groupe sur chaque instance annulerait le bénéfice — on
/// aurait remplacé une table en mémoire par autant de `LISTEN` à tenir synchronisés.
const CANAL: &str = "wac_notice";

/// Plafond du payload d'un `NOTIFY`, moins une marge.
///
/// Postgres refuse au-delà de 8000 octets. La marge absorbe l'encodage JSON autour du contenu ;
/// le test `un_signal_maximal_tient_dans_le_payload_notify` gèle le calcul, sans quoi un
/// relèvement de `MAX_SIGNAL_BYTES` casserait la diffusion inter-instances **des seuls gros
/// signaux**, c'est-à-dire de façon parfaitement silencieuse.
const NOTIFY_MAX: usize = 7800;

/// Profondeur de la file de sortie vers les autres instances.
///
/// Même philosophie que `CAPACITY` : si le relais prend du retard, on jette plutôt que de faire
/// grossir la mémoire. Un événement perdu se rattrape par la relève.
const RELAY_CAPACITY: usize = 1024;

/// Représentation d'un `Notice` sur le fil Postgres.
///
/// Champs courts : le plafond de 8000 octets est la contrainte, et un nom de champ verbeux le
/// consomme pour rien.
#[derive(Serialize, Deserialize)]
#[serde(tag = "k")]
enum Wire {
    #[serde(rename = "e")]
    Envelope { g: String, s: i64 },
    #[serde(rename = "s")]
    Signal { g: String, p: String },
}

impl Wire {
    fn from(notice: &Notice) -> Self {
        match notice {
            Notice::Envelope { group_id, seq } => {
                Self::Envelope { g: hex::encode(group_id), s: *seq }
            }
            Notice::Signal { group_id, payload } => {
                Self::Signal { g: hex::encode(group_id), p: BASE64_STANDARD.encode(payload) }
            }
        }
    }

    fn into_notice(self) -> Option<Notice> {
        match self {
            Self::Envelope { g, s } => {
                Some(Notice::Envelope { group_id: hex::decode(g).ok()?, seq: s })
            }
            Self::Signal { g, p } => Some(Notice::Signal {
                group_id: hex::decode(g).ok()?,
                payload: BASE64_STANDARD.decode(p).ok()?,
            }),
        }
    }
}

/// Table des groupes ayant au moins un auditeur.
#[derive(Default)]
pub struct Hub {
    channels: Mutex<HashMap<Vec<u8>, broadcast::Sender<Notice>>>,
    /// Sortie vers les autres instances, quand [`Hub::attach`] l'a branchée.
    ///
    /// `None` tant qu'elle ne l'est pas : un hub non branché diffuse localement et rien de plus,
    /// ce qui est exactement le comportement d'avant et ce dont les tests unitaires ont besoin.
    relay: Mutex<Option<mpsc::Sender<Notice>>>,
}

impl Hub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Branche le hub sur Postgres : ce qui est publié ici part vers les autres instances, et
    /// ce qu'elles publient arrive ici.
    ///
    /// # Pourquoi `LISTEN/NOTIFY` plutôt qu'un bus dédié
    ///
    /// Parce que le `Hub` en mémoire est le plafond dur de ce serveur — deux instances donnent
    /// deux populations de clients qui ne se voient pas — et que le lever ne justifie pas
    /// d'ajouter un service à déployer, à surveiller et à faire figurer dans le modèle de
    /// menace. La base est déjà là, et la diffusion est déjà best-effort.
    ///
    /// # Ce que le serveur apprend, et qui ne l'apprend pas
    ///
    /// Le `group_id` transite en clair dans le payload. Le serveur le connaît déjà par
    /// `group_members` : rien de nouveau ne fuit vers lui. Ce qui est nouveau, c'est qu'il
    /// apparaîtra dans les journaux Postgres d'un déploiement réglé sur `log_statement = all`.
    ///
    /// **Doit être appelée depuis un runtime tokio**, dont elle détache deux tâches.
    pub fn attach(self: &Arc<Self>, pool: PgPool) {
        let (sender, mut receiver) = mpsc::channel::<Notice>(RELAY_CAPACITY);
        *self.relay.lock().expect("hub empoisonné") = Some(sender);

        // Sortie : ce que cette instance publie part vers les autres.
        let emission = pool.clone();
        tokio::spawn(async move {
            while let Some(notice) = receiver.recv().await {
                let payload = serde_json::to_string(&Wire::from(&notice))
                    .expect("un Notice est toujours sérialisable");

                // Au-delà du plafond, on renonce à la diffusion inter-instances plutôt que de
                // laisser Postgres refuser la requête. Seuls les signaux peuvent atteindre cette
                // taille, et un signal perdu est sans conséquence — une enveloppe, elle, ne
                // porte qu'un numéro de séquence et ne peut pas approcher la limite.
                if payload.len() > NOTIFY_MAX {
                    tracing::debug!(taille = payload.len(), "notice trop volumineuse pour NOTIFY");
                    continue;
                }

                if let Err(error) = sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(CANAL)
                    .bind(&payload)
                    .execute(&emission)
                    .await
                {
                    tracing::debug!(%error, "diffusion inter-instances échouée");
                }
            }
        });

        // Entrée : ce que les autres instances publient arrive ici.
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        tracing::debug!(%error, "écoute inter-instances indisponible");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };

                if let Err(error) = listener.listen(CANAL).await {
                    tracing::debug!(%error, "LISTEN refusé");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }

                // `recv` reconnecte tout seul en cas de coupure, mais rend la main sur erreur
                // définitive : la boucle extérieure rouvre alors une écoute. Sans elle, une
                // instance survivrait à un redémarrage de la base en ayant cessé d'entendre les
                // autres, silencieusement.
                while let Ok(notification) = listener.recv().await {
                    let Ok(wire) = serde_json::from_str::<Wire>(notification.payload()) else {
                        continue;
                    };

                    if let Some(notice) = wire.into_notice() {
                        hub.publish_local(notice);
                    }
                }
            }
        });
    }

    /// Ouvre une écoute sur un groupe, en créant le canal s'il n'existait pas.
    pub fn subscribe(&self, group_id: &[u8]) -> broadcast::Receiver<Notice> {
        let mut channels = self.channels.lock().expect("hub empoisonné");
        channels
            .entry(group_id.to_vec())
            .or_insert_with(|| broadcast::channel(CAPACITY).0)
            .subscribe()
    }

    /// Diffuse aux auditeurs de cette instance **et** des autres.
    ///
    /// C'est le point d'entrée des handlers. Le relais est best-effort : si sa file est pleine,
    /// l'événement reste local. Bloquer ici ferait payer à un dépôt d'enveloppe le retard d'une
    /// diffusion dont `crate::stream` documente déjà qu'elle est négligeable.
    pub fn publish(&self, notice: Notice) {
        if let Some(relay) = self.relay.lock().expect("hub empoisonné").as_ref()
            && relay.try_send(notice.clone()).is_err()
        {
            tracing::debug!("relais inter-instances saturé");
        }

        self.publish_local(notice);
    }

    /// Diffuse aux seuls auditeurs de cette instance.
    ///
    /// Appelée par l'écoute Postgres. Sans cette porte séparée, un événement reçu d'une autre
    /// instance serait re-notifié par celle-ci, et les instances se le renverraient
    /// indéfiniment.
    ///
    /// L'absence d'auditeur n'est pas une erreur : c'est le cas courant, et il sert au
    /// nettoyage. Sans cette suppression, un serveur de longue durée garderait un canal par
    /// groupe ayant jamais été écouté — une fuite lente et silencieuse.
    fn publish_local(&self, notice: Notice) {
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

    /// **Le test qui empêche une régression silencieuse du fanout.**
    ///
    /// Postgres refuse un `NOTIFY` de plus de 8000 octets. Un relèvement de `MAX_SIGNAL_BYTES`
    /// ne casserait donc pas la diffusion — il la casserait pour les seuls signaux volumineux,
    /// c'est-à-dire d'une façon qu'aucun test fonctionnel ne rattraperait.
    #[test]
    fn un_signal_maximal_tient_dans_le_payload_notify() {
        // Le pire cas des deux champs à la fois : un groupe à l'identifiant le plus long que
        // `decode_group_id` accepte, et un signal au plafond.
        let notice = Notice::Signal {
            group_id: vec![0xab; 64],
            payload: vec![0u8; crate::routes::MAX_SIGNAL_BYTES],
        };

        let encode = serde_json::to_string(&Wire::from(&notice)).expect("sérialisable");

        assert!(
            encode.len() <= NOTIFY_MAX,
            "un signal au plafond fait {} octets, au-delà des {NOTIFY_MAX} tenables",
            encode.len(),
        );
    }

    /// Le format du fil est un aller-retour fidèle.
    ///
    /// Une asymétrie ici ferait diverger ce que voient les clients d'une instance de ce que
    /// voient ceux d'une autre — le genre de bug qui ne se manifeste qu'en production, où il y a
    /// plus d'une instance.
    #[test]
    fn le_format_du_fil_fait_l_aller_retour() {
        for original in [
            Notice::Envelope { group_id: b"groupe-a".to_vec(), seq: 42 },
            Notice::Signal { group_id: b"groupe-a".to_vec(), payload: vec![1, 2, 3] },
        ] {
            let encode = serde_json::to_string(&Wire::from(&original)).expect("sérialisable");
            let decode: Wire = serde_json::from_str(&encode).expect("relisible");

            match (original, decode.into_notice().expect("convertible")) {
                (
                    Notice::Envelope { group_id: a, seq: x },
                    Notice::Envelope { group_id: b, seq: y },
                ) => {
                    assert_eq!((a, x), (b, y));
                }
                (
                    Notice::Signal { group_id: a, payload: x },
                    Notice::Signal { group_id: b, payload: y },
                ) => {
                    assert_eq!((a, x), (b, y));
                }
                (avant, apres) => panic!("le type a changé : {avant:?} devenu {apres:?}"),
            }
        }
    }

    /// Un hub non branché ne fait que du local, et ne panique pas de ne pas avoir de relais.
    ///
    /// C'est ce qui permet aux tests unitaires ci-dessus d'exister sans base de données, et à
    /// `publish` de rester une fonction synchrone appelable depuis n'importe quel handler.
    #[tokio::test]
    async fn un_hub_non_branche_diffuse_quand_meme_localement() {
        let hub = Hub::new();
        let mut alice = hub.subscribe(b"groupe-a");

        hub.publish(Notice::Envelope { group_id: b"groupe-a".to_vec(), seq: 1 });

        assert!(alice.recv().await.is_ok());
    }
}
