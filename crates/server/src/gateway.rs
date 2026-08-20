//! Session gateway : une connexion, tous les groupes.
//!
//! # Ce que ce module remplace
//!
//! Le flux SSE de `routes::stream`, qui reste en place le temps que les clients migrent. Trois
//! choses que ce flux ne pouvait pas faire, et qui ont chacune un coût réel :
//!
//! * **s'abonner à un groupe rejoint après l'ouverture.** Le SSE fige sa liste au moment de la
//!   connexion ; découvrir un groupe obligeait le client à tout rouvrir.
//! * **rattraper le retard à l'ouverture.** Le client relevait chaque conversation par une
//!   requête signée pour découvrir qu'il n'avait rien manqué. Ici, il annonce ses curseurs et
//!   le serveur ne parle que s'il a quelque chose à dire.
//! * **savoir que le client est parti.** Le keep-alive SSE va du serveur vers le client : un
//!   client disparu reste indistinguable d'un client silencieux, et sa présence continue d'être
//!   écrite.
//!
//! # Ce qui ne transite pas ici
//!
//! Aucun contenu, exactement comme le flux SSE. Une trame `envelope` ne porte que le numéro de
//! séquence ; le client va chercher l'enveloppe par le chemin HTTP normal, qui revérifie son
//! appartenance et applique la pagination. Dupliquer ce chemin ici aurait dupliqué son contrôle
//! d'accès, et c'est la copie oubliée qui devient la faille.
//!
//! # Ce que ce module change dans le modèle de menace
//!
//! **L'authentification passe d'une signature par requête à une signature par session.** C'est
//! le changement à peser, et il coupe dans les deux sens.
//!
//! Ce qu'on gagne : le défi est émis par le serveur et consommé à la première utilisation, donc
//! la fenêtre de rejeu de soixante secondes que documente [`crate::auth`] n'existe pas sur ce
//! chemin.
//!
//! Ce qu'on perd : une session ouverte survit à la révocation de l'appareil qui l'a ouverte, et
//! à son retrait d'un groupe. Une signature par requête faisait cette vérification à chaque
//! appel, gratuitement. C'est pourquoi [`Session::revalidate`] existe et tourne à chaque
//! battement — sans elle, révoquer un appareil ne le couperait de rien tant qu'il garde sa
//! socket ouverte.
//!
//! # Ce que ce module n'authentifie pas, délibérément
//!
//! La trame `signal`. Elle est authentifiée par le MAC de groupe, comme sur le chemin HTTP :
//! le serveur vérifie que l'expéditeur détient la clé de dépôt, donc qu'il est membre, sans
//! apprendre lequel. Lier le signal à l'identité de la session — qui est pourtant connue ici —
//! défairait le sealed sender pour la seule commodité de ne pas revérifier un MAC.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, StreamExt};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio_stream::StreamMap;
use tokio_stream::wrappers::BroadcastStream;

use crate::AppState;
use crate::error::{ApiError, ApiResult};
use crate::stream::{Hub, Notice};

/// Rythme de battement imposé au client, annoncé dans `hello`.
///
/// Il fixe aussi la granularité de [`Session::revalidate`] : une révocation prend effet sur les
/// sessions ouvertes en au plus deux battements. Le raccourcir rendrait la coupure plus vive au
/// prix d'une requête par session et par battement — et ce n'est pas là que se joue la
/// protection, puisqu'un appareil révoqué détient encore les secrets du groupe.
const HEARTBEAT: Duration = Duration::from_secs(30);

/// Silence au-delà duquel la session est fermée.
///
/// Deux battements plus une marge : un client qui perd un battement sur une bascule de réseau
/// ne doit pas être déconnecté pour autant, puisque la reconnexion lui coûterait un défi, une
/// signature et un rattrapage complet.
const SILENCE_MAX: Duration = Duration::from_secs(80);

/// Délai laissé au client pour répondre au défi.
///
/// Court, et c'est le point : une socket non authentifiée ne consomme aucune requête et
/// n'apparaît nulle part, ce qui en fait le moyen le moins cher d'occuper un serveur.
const IDENTIFY_MAX: Duration = Duration::from_secs(10);

/// Plafond d'abonnements simultanés pour une session.
///
/// Chaque abonnement est un `broadcast::Receiver` avec sa file. Sans plafond, un client
/// authentifié fait grossir la mémoire du serveur en s'abonnant en boucle — y compris à des
/// groupes dont il est réellement membre, donc sans rien violer.
const MAX_SUBSCRIPTIONS: usize = 512;

/// Plafond de taille d'une trame, dans les deux sens.
///
/// Vaut avant l'authentification : c'est là qu'il compte, puisque le pair n'a alors rien prouvé.
const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Plafond de curseurs acceptés dans un `identify`.
///
/// **Sans cette borne, une seule trame achète autant de requêtes SQL qu'elle contient d'entrées.**
/// Le filtre d'appartenance ne suffit pas : il écarte les groupes étrangers, mais rien n'empêche
/// de répéter mille fois un groupe dont on est réellement membre. L'amplification est le
/// problème, pas l'accès.
///
/// Aligné sur [`MAX_SUBSCRIPTIONS`] : un client n'a pas de raison d'annoncer un curseur pour un
/// groupe auquel il ne peut pas s'abonner.
const MAX_CURSORS: usize = MAX_SUBSCRIPTIONS;

/// Plafond d'enveloppes annoncées par groupe lors du rattrapage.
///
/// Aligné sur la pagination du chemin HTTP. Un client très en retard reçoit les premières et
/// découvre le reste en paginant : c'est déjà ce que fait la relève normale, et annoncer dix
/// mille séquences d'un coup ne l'aiderait pas à les lire plus vite.
const MAX_RESUME_PER_GROUP: i64 = 200;

/// Trames émises par le client.
///
/// `deny_unknown_fields` n'est **pas** posé : un client plus récent qu'un serveur doit pouvoir
/// ajouter un champ sans que la session soit refusée. Un champ inconnu est ignoré, jamais
/// interprété.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ClientFrame {
    Identify {
        device_id: String,
        /// Le défi reçu dans `hello`, renvoyé tel quel.
        nonce: String,
        signature: String,
        /// Dernière séquence connue par groupe. Absent vaut « je ne sais rien ».
        #[serde(default)]
        cursors: Vec<Cursor>,
    },
    Subscribe {
        group_id: String,
    },
    Unsubscribe {
        group_id: String,
    },
    Heartbeat,
    Signal {
        group_id: String,
        nonce: String,
        mac: String,
        payload: String,
    },
}

#[derive(Deserialize)]
struct Cursor {
    group_id: String,
    seq: i64,
}

/// Trames émises par le serveur.
#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ServerFrame<'a> {
    Hello { heartbeat_ms: u64, nonce: String },
    Ready { groups: Vec<String> },
    Envelope { group_id: String, seq: i64 },
    Signal { group_id: String, payload: String },
    HeartbeatAck,
    /// Motif volontairement grossier : voir [`reason`].
    Error { reason: &'a str },
}

/// Traduit une erreur interne en motif servi au client.
///
/// Les motifs sont délibérément grossiers, pour la même raison que `ApiError` refuse de
/// distinguer « appareil inconnu » de « signature invalide » : la distinction transformerait la
/// gateway en oracle d'énumération. Le détail part dans les traces du serveur, pas sur le fil.
fn reason(error: &ApiError) -> &'static str {
    match error {
        ApiError::BadRequest(_) => "trame invalide",
        ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound => "refusé",
        ApiError::Conflict(_) => "conflit",
        ApiError::Database(err) => {
            tracing::error!(error = %err, "erreur de base de données dans la gateway");
            "erreur interne"
        }
    }
}

type Sender = SplitSink<WebSocket, Message>;

/// Point d'entrée HTTP : bascule la connexion en WebSocket.
///
/// Aucun extracteur authentifiant ici, et c'est délibéré. L'API `WebSocket` du navigateur
/// n'accepte pas d'en-tête personnalisé — même limite qu'`EventSource`, pour laquelle
/// `routes::stream` a déjà dû renoncer. Mettre la signature en paramètre d'URL la ferait
/// atterrir dans les journaux d'accès de tout proxy traversé ; on ouvre donc la socket sans
/// identité et rien n'est servi avant le défi.
pub async fn handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    // **Plafond de taille, avant toute authentification.**
    //
    // Sans lui, la valeur par défaut de tungstenite s'applique : 64 Mio par message. Un pair
    // qui n'a encore rien prouvé peut donc faire allouer 64 Mio, autant de fois qu'il ouvre de
    // sockets. Le chemin HTTP se protège depuis toujours par `RequestBodyLimitLayer` à 1 Mio ;
    // cette route est arrivée sans son équivalent.
    //
    // La borne est large devant ce que le protocole transporte — la plus grosse trame est un
    // `signal`, plafonné à 4 Kio par `MAX_SIGNAL_BYTES`, plus son encodage base64 — et étroite
    // devant ce qu'une machine peut encaisser.
    ws.max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            if let Err(error) = session(state, socket).await {
                tracing::debug!(%error, "session gateway terminée");
            }
        })
}

/// État d'une session authentifiée.
struct Session {
    pool: PgPool,
    hub: Arc<Hub>,
    device_id: String,
    /// Un `BroadcastStream` par groupe écouté. `StreamMap` plutôt que `select_all` : les
    /// abonnements changent pendant la vie de la connexion, et un `select_all` sur `Vec` fige
    /// son contenu à la construction.
    subscriptions: StreamMap<Vec<u8>, BroadcastStream<Notice>>,
}

async fn session(state: AppState, socket: WebSocket) -> Result<(), axum::Error> {
    let (mut sender, mut receiver) = socket.split();

    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);

    send(
        &mut sender,
        &ServerFrame::Hello {
            heartbeat_ms: HEARTBEAT.as_millis() as u64,
            nonce: BASE64_STANDARD.encode(challenge),
        },
    )
    .await?;

    // Rien n'est abonné, rien n'est lu, tant que le défi n'a pas été relevé.
    let identified = tokio::time::timeout(IDENTIFY_MAX, async {
        while let Some(message) = receiver.next().await {
            let Ok(Message::Text(text)) = message else { continue };
            return serde_json::from_str::<ClientFrame>(&text).ok();
        }
        None
    })
    .await;

    let Ok(Some(ClientFrame::Identify { device_id, nonce, signature, cursors })) = identified
    else {
        // Aucun motif : à ce stade le pair n'a rien prouvé, et lui dire ce qui manquait
        // l'aiderait à sonder.
        return sender.close().await;
    };

    let mut session = match authenticate(&state, &device_id, &challenge, &nonce, &signature).await {
        Ok(session) => session,
        Err(error) => {
            let _ = send(&mut sender, &ServerFrame::Error { reason: reason(&error) }).await;
            return sender.close().await;
        }
    };

    let groups = match session.membership().await {
        Ok(groups) => groups,
        Err(error) => {
            let _ = send(&mut sender, &ServerFrame::Error { reason: reason(&error) }).await;
            return sender.close().await;
        }
    };

    for group_id in &groups {
        session.subscribe(group_id.clone());
    }

    send(
        &mut sender,
        &ServerFrame::Ready { groups: groups.iter().map(hex::encode).collect() },
    )
    .await?;

    // Rattrapage. Il vient après `ready` pour que le client ait déjà sa liste de groupes quand
    // les séquences manquées arrivent.
    if let Err(error) = session.resume(&mut sender, &cursors, &groups).await {
        let _ = send(&mut sender, &ServerFrame::Error { reason: reason(&error) }).await;
        return sender.close().await;
    }

    session.pump(sender, receiver).await
}

/// Vérifie le défi et ouvre la session.
async fn authenticate(
    state: &AppState,
    device_id: &str,
    challenge: &[u8],
    nonce: &str,
    signature: &str,
) -> ApiResult<Session> {
    // Le nonce renvoyé doit être **celui qui a été servi**. Le comparer plutôt que de signer
    // aveuglément ce que le client propose est ce qui empêche de rejouer une signature obtenue
    // sur une session précédente.
    let echoed = BASE64_STANDARD.decode(nonce).map_err(|_| ApiError::Unauthorized)?;
    if echoed != challenge {
        return Err(ApiError::Unauthorized);
    }

    // Appareil révoqué : refusé à l'ouverture, et coupé en cours de session par `revalidate`.
    let auth_key: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT auth_key FROM devices WHERE id = $1 AND revoked_at IS NULL")
            .bind(device_id)
            .fetch_optional(&state.pool)
            .await?;

    let (auth_key,) = auth_key.ok_or(ApiError::Unauthorized)?;

    let auth_key: [u8; 32] = auth_key.try_into().map_err(|_| ApiError::Unauthorized)?;
    let auth_key = VerifyingKey::from_bytes(&auth_key).map_err(|_| ApiError::Unauthorized)?;

    let signature = BASE64_STANDARD
        .decode(signature)
        .ok()
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        .map(|bytes| Signature::from_bytes(&bytes))
        .ok_or(ApiError::Unauthorized)?;

    let message =
        attest::gateway_message(device_id, challenge).map_err(|_| ApiError::Unauthorized)?;

    auth_key.verify_strict(&message, &signature).map_err(|_| ApiError::Unauthorized)?;

    Ok(Session {
        pool: state.pool.clone(),
        hub: state.hub.clone(),
        device_id: device_id.to_owned(),
        subscriptions: StreamMap::new(),
    })
}

impl Session {
    /// Groupes dont l'appareil est actuellement membre.
    ///
    /// Relue à chaque battement plutôt que mémorisée : c'est le seul moyen qu'un retrait de
    /// groupe prenne effet sur une session déjà ouverte.
    async fn membership(&self) -> ApiResult<Vec<Vec<u8>>> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT m.group_id FROM group_members m
             JOIN devices d ON d.id = m.device_id
             WHERE m.device_id = $1 AND d.revoked_at IS NULL",
        )
        .bind(&self.device_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(group_id,)| group_id).collect())
    }

    fn subscribe(&mut self, group_id: Vec<u8>) {
        if self.subscriptions.contains_key(&group_id) || self.subscriptions.len() >= MAX_SUBSCRIPTIONS
        {
            return;
        }

        let receiver = BroadcastStream::new(self.hub.subscribe(&group_id));
        self.subscriptions.insert(group_id, receiver);
    }

    /// Annonce les séquences déposées depuis le curseur du client.
    ///
    /// Ne sert que des numéros : le client ira lire par le chemin HTTP, qui revérifie son
    /// appartenance. Un curseur portant sur un groupe dont l'appareil n'est pas membre est
    /// **ignoré silencieusement** — répondre « inconnu » plutôt que « pas membre » ferait de ce
    /// rattrapage un oracle d'existence de groupe.
    async fn resume(
        &self,
        sender: &mut Sender,
        cursors: &[Cursor],
        groups: &[Vec<u8>],
    ) -> ApiResult<()> {
        let membres: HashSet<&[u8]> = groups.iter().map(Vec::as_slice).collect();

        // Les curseurs excédentaires sont ignorés en silence plutôt que la session refusée : un
        // client honnête n'en produit jamais autant, et refuser transformerait une borne de
        // sécurité en panne pour un cas qui ne se présente pas.
        let mut vus: HashSet<&str> = HashSet::new();

        for cursor in cursors.iter().take(MAX_CURSORS) {
            // Un même groupe répété n'achète qu'une requête. C'est la seconde moitié de la
            // borne : sans elle, `MAX_CURSORS` entrées identiques passeraient toutes.
            if !vus.insert(cursor.group_id.as_str()) {
                continue;
            }

            let Ok(group_id) = hex::decode(&cursor.group_id) else { continue };
            if !membres.contains(group_id.as_slice()) {
                continue;
            }

            let rows: Vec<(i64,)> = sqlx::query_as(
                "SELECT seq FROM envelopes
                 WHERE group_id = $1 AND seq > $2
                 ORDER BY seq
                 LIMIT $3",
            )
            .bind(&group_id)
            .bind(cursor.seq)
            .bind(MAX_RESUME_PER_GROUP)
            .fetch_all(&self.pool)
            .await?;

            for (seq,) in rows {
                let frame =
                    ServerFrame::Envelope { group_id: cursor.group_id.clone(), seq };
                if send(sender, &frame).await.is_err() {
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Recale les abonnements sur l'appartenance réelle, et dit si la session doit survivre.
    ///
    /// C'est la contrepartie du passage à une authentification par session : sans elle, un
    /// appareil révoqué ou évincé continuerait d'être servi tant qu'il garde sa socket ouverte.
    async fn revalidate(&mut self) -> ApiResult<bool> {
        let groups = self.membership().await?;

        // Aucun groupe **et** appareil disparu ou révoqué : la session n'a plus d'objet. On
        // distingue les deux cas, parce qu'un appareil parfaitement valide peut légitimement
        // n'être membre d'aucun groupe — c'est l'état d'un appareil fraîchement enregistré.
        let vivant: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM devices WHERE id = $1 AND revoked_at IS NULL")
                .bind(&self.device_id)
                .fetch_optional(&self.pool)
                .await?;

        if vivant.is_none() {
            return Ok(false);
        }

        let actuels: HashSet<Vec<u8>> = groups.into_iter().collect();

        let perdus: Vec<Vec<u8>> = self
            .subscriptions
            .keys()
            .filter(|group_id| !actuels.contains(*group_id))
            .cloned()
            .collect();

        for group_id in perdus {
            self.subscriptions.remove(&group_id);
        }

        Ok(true)
    }

    /// Boucle principale : trames du client d'un côté, diffusion du hub de l'autre.
    async fn pump(
        mut self,
        mut sender: Sender,
        mut receiver: futures_util::stream::SplitStream<WebSocket>,
    ) -> Result<(), axum::Error> {
        let mut battement = tokio::time::interval(HEARTBEAT);
        battement.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut dernier_signe_de_vie = tokio::time::Instant::now();

        loop {
            tokio::select! {
                // `biased` pour que le hub ne puisse pas affamer les trames du client : sans
                // lui, un groupe très bavard retarderait indéfiniment un `unsubscribe`.
                biased;

                message = receiver.next() => {
                    let Some(message) = message else { return Ok(()) };
                    let message = message?;

                    dernier_signe_de_vie = tokio::time::Instant::now();

                    match message {
                        Message::Text(text) => {
                            // Une trame illisible n'est pas fatale : un client plus récent peut
                            // émettre une opération que ce serveur ne connaît pas encore.
                            let Ok(frame) = serde_json::from_str::<ClientFrame>(&text) else {
                                continue;
                            };

                            match self.handle(frame).await {
                                Reaction::Silence => {}
                                Reaction::Repondre(frame) => send(&mut sender, &frame).await?,
                                Reaction::Terminer(frame) => {
                                    let _ = send(&mut sender, &frame).await;
                                    return sender.close().await;
                                }
                            }
                        }
                        Message::Close(_) => return sender.close().await,
                        // Ping et Pong sont traités par la couche axum ; les trames binaires
                        // n'ont pas de sens dans ce protocole et sont ignorées plutôt que
                        // fatales.
                        _ => {}
                    }
                }

                Some((group_id, notice)) = self.subscriptions.next() => {
                    // Un abonné distancé perd des événements plutôt que de faire grossir la
                    // mémoire du serveur. Ce n'est pas une perte de données : le client
                    // rattrape par la relève, comme le documente `crate::stream`.
                    let Ok(notice) = notice else { continue };

                    let frame = match notice {
                        Notice::Envelope { seq, .. } => {
                            ServerFrame::Envelope { group_id: hex::encode(&group_id), seq }
                        }
                        Notice::Signal { payload, .. } => ServerFrame::Signal {
                            group_id: hex::encode(&group_id),
                            payload: BASE64_STANDARD.encode(&payload),
                        },
                    };

                    send(&mut sender, &frame).await?;
                }

                _ = battement.tick() => {
                    if dernier_signe_de_vie.elapsed() > SILENCE_MAX {
                        return sender.close().await;
                    }

                    match self.revalidate().await {
                        Ok(true) => {}
                        Ok(false) => return sender.close().await,
                        // Une base momentanément indisponible ne doit pas déconnecter tout le
                        // monde : on retentera au battement suivant. La session garde ses
                        // abonnements, ce qui est le comportement d'avant cette vérification.
                        Err(error) => tracing::debug!(%error, "revalidation reportée"),
                    }

                    crate::presence::touch_detached(self.pool.clone(), self.device_id.clone());
                }
            }
        }
    }

    /// Traite une trame du client.
    async fn handle(&mut self, frame: ClientFrame) -> Reaction {
        match frame {
            // Une seconde ouverture sur une session déjà ouverte : ignorée. L'accepter
            // permettrait de changer d'identité en cours de route sans que les abonnements en
            // place soient recalculés.
            ClientFrame::Identify { .. } => Reaction::Silence,

            // Le battement du client est ce qui déclenche la revalidation, plutôt que le seul
            // tick du serveur : il la rend prompte — un appareil révoqué est coupé au battement
            // suivant, pas au prochain tick — sans rien coûter à une session inactive.
            //
            // Une requête par battement, donc, et sans amortissement. C'est le même ordre de
            // grandeur qu'une trame `subscribe` ou `signal`, qui interrogent déjà la base à
            // chaque appel ; un client qui martèlerait ses battements se limiterait lui-même
            // par sa bande passante bien avant d'inquiéter la base.
            ClientFrame::Heartbeat => match self.revalidate().await {
                Ok(true) => Reaction::Repondre(ServerFrame::HeartbeatAck),
                Ok(false) => {
                    Reaction::Terminer(ServerFrame::Error { reason: "session révoquée" })
                }
                Err(error) => Reaction::Repondre(ServerFrame::Error { reason: reason(&error) }),
            },

            ClientFrame::Subscribe { group_id } => {
                let Ok(group_id) = crate::routes::decode_group_id(&group_id) else {
                    return Reaction::Repondre(ServerFrame::Error { reason: "trame invalide" });
                };

                // Revérifié en base, à chaque fois. Se fier à la liste calculée à l'ouverture
                // laisserait un appareil s'abonner à un groupe dont il vient d'être retiré.
                match crate::routes::is_member(&self.pool, &group_id, &self.device_id).await {
                    Ok(true) => {
                        self.subscribe(group_id);
                        Reaction::Silence
                    }
                    Ok(false) => Reaction::Repondre(ServerFrame::Error { reason: "refusé" }),
                    Err(error) => {
                        Reaction::Repondre(ServerFrame::Error { reason: reason(&error) })
                    }
                }
            }

            ClientFrame::Unsubscribe { group_id } => {
                if let Ok(group_id) = crate::routes::decode_group_id(&group_id) {
                    self.subscriptions.remove(&group_id);
                }
                Reaction::Silence
            }

            ClientFrame::Signal { group_id, nonce, mac, payload } => {
                let decode = |value: &str| BASE64_STANDARD.decode(value).ok();
                let (Ok(group_id), Some(nonce), Some(mac), Some(payload)) = (
                    crate::routes::decode_group_id(&group_id),
                    decode(&nonce),
                    decode(&mac),
                    decode(&payload),
                ) else {
                    return Reaction::Repondre(ServerFrame::Error { reason: "trame invalide" });
                };

                // Même vérification que le chemin HTTP, par la même fonction : le MAC de groupe
                // prouve l'appartenance sans révéler qui poste. La session connaît pourtant
                // l'identité de son propriétaire — s'en servir ici défairait le sealed sender.
                match crate::routes::verify_signal(&self.pool, &group_id, &nonce, &mac, &payload)
                    .await
                {
                    Ok(()) => {
                        self.hub.publish(Notice::Signal { group_id, payload });
                        Reaction::Silence
                    }
                    Err(error) => {
                        Reaction::Repondre(ServerFrame::Error { reason: reason(&error) })
                    }
                }
            }
        }
    }
}

/// Ce que le serveur fait d'une trame reçue.
///
/// Le troisième cas est celui qui justifie l'énumération : une session dont l'appareil vient
/// d'être révoqué doit être **fermée**, pas seulement avertie. Renvoyer une erreur et poursuivre
/// laisserait la socket servir les groupes déjà abonnés.
enum Reaction {
    Silence,
    Repondre(ServerFrame<'static>),
    Terminer(ServerFrame<'static>),
}

async fn send(sender: &mut Sender, frame: &ServerFrame<'_>) -> Result<(), axum::Error> {
    // `expect` plutôt qu'une erreur remontée : ces structures n'ont aucun champ qui puisse
    // échouer à la sérialisation, et un échec signalerait un bug de ce module, pas une
    // condition d'exécution.
    let text = serde_json::to_string(frame).expect("les trames serveur sont sérialisables");
    sender.send(Message::Text(text.into())).await
}
