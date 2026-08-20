//! Réveil des appareils endormis.
//!
//! # Ce que ce module dégrade
//!
//! Tout le reste du serveur tend à en savoir le moins possible. Celui-ci va dans l'autre sens, et
//! il faut le dire avant d'expliquer ce qu'il apporte : pour qu'un téléphone endormi apprenne
//! qu'un message l'attend, le serveur doit demander à Google ou Apple de le réveiller. Ce tiers
//! apprend alors le **rythme** des conversations d'un appareil qu'il sait rattacher à un compte.
//!
//! Le contenu reste chiffré. Ce qui fuit, ce sont les métadonnées d'activité, et c'est
//! irréductible : c'est le principe du push, pas un défaut d'implémentation. Voir
//! `migrations/0011_push.sql` pour les trois bornes qui en découlent.
//!
//! # Le réveil ne transporte rien
//!
//! Ni texte, ni expéditeur, ni identifiant de groupe : « réveille-toi », et c'est tout.
//! L'application relève ensuite par le chemin normal, déchiffre, et compose la notification
//! localement. Mettre le message dans la notification le montrerait au fournisseur **et** à
//! l'écran verrouillé — c'est-à-dire exactement ce que ce projet existe pour éviter.
//!
//! C'est ce qui explique la forme de [`Emetteur`] : il ne prend que des jetons. Il n'y a rien
//! d'autre à lui donner, et l'interface le rend impossible plutôt que déconseillé.
//!
//! # Inerte sans configuration
//!
//! [`Silencieux`] est l'émetteur par défaut. Un déploiement auto-hébergé qui ne parle ni à Apple
//! ni à Google enregistre les jetons et n'envoie rien : la fonctionnalité manque, l'application
//! non. C'est le comportement à préserver en priorité si un jour quelqu'un branche un vrai
//! fournisseur ici.

use std::sync::Arc;

use sqlx::PgPool;

/// Où joindre un appareil, et par quel fournisseur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adresse {
    pub provider: String,
    pub token: String,
}

/// Ce qui sait réveiller des appareils.
///
/// Volontairement borné aux adresses : ce trait ne peut pas transporter de contenu parce qu'il
/// n'y en a pas à transporter. Une signature qui accepterait un texte inviterait, un jour de
/// hâte, à y mettre l'aperçu du message.
pub trait Emetteur: Send + Sync {
    fn reveiller(&self, adresses: Vec<Adresse>);
}

/// L'émetteur par défaut : il ne réveille personne.
///
/// Ce n'est pas un bouchon en attendant mieux, c'est le comportement d'un déploiement sans
/// fournisseur configuré — et ce déploiement doit rester pleinement fonctionnel.
pub struct Silencieux;

impl Emetteur for Silencieux {
    fn reveiller(&self, adresses: Vec<Adresse>) {
        // Compté et non ignoré : sans trace, un déploiement dont la configuration a disparu
        // ressemble trait pour trait à un déploiement qui n'en a jamais eu.
        if !adresses.is_empty() {
            tracing::debug!(appareils = adresses.len(), "réveil ignoré : aucun fournisseur");
        }
    }
}

/// Enregistre ou remplace le jeton d'un appareil.
///
/// Le remplacement est la règle : les fournisseurs font tourner leurs jetons sans prévenir, et
/// garder les anciens n'accumulerait que des adresses mortes.
pub async fn enregistrer(
    pool: &PgPool,
    device_id: &str,
    provider: &str,
    token: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO push_tokens (device_id, provider, token, updated_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (device_id) DO UPDATE
         SET provider = EXCLUDED.provider, token = EXCLUDED.token, updated_at = now()",
    )
    .bind(device_id)
    .bind(provider)
    .bind(token)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Retire le jeton d'un appareil. Le silence redevient l'état normal.
pub async fn oublier(pool: &PgPool, device_id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Les adresses des membres d'un groupe, sauf celle qu'on exclut.
///
/// # Pourquoi l'exclusion est optionnelle
///
/// L'émetteur d'un dépôt **anonyme** est inconnu du serveur : le sealed sender lui a retiré ce
/// pouvoir, et il n'est pas question de le lui rendre pour économiser une notification. Cet
/// appareil se réveillera donc pour un message qu'il vient d'écrire — un défaut d'élégance, à
/// corriger côté client qui, lui, sait ce qu'il a envoyé.
pub async fn adresses_du_groupe(
    pool: &PgPool,
    group_id: &[u8],
    sauf: Option<&str>,
) -> sqlx::Result<Vec<Adresse>> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT p.provider, p.token
         FROM push_tokens p
         JOIN group_members m ON m.device_id = p.device_id
         WHERE m.group_id = $1 AND ($2::text IS NULL OR p.device_id <> $2)",
    )
    .bind(group_id)
    .bind(sauf)
    .fetch_all(pool)
    .await
    .map(|lignes| {
        lignes.into_iter().map(|(provider, token)| Adresse { provider, token }).collect()
    })
}

/// Réveille les membres d'un groupe après un dépôt.
///
/// Détaché, comme la présence : un fournisseur lent ou en panne ne doit pas retarder la réponse à
/// celui qui vient d'envoyer son message. Le message, lui, est déjà écrit et déjà annoncé aux
/// clients connectés — le réveil ne sert qu'à ceux qui ne le sont pas.
pub fn reveiller_detache(
    pool: PgPool,
    emetteur: Arc<dyn Emetteur>,
    group_id: Vec<u8>,
    sauf: Option<String>,
) {
    tokio::spawn(async move {
        match adresses_du_groupe(&pool, &group_id, sauf.as_deref()).await {
            Ok(adresses) if !adresses.is_empty() => emetteur.reveiller(adresses),
            Ok(_) => {}
            Err(erreur) => tracing::warn!(?erreur, "réveil impossible"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Un émetteur qui note ce qu'on lui demande, pour vérifier ce qui lui parvient.
    #[derive(Default)]
    struct Espion(Mutex<Vec<Adresse>>);

    impl Emetteur for Espion {
        fn reveiller(&self, adresses: Vec<Adresse>) {
            self.0.lock().expect("espion empoisonné").extend(adresses);
        }
    }

    /// **Le test qui porte la propriété du module.**
    ///
    /// Le trait ne doit pas pouvoir transporter de contenu. Ce test ne l'exprime pas par une
    /// assertion — le compilateur s'en charge — mais il fige l'usage : ce qui traverse la
    /// frontière est une liste d'adresses, et rien d'autre. Si un jour quelqu'un ajoute un
    /// paramètre de message, ce fichier cessera de compiler et la discussion aura lieu.
    #[test]
    fn le_reveil_ne_transporte_que_des_adresses() {
        let espion = Espion::default();
        let adresse = Adresse { provider: "fcm".into(), token: "abc".into() };

        espion.reveiller(vec![adresse.clone()]);

        assert_eq!(espion.0.lock().unwrap().as_slice(), &[adresse]);
    }

    /// L'émetteur par défaut n'envoie rien et ne panique pas.
    ///
    /// C'est le comportement d'un déploiement sans fournisseur, pas un cas dégradé : il doit
    /// rester le chemin le mieux tenu du module.
    #[test]
    fn sans_fournisseur_rien_ne_part() {
        Silencieux.reveiller(vec![Adresse { provider: "fcm".into(), token: "abc".into() }]);
        Silencieux.reveiller(Vec::new());
    }
}
