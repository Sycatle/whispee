//! Registre de présence : qui est éveillé, à la minute près.
//!
//! # Ce que ce module ajoute au modèle de menace
//!
//! Un registre transverse aux conversations, et il n'y a pas de formulation chiffrée qui
//! l'évite : pour afficher qu'un compte est connecté, il faut que quelqu'un le sache. Ce
//! quelqu'un est le serveur, et ce qu'il apprend, ce sont les horaires d'éveil de chacun.
//! Voir `migrations/0008_presence.sql` pour ce qui borne la fuite.
//!
//! # Ce que ce module ne doit jamais faire
//!
//! **Être appelé depuis un chemin anonyme.** Les dépôts d'enveloppes scellées et les signaux de
//! frappe prouvent l'appartenance à un groupe par un MAC, pas l'identité : le serveur ne sait
//! pas qui dépose, et il ne doit pas l'apprendre. Y écrire une touche de présence demanderait
//! de ré-attribuer le dépôt à un appareil — précisément le pouvoir que le sealed sender lui a
//! retiré. Un test le gèle.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use sqlx::PgPool;

/// Rythme de réécriture. Borne la fraîcheur de la valeur, et c'est le seul chiffre qui coûte.
///
/// Le seuil « en ligne », lui, est un choix d'affichage et vit côté client : le serveur renvoie
/// un horodatage, jamais un booléen. Un booléen figerait la politique dans le protocole et
/// interdirait le « vu à 14:02 » à partir de la même donnée.
pub const PRESENCE_REFRESH: Duration = Duration::from_secs(60);

/// Amortissement en mémoire, devant la garde SQL.
///
/// Placé dans un `static` plutôt que dans l'état applicatif : le routeur des pièces jointes n'a
/// que `PgPool` comme état, et l'extracteur `Signed` est générique sur `S`. De toute façon, la
/// protection réelle est la clause `WHERE` ci-dessous — elle reste juste avec plusieurs
/// instances, ce cache non.
static DERNIERE_TOUCHE: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Note qu'un appareil est éveillé, au plus une fois par `PRESENCE_REFRESH`.
///
/// Sans amortissement, un client ferait une écriture par requête : à dix conversations et une
/// relève toutes les trente secondes, c'est une écriture par seconde et par appareil, pour une
/// information inchangée entre deux battements.
///
/// La mise à jour reste HOT — `last_seen_at` n'est pas indexée — donc elle ne réécrit aucune
/// entrée d'index. Le compte qui a refusé la présence n'est jamais écrit : le refus est honoré
/// ici, à la source, et non au filtrage en lecture.
pub async fn touch(pool: &PgPool, device_id: &str) -> sqlx::Result<()> {
    {
        let mut cache = DERNIERE_TOUCHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dernier) = cache.get(device_id)
            && dernier.elapsed() < PRESENCE_REFRESH
        {
            return Ok(());
        }
        cache.insert(device_id.to_owned(), Instant::now());
    }

    sqlx::query(
        "UPDATE devices d
            SET last_seen_at = date_trunc('minute', now())
          FROM accounts a
         WHERE d.id = $1
           AND a.handle = d.handle
           AND a.presence_optout = false
           AND (d.last_seen_at IS NULL OR d.last_seen_at < now() - interval '60 seconds')",
    )
    .bind(device_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Touche sans jamais faire échouer l'appelant.
///
/// Utilisée depuis l'extracteur d'authentification, qui est sur le chemin de latence de toutes
/// les requêtes signées. Une présence qui ferait échouer un envoi de message serait une
/// régression de la fonction principale au profit d'un point de couleur.
pub fn touch_detached(pool: PgPool, device_id: String) {
    tokio::spawn(async move {
        if let Err(error) = touch(&pool, &device_id).await {
            tracing::debug!(%error, "présence non enregistrée");
        }
    });
}

/// Dernière activité d'un compte, en secondes depuis l'époque.
pub struct Seen {
    pub handle: String,
    pub last_seen: i64,
}

/// Lit la présence des comptes demandés, pour un appelant donné.
///
/// # Contrôle d'accès
///
/// Un handle n'est servi que si l'appelant partage au moins un groupe avec lui — ou s'il s'agit
/// de son propre compte. Sans cette clause, la route serait un oracle d'activité sur n'importe
/// quel pseudonyme du serveur.
///
/// Réciprocité : un compte qui a refusé de diffuser sa présence n'obtient pas celle des autres.
/// Le réglage permettrait sinon de voir sans être vu, c'est-à-dire exactement ce qu'il prétend
/// empêcher.
///
/// # Ce qui ne sort pas
///
/// Le détail par appareil. Seul le `MAX` par compte est servi : le nombre d'appareils d'une
/// personne et leurs habitudes respectives sont une fuite distincte de « en ligne ».
///
/// Un handle inconnu et un handle sans groupe commun produisent le même résultat — leur absence.
/// Les distinguer ferait de la route un oracle d'existence de compte.
pub async fn read(pool: &PgPool, device_id: &str, handles: &[String]) -> sqlx::Result<Vec<Seen>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT d.handle, EXTRACT(EPOCH FROM MAX(d.last_seen_at))::BIGINT
           FROM devices d
          WHERE d.revoked_at IS NULL
            AND d.handle = ANY($2)
            AND EXISTS (
                  SELECT 1 FROM devices moi
                   JOIN accounts a ON a.handle = moi.handle
                  WHERE moi.id = $1 AND a.presence_optout = false
                )
            AND (
                 d.handle = (SELECT handle FROM devices WHERE id = $1)
              OR EXISTS (
                   SELECT 1
                     FROM group_members moi
                     JOIN group_members eux ON eux.group_id = moi.group_id
                     JOIN devices autre ON autre.id = eux.device_id
                    WHERE moi.device_id = $1 AND autre.handle = d.handle
                 )
            )
          GROUP BY d.handle
         HAVING MAX(d.last_seen_at) IS NOT NULL",
    )
    .bind(device_id)
    .bind(handles)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(handle, last_seen)| Seen { handle, last_seen }).collect())
}
