//! Journal auditable des clés de compte, côté serveur.
//!
//! # Ce que le serveur fait ici, et ce qu'il ne fait pas
//!
//! Il **construit** l'arbre et **signe** les têtes. Il ne vérifie rien pour le compte du
//! client : toutes les preuves qu'il émet sont revérifiées côté client, avec la même crate
//! [`transparency`], contre la clé publique du journal. C'est la seule façon dont un journal
//! a un sens — sinon on demande au surveillé de garantir la surveillance.
//!
//! # La faiblesse structurelle, à ne pas masquer
//!
//! Le journal est signé par la même partie que celle qu'il surveille. Un serveur malveillant
//! peut donc tenir **deux journaux** cohérents et en servir un à chacun. Rien dans ce fichier
//! ne l'en empêche, et rien ne le pourrait : la détection appartient au *gossip* entre clients,
//! qui compare les têtes dans des messages que le serveur ne peut pas lire ni falsifier.
//!
//! Un déploiement sérieux confierait le journal à un ou plusieurs opérateurs distincts. Ici il
//! y a un seul processus, et le dire est préférable à le laisser deviner.

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use transparency::{Hash, TreeHead};

/// Charge la clé de signature du journal, en la créant au premier démarrage.
///
/// `ON CONFLICT DO NOTHING` plutôt qu'un « lire puis écrire » : deux processus qui démarrent
/// ensemble produiraient sinon deux clés, donc deux journaux, et les clients verraient une
/// bifurcation causée par nous-mêmes.
pub async fn ensure_signing_key(pool: &PgPool) -> Result<(), sqlx::Error> {
    let fresh = SigningKey::generate(&mut rand_core::OsRng);

    sqlx::query("INSERT INTO log_key (id, signing_key) VALUES (TRUE, $1) ON CONFLICT DO NOTHING")
        .bind(fresh.to_bytes().as_slice())
        .execute(pool)
        .await?;

    Ok(())
}

/// Relit la clé du journal.
///
/// Relue à chaque requête plutôt que mise en cache dans l'état de l'application. C'est un
/// aller-retour de base par preuve, assumé pour ce projet : un cache de la clé de signature
/// est le genre d'état qui survit à une rotation qu'on croyait effectuée.
pub async fn signing_key(pool: &PgPool) -> Result<SigningKey, sqlx::Error> {
    let (stored,): (Vec<u8>,) =
        sqlx::query_as("SELECT signing_key FROM log_key WHERE id = TRUE").fetch_one(pool).await?;

    let bytes: [u8; 32] = stored.try_into().expect("contrainte log_signing_key_is_ed25519");
    Ok(SigningKey::from_bytes(&bytes))
}

/// Ajoute une clé de compte au journal.
///
/// Le hash de feuille est calculé **ici**, par la crate partagée, et jamais en SQL : une
/// seconde implémentation de la formule diverge tôt ou tard, et une divergence silencieuse
/// dans un journal auditable est pire que pas de journal du tout.
///
/// À appeler dans la même transaction que l'écriture du compte : une clé publiée sans entrée
/// de journal serait rejetée par tous les clients.
pub async fn append(
    tx: &mut sqlx::PgConnection,
    handle: &str,
    identity_key: &[u8],
) -> Result<(), sqlx::Error> {
    let leaf = transparency::leaf_hash(&transparency::entry(handle, identity_key));

    sqlx::query("INSERT INTO log_entries (handle, identity_key, leaf) VALUES ($1, $2, $3)")
        .bind(handle)
        .bind(identity_key)
        .bind(leaf.as_slice())
        .execute(tx)
        .await?;

    Ok(())
}

/// Fait entrer dans le journal les comptes créés avant son introduction.
///
/// Sans ce rattrapage, leurs clés n'auraient aucune preuve d'inclusion et les clients les
/// rejetteraient toutes — le journal rendrait le système moins utilisable plutôt que plus sûr.
///
/// L'ordre est déterministe (`created_at, handle`) : deux exécutions doivent produire le même
/// arbre, sans quoi un redémarrage ressemblerait à une réécriture.
pub async fn backfill(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let manquants: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT a.handle, a.identity_key FROM accounts a
         WHERE NOT EXISTS (SELECT 1 FROM log_entries l WHERE l.handle = a.handle)
         ORDER BY a.created_at, a.handle",
    )
    .fetch_all(pool)
    .await?;

    let mut tx = pool.begin().await?;
    for (handle, identity_key) in &manquants {
        append(&mut tx, handle, identity_key).await?;
    }
    tx.commit().await?;

    Ok(manquants.len())
}

/// Toutes les feuilles, dans l'ordre de l'arbre.
///
/// Relues intégralement à chaque preuve. C'est assumé pour ce projet : un journal réel tiendrait
/// les nœuds intermédiaires en cache, mais recalculer garantit qu'aucun état dérivé ne peut
/// diverger de la table — et c'est la table qui fait foi.
pub async fn leaves(pool: &PgPool) -> Result<Vec<Hash>, sqlx::Error> {
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT leaf FROM log_entries ORDER BY seq").fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(|(leaf,)| leaf.try_into().expect("contrainte log_leaf_is_sha256"))
        .collect())
}

/// Position de la dernière entrée d'un compte, et sa clé.
///
/// La **dernière** : une rotation ajoute une entrée sans en retirer aucune, et c'est la plus
/// récente qui fait foi. Les anciennes restent dans l'arbre — c'est ce qui permet à un client
/// de constater qu'une clé a changé, plutôt que de la voir disparaître.
pub async fn latest(
    pool: &PgPool,
    handle: &str,
) -> Result<Option<(i64, Vec<u8>)>, sqlx::Error> {
    let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, identity_key FROM log_entries WHERE handle = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(handle)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Indice d'une entrée dans l'arbre.
///
/// `seq` est un `BIGSERIAL` : il croît strictement mais peut sauter (transaction annulée). On
/// ne peut donc pas s'en servir directement comme indice, il faut compter les entrées qui
/// précèdent. Confondre les deux produirait des preuves d'inclusion valides pour la mauvaise
/// position — le genre d'erreur qui ne se voit qu'une fois qu'un rollback a eu lieu.
pub async fn index_of(pool: &PgPool, seq: i64) -> Result<usize, sqlx::Error> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM log_entries WHERE seq < $1").bind(seq).fetch_one(pool).await?;

    Ok(count as usize)
}

/// Tête courante du journal, signée.
pub fn head(leaves: &[Hash], key: &SigningKey) -> (TreeHead, [u8; 64]) {
    let head = TreeHead {
        size: leaves.len() as u64,
        root: transparency::root(leaves),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let signature = head.sign(key);
    (head, signature)
}
