//! Limite de débit des routes ouvertes.
//!
//! # Ce que cela ferme
//!
//! Quatre routes s'exercent **sans aucune authentification**, parce qu'elles précèdent
//! l'existence d'une identité : création de compte, enregistrement d'appareil, dépôt et
//! relève d'appairage. Rien ne les bornait.
//!
//! La création de compte est la plus coûteuse à laisser ouverte. Elle écrit une entrée dans
//! `log_entries` — le journal de transparence — et cette écriture est faite pour ne jamais être
//! reprise : un journal append-only dont on retire une feuille cesse de pouvoir prouver sa
//! consistance. Un tiers sans identité pouvait donc faire grossir indéfiniment la seule table du
//! schéma qu'on ne sait pas nettoyer. La clé étrangère `ON DELETE CASCADE` de `log_entries` offre
//! bien une sortie — supprimer les comptes — mais elle troue le journal, c'est-à-dire qu'elle
//! choisit de casser les preuves plutôt que de garder le déchet. Aucune des deux issues n'est
//! bonne : il fallait empêcher l'entrée.
//!
//! # Ce que cela ne ferme pas
//!
//! **Le compteur vit en mémoire, donc par instance.** Deux instances derrière un répartiteur
//! offrent deux fois le quota, et un redémarrage remet tout à zéro. C'est la même réserve que
//! celle déjà écrite dans `crate::presence` sur son cache — à ceci près qu'ici, contrairement à
//! la présence, il n'y a pas de garde en base derrière pour rattraper. Un déploiement sérieux
//! mettrait cette limite devant le serveur, dans le répartiteur, où elle voit tout le trafic.
//!
//! **L'adresse n'est pas une identité.** Un attaquant qui en change contourne la limite ; des
//! utilisateurs légitimes derrière un même NAT la partagent. C'est un ralentisseur, pas une
//! barrière, et le présenter autrement serait se mentir.
//!
//! **Derrière un proxy, l'adresse vue est celle du proxy.** Le serveur lit la socket et rien
//! d'autre : il ne fait aucune confiance à `X-Forwarded-For`, qui se falsifie librement et
//! transformerait la limite en formalité. La contrepartie est qu'un déploiement derrière un
//! proxy limite le proxy entier ; c'est à lui de porter la limite dans ce cas.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Quota par défaut, par adresse et par minute.
///
/// Généreux pour un usage humain — créer un compte, y rattacher quelques appareils, appairer —
/// et étroit devant ce qu'il faut de requêtes pour faire grossir une table de façon gênante.
pub const DEFAUT_PAR_MINUTE: u32 = 60;

/// Au-delà de ce nombre d'adresses suivies, les entrées périmées sont balayées.
///
/// Sans ce nettoyage, la table grandirait d'une entrée par adresse rencontrée et ne
/// rétrécirait jamais : on aurait remplacé un vecteur de remplissage de disque par un vecteur
/// de remplissage de mémoire, ce qui n'est pas un progrès.
const SEUIL_DE_BALAYAGE: usize = 4096;

pub struct Throttle {
    quota: u32,
    fenetre: Duration,
    vues: Mutex<HashMap<IpAddr, Compteur>>,
}

struct Compteur {
    depuis: Instant,
    requetes: u32,
}

impl Throttle {
    /// Limiteur au quota donné, par minute.
    ///
    /// `0` désactive la limite. Les tests d'intégration s'en servent : ils créent des dizaines de
    /// comptes en quelques secondes depuis la boucle locale, ce qu'aucun quota réaliste ne
    /// laisserait passer. Le test qui vérifie que la limite mord, lui, construit son propre
    /// limiteur avec un quota bas.
    pub fn par_minute(quota: u32) -> Self {
        Self {
            quota,
            fenetre: Duration::from_secs(60),
            vues: Mutex::new(HashMap::new()),
        }
    }

    /// Quota lu depuis `THROTTLE_PER_MINUTE`, ou [`DEFAUT_PAR_MINUTE`].
    pub fn depuis_environnement() -> Self {
        let quota = std::env::var("THROTTLE_PER_MINUTE")
            .ok()
            .and_then(|valeur| valeur.parse().ok())
            .unwrap_or(DEFAUT_PAR_MINUTE);

        Self::par_minute(quota)
    }

    /// Décompte une requête, et dit si elle peut passer.
    ///
    /// Fenêtre fixe et non glissante : à la bascule, un appelant peut émettre deux quotas en
    /// peu de temps. C'est connu, et sans importance ici — la limite existe pour empêcher une
    /// croissance soutenue, pas une rafale.
    pub fn autorise(&self, adresse: IpAddr) -> bool {
        if self.quota == 0 {
            return true;
        }

        let maintenant = Instant::now();
        let mut vues = self.vues.lock().unwrap_or_else(|erreur| erreur.into_inner());

        if vues.len() > SEUIL_DE_BALAYAGE {
            vues.retain(|_, compteur| maintenant.duration_since(compteur.depuis) < self.fenetre);
        }

        let compteur = vues
            .entry(adresse)
            .or_insert(Compteur { depuis: maintenant, requetes: 0 });

        if maintenant.duration_since(compteur.depuis) >= self.fenetre {
            *compteur = Compteur { depuis: maintenant, requetes: 0 };
        }

        compteur.requetes += 1;
        compteur.requetes <= self.quota
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(dernier: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, dernier])
    }

    #[test]
    fn le_quota_laisse_passer_puis_refuse() {
        let throttle = Throttle::par_minute(3);

        for tour in 1..=3 {
            assert!(throttle.autorise(ip(1)), "la requête {tour} devait passer");
        }

        assert!(!throttle.autorise(ip(1)), "la quatrième dépasse le quota");
    }

    #[test]
    fn une_adresse_n_epuise_pas_le_quota_d_une_autre() {
        let throttle = Throttle::par_minute(1);

        assert!(throttle.autorise(ip(1)));
        assert!(!throttle.autorise(ip(1)));

        assert!(throttle.autorise(ip(2)), "le compteur est par adresse, pas global");
    }

    /// Le quota nul rend le limiteur transparent — ce dont dépend le harnais de test.
    #[test]
    fn un_quota_nul_ne_refuse_jamais() {
        let throttle = Throttle::par_minute(0);

        for _ in 0..1000 {
            assert!(throttle.autorise(ip(1)));
        }
    }
}
