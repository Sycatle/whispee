//! Ce que la webview peut demander au processus natif.
//!
//! # Une couche mince, délibérément
//!
//! Toute la logique vit dans [`crate::store`] et [`crate::cipher`], qui sont testables sans
//! Tauri ni webview. Ce module ne fait que traduire : base64 à l'entrée, base64 à la sortie,
//! erreurs en chaînes. C'est ce qui permet aux treize tests des deux autres modules d'exister —
//! une commande Tauri, elle, demande un `AppHandle`, donc une application, donc rien de testable
//! en unitaire.
//!
//! # Pourquoi du base64 et pas des octets
//!
//! L'IPC de Tauri sérialise en JSON. Un `Vec<u8>` y devient un tableau de nombres — plus de six
//! octets de JSON par octet utile. Le base64 coûte un tiers, ce qui reste un coût : l'état MLS
//! traverse cette frontière **en clair** à chaque sauvegarde, et il peut faire des dizaines de
//! kilooctets.
//!
//! Ce coût n'est pas mesuré. S'il devient visible, la seule sortie qui ne ramène pas la clé dans
//! la webview est de faire porter la sauvegarde entière au Rust — c'est-à-dire de déplacer aussi
//! le stockage MLS, ce qui est un autre chantier.
//!
//! # Ce que ces commandes ne protègent pas
//!
//! Elles sont atteignables par tout JavaScript de la page. Un script hostile peut appeler
//! `state_open` comme il pouvait appeler `crypto.subtle.decrypt` : ce qui change, c'est qu'il ne
//! peut pas emporter la clé, pas qu'il ne peut pas s'en servir. La frontière de processus
//! remplace la garantie du moteur JavaScript ; elle ne fait pas de la webview un lieu sûr.

use std::sync::Mutex;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use tauri::{Manager, State};

use crate::cipher::DeviceSecrets;
use crate::store::{self, Emplacement};

/// Les secrets et l'emplacement, tenus par le processus pour toute la durée de l'application.
pub struct Coffre {
    secrets: Mutex<DeviceSecrets>,
    emplacement: Emplacement,
}

impl Coffre {
    /// Ouvre le coffre au démarrage, en créant les secrets au premier lancement.
    pub fn ouvrir(racine: std::path::PathBuf) -> std::io::Result<Self> {
        let emplacement = Emplacement::new(racine);
        let secrets = DeviceSecrets::charger_ou_creer(&emplacement.secrets())?;

        Ok(Self { secrets: Mutex::new(secrets), emplacement })
    }
}

/// Traduit une erreur en message présentable, sans détail exploitable.
///
/// Les erreurs d'entrée/sortie portent des chemins, et les erreurs AEAD ne disent rien d'utile de
/// toute façon. Le détail part dans les traces, pas dans la webview.
fn echec(contexte: &'static str) -> String {
    contexte.to_owned()
}

#[tauri::command]
pub fn device_public_key(coffre: State<'_, Coffre>) -> Result<String, String> {
    let secrets = coffre.secrets.lock().map_err(|_| echec("coffre indisponible"))?;
    Ok(BASE64_STANDARD.encode(secrets.cle_publique()))
}

#[tauri::command]
pub fn device_sign(payload: String, coffre: State<'_, Coffre>) -> Result<String, String> {
    let message = BASE64_STANDARD.decode(payload).map_err(|_| echec("payload illisible"))?;
    let secrets = coffre.secrets.lock().map_err(|_| echec("coffre indisponible"))?;

    Ok(BASE64_STANDARD.encode(secrets.signer(&message)))
}

#[tauri::command]
pub fn state_seal(plaintext: String, coffre: State<'_, Coffre>) -> Result<String, String> {
    let clair = BASE64_STANDARD.decode(plaintext).map_err(|_| echec("clair illisible"))?;
    let secrets = coffre.secrets.lock().map_err(|_| echec("coffre indisponible"))?;

    let scelle = secrets.sceller(&clair).map_err(|_| echec("chiffrement impossible"))?;
    Ok(BASE64_STANDARD.encode(scelle))
}

#[tauri::command]
pub fn state_open(blob: String, coffre: State<'_, Coffre>) -> Result<String, String> {
    let scelle = BASE64_STANDARD.decode(blob).map_err(|_| echec("blob illisible"))?;
    let secrets = coffre.secrets.lock().map_err(|_| echec("coffre indisponible"))?;

    // Un échec ici signifie soit une altération, soit une clé qui ne correspond pas. Les deux
    // sont graves et indiscernables : c'est la propriété de l'AEAD, pas une imprécision.
    let clair = secrets.ouvrir(&scelle).map_err(|_| echec("déchiffrement impossible"))?;
    Ok(BASE64_STANDARD.encode(clair))
}

/// Lit la session persistée, ou `None` au premier lancement.
#[tauri::command]
pub fn session_load(coffre: State<'_, Coffre>) -> Result<Option<String>, String> {
    let contenu = Emplacement::lire(&coffre.emplacement.session())
        .map_err(|_| echec("session illisible"))?;

    Ok(contenu.map(|octets| BASE64_STANDARD.encode(octets)))
}

#[tauri::command]
pub fn session_save(contenu: String, coffre: State<'_, Coffre>) -> Result<(), String> {
    let octets = BASE64_STANDARD.decode(contenu).map_err(|_| echec("session illisible"))?;

    store::ecrire_atomiquement(&coffre.emplacement.session(), &octets)
        .map_err(|_| echec("écriture impossible"))
}

/// Efface la session, **sans toucher aux secrets**.
///
/// Les deux effacements sont distincts parce que leurs conséquences le sont : effacer la session
/// laisse un appareil enregistré qui repart de zéro, effacer les secrets laisse une identité que
/// le serveur connaît encore mais que plus personne ne peut prouver. `Session.forget` doit
/// appeler les deux ; ce sont deux appels, et c'est voulu.
#[tauri::command]
pub fn session_clear(coffre: State<'_, Coffre>) -> Result<(), String> {
    match std::fs::remove_file(coffre.emplacement.session()) {
        Ok(()) => Ok(()),
        // Effacer ce qui n'existe pas est le résultat demandé, pas une erreur.
        Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(echec("effacement impossible")),
    }
}

/// Installe le coffre dans l'application.
///
/// Échoue bruyamment si les secrets ne peuvent être ni lus ni créés. C'est délibéré : démarrer
/// sans coffre donnerait une application qui semble fonctionner et ne peut rien persister, donc
/// qui perd tout au premier redémarrage — la panne la plus coûteuse et la plus tardive à voir.
pub fn installer(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let racine = app.path().app_local_data_dir()?;
    app.manage(Coffre::ouvrir(racine)?);

    Ok(())
}
