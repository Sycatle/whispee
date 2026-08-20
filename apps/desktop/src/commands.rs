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

/// Range la clé maîtresse du verrou, scellée par les secrets de l'appareil.
///
/// # Ce que le déverrouillage biométrique échange
///
/// Un mot de passe n'est stocké nulle part : il n'existe que dans la tête de son propriétaire, et
/// c'est ce qui rend l'état illisible pour qui emporte le disque. L'activation de la biométrie
/// **écrit la clé maîtresse sur l'appareil**, scellée par les secrets qui, eux, sont en clair
/// dans le répertoire privé de l'application.
///
/// La protection devient donc celle du système : le répertoire privé, et l'invite biométrique
/// devant cette commande. C'est solide contre qui prend le téléphone en main, et sans valeur
/// contre qui en extrait le stockage — un `root`, une sauvegarde non chiffrée, une image disque.
///
/// C'est **strictement plus faible** que le mot de passe seul. L'interface doit le dire avant
/// d'offrir le bouton, pas après.
#[tauri::command]
pub fn master_seal(master: String, coffre: State<'_, Coffre>) -> Result<(), String> {
    let clair = BASE64_STANDARD.decode(master).map_err(|_| echec("clé illisible"))?;

    let secrets = coffre.secrets.lock().map_err(|_| echec("coffre indisponible"))?;
    let scelle = secrets.sceller(&clair).map_err(|_| echec("chiffrement impossible"))?;

    store::ecrire_atomiquement(&coffre.emplacement.master(), &scelle)
        .map_err(|_| echec("écriture impossible"))
}

/// Rend la clé maîtresse, après authentification de l'utilisateur.
///
/// L'invite est déclenchée **ici**, dans le processus natif, et non par la webview avant
/// l'appel. La différence est tout l'intérêt du dispositif : une invite posée côté JavaScript
/// est une politesse qu'un script hostile saute, tandis que celle-ci est sur le chemin de la
/// clé. Sans authentification, la commande ne rend rien.
///
/// Sur bureau, il n'y a pas d'invite : les plateformes de bureau n'exposent rien d'équivalent à
/// travers Tauri. La commande y reste utilisable, ce qui est cohérent — l'activation, elle, est
/// refusée en amont par `biometrie_disponible`.
#[tauri::command]
pub async fn master_open(app: tauri::AppHandle) -> Result<Option<String>, String> {
    authentifier(&app, "Déverrouiller vos conversations")?;

    let coffre = app.state::<Coffre>();
    let Some(scelle) = Emplacement::lire(&coffre.emplacement.master())
        .map_err(|_| echec("clé illisible"))?
    else {
        return Ok(None);
    };

    let secrets = coffre.secrets.lock().map_err(|_| echec("coffre indisponible"))?;
    let clair = secrets.ouvrir(&scelle).map_err(|_| echec("déchiffrement impossible"))?;

    Ok(Some(BASE64_STANDARD.encode(clair)))
}

/// Le déverrouillage biométrique est-il activé sur cet appareil ?
///
/// Sans invite, délibérément : l'interface doit pouvoir décider quel bouton afficher avant que
/// l'utilisateur n'ait rien demandé. Poser l'invite ici la déclencherait à chaque démarrage,
/// y compris pour répondre « non ».
///
/// La question ne fuit rien : elle ne dit pas quelle est la clé, seulement qu'il en existe une.
#[tauri::command]
pub fn master_present(coffre: State<'_, Coffre>) -> Result<bool, String> {
    Ok(Emplacement::lire(&coffre.emplacement.master())
        .map_err(|_| echec("clé illisible"))?
        .is_some())
}

/// Retire la clé maîtresse. Le verrou reste posé ; seule la biométrie cesse de l'ouvrir.
#[tauri::command]
pub fn master_clear(coffre: State<'_, Coffre>) -> Result<(), String> {
    match std::fs::remove_file(coffre.emplacement.master()) {
        Ok(()) => Ok(()),
        Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(echec("effacement impossible")),
    }
}

/// Le déverrouillage biométrique est-il utilisable sur cet appareil ?
///
/// Deux conditions, et pas une : la plateforme doit exposer l'invite, et l'utilisateur doit
/// avoir enrôlé une empreinte ou un visage. Un téléphone dont personne n'a configuré la
/// biométrie répond non, et proposer le réglage y donnerait un bouton qui échoue à l'usage.
#[tauri::command]
pub fn biometrie_disponible(app: tauri::AppHandle) -> bool {
    let _ = &app;

    #[cfg(mobile)]
    {
        use tauri_plugin_biometric::BiometricExt;
        return app.biometric().status().map(|etat| etat.is_available).unwrap_or(false);
    }

    #[cfg(not(mobile))]
    false
}

/// L'invite du système, là où elle existe.
///
/// Sur bureau elle n'existe pas et la fonction laisse passer : c'est `biometrie_disponible` qui
/// empêche d'y activer le réglage, et refuser ici en plus ne ferait qu'égarer le diagnostic si
/// un jour un fichier `master.bin` s'y retrouvait.
fn authentifier(app: &tauri::AppHandle, raison: &str) -> Result<(), String> {
    let _ = (app, raison);

    #[cfg(mobile)]
    {
        use tauri_plugin_biometric::{AuthOptions, BiometricExt};

        return app
            .biometric()
            .authenticate(raison.to_owned(), AuthOptions::default())
            .map_err(|_| echec("authentification refusée"));
    }

    #[cfg(not(mobile))]
    Ok(())
}
