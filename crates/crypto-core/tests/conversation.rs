//! Cycle complet d'une conversation 1-to-1 : publication, invitation, échange, persistance.

use crypto_core::{Conversation, Identity, Incoming, fingerprint};

/// Monte une conversation à deux membres, comme le ferait le vrai flux :
/// Bob publie un KeyPackage, Alice crée le groupe et l'invite, Bob rejoint via le Welcome.
fn conversation_a_deux() -> (Identity, Identity, Conversation, Conversation) {
    let alice = Identity::create("alice@device-1").unwrap();
    let bob = Identity::create("bob@device-1").unwrap();

    let bob_key_package = bob.publish_key_package().unwrap();

    let mut alice_group = Conversation::create(&alice).unwrap();
    let invitation = alice_group.invite(&alice, &bob_key_package).unwrap();
    let arbre = alice_group.apply_pending(&alice).unwrap();

    let bob_group =
        Conversation::join(&bob, &invitation.welcome, &arbre).unwrap();

    (alice, bob, alice_group, bob_group)
}

#[test]
fn cycle_complet_1_to_1() {
    let (alice, bob, mut alice_group, mut bob_group) = conversation_a_deux();

    assert_eq!(alice_group.member_count(), 2);
    assert_eq!(bob_group.member_count(), 2);
    // Les deux doivent être à la même epoch, sans quoi rien ne se déchiffre.
    assert_eq!(alice_group.epoch(), bob_group.epoch());
    assert_eq!(alice_group.id(), bob_group.id());

    let ciphertext = alice_group.encrypt(&alice, b"salut Bob").unwrap();
    match bob_group.process(&bob, &ciphertext, &Default::default()).unwrap() {
        Incoming::Application { sender, plaintext } => {
            assert_eq!(plaintext, b"salut Bob");
            assert_eq!(sender.as_deref(), Some("alice@device-1"));
        }
        other => panic!("attendu un message applicatif, reçu {other:?}"),
    }

    let reply = bob_group.encrypt(&bob, b"salut Alice").unwrap();
    match alice_group.process(&alice, &reply, &Default::default()).unwrap() {
        Incoming::Application { sender, plaintext } => {
            assert_eq!(plaintext, b"salut Alice");
            assert_eq!(sender.as_deref(), Some("bob@device-1"));
        }
        other => panic!("attendu un message applicatif, reçu {other:?}"),
    }
}

#[test]
fn le_transport_ne_voit_rien() {
    // C'est *le* test qui compte : le blob qui transite ne doit contenir aucune trace du
    // clair. Tout le reste du protocole n'a de valeur que si celui-ci passe.
    let (alice, _bob, mut alice_group, _bob_group) = conversation_a_deux();

    let secret = b"le code du coffre est 4815162342";
    let ciphertext = alice_group.encrypt(&alice, secret).unwrap();

    assert!(
        !ciphertext.windows(secret.len()).any(|w| w == secret),
        "le clair apparaît dans le message transporté"
    );
    assert!(
        !ciphertext.windows(5).any(|w| w == b"alice"),
        "l'identité de l'expéditeur apparaît en clair dans le message"
    );
}

/// OpenMLS 0.8.1 exécute un `debug_assert!(false)` avant de retourner l'erreur de
/// déchiffrement (`framing/private_message_in.rs:136`). En build debug, un message altéré
/// fait donc **paniquer** le processus au lieu d'être rejeté — un déni de service à distance
/// trivial pour qui peut modifier un octet en transit.
///
/// En release, `debug_assert!` disparaît et l'erreur remonte correctement. Le test est donc
/// vérifié en release uniquement. **Conséquence opérationnelle : ne jamais déployer de build
/// debug de ce code**, et traiter cette contrainte comme un invariant de la CI.
#[test]
#[cfg_attr(debug_assertions, ignore = "OpenMLS panique via debug_assert! ; lancer avec --release")]
fn ciphertext_altere_rejete() {
    let (alice, bob, mut alice_group, mut bob_group) = conversation_a_deux();

    let mut ciphertext = alice_group.encrypt(&alice, "intègre".as_bytes()).unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(bob_group.process(&bob, &ciphertext, &Default::default()).is_err());
}

#[test]
fn rejeu_refuse() {
    let (alice, bob, mut alice_group, mut bob_group) = conversation_a_deux();

    let ciphertext = alice_group.encrypt(&alice, b"une seule fois").unwrap();
    assert!(bob_group.process(&bob, &ciphertext, &Default::default()).is_ok());

    // La clé de message a été consommée : le même chiffré ne doit plus passer.
    assert!(bob_group.process(&bob, &ciphertext, &Default::default()).is_err());
}

#[test]
fn empreintes_croisees_coherentes() {
    let (alice, bob, alice_group, bob_group) = conversation_a_deux();

    let vue_alice = alice_group.peer_fingerprints(&alice);
    let vue_bob = bob_group.peer_fingerprints(&bob);

    assert_eq!(vue_alice.len(), 1);
    assert_eq!(vue_bob.len(), 1);
    assert_eq!(vue_alice[0].0, "bob@device-1");
    assert_eq!(vue_bob[0].0, "alice@device-1");

    // Chacun doit voir l'empreinte réelle de l'autre : c'est ce qui rend la comparaison
    // hors bande capable de détecter une substitution par le serveur.
    assert_eq!(vue_alice[0].1, fingerprint(bob.signature_key()));
    assert_eq!(vue_bob[0].1, fingerprint(alice.signature_key()));
    assert_ne!(vue_alice[0].1, vue_bob[0].1);
}

/// La non-réutilisation des KeyPackages est une responsabilité du **serveur**, pas de la
/// bibliothèque : OpenMLS accepte de réutiliser le même KeyPackage pour deux groupes.
///
/// La clé d'initialisation d'un KeyPackage est pourtant à usage unique. La resservir fait
/// partager le même secret d'entrée à deux groupes distincts, ce qui détruit la forward
/// secrecy de l'ajout. Le serveur doit donc retirer chaque KeyPackage du stock dès qu'il
/// est servi, et signaler l'épuisement du stock d'un appareil.
///
/// Ce test verrouille cette exigence : s'il se met à échouer, c'est qu'une version
/// d'OpenMLS a commencé à refuser la réutilisation — bonne nouvelle, mais la contrainte
/// côté serveur reste nécessaire pour les versions antérieures.
#[test]
fn la_reutilisation_de_key_package_doit_etre_empechee_par_le_serveur() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let key_package = bob.publish_key_package().unwrap();

    let mut premier = Conversation::create(&alice).unwrap();
    premier.invite(&alice, &key_package).unwrap();

    let mut second = Conversation::create(&alice).unwrap();
    assert!(
        second.invite(&alice, &key_package).is_ok(),
        "OpenMLS refuse désormais la réutilisation : mettre à jour la note ci-dessus"
    );
}

#[test]
fn key_package_illisible_refuse() {
    let alice = Identity::create("alice").unwrap();
    let mut groupe = Conversation::create(&alice).unwrap();

    assert!(groupe.invite(&alice, b"ceci n'est pas un key package").is_err());
}

#[test]
fn etat_persiste_et_recharge() {
    let (alice, bob, mut alice_group, mut bob_group) = conversation_a_deux();

    let ciphertext = alice_group.encrypt(&alice, "avant redémarrage".as_bytes()).unwrap();
    bob_group.process(&bob, &ciphertext, &Default::default()).unwrap();

    // L'état exporté est en clair : il doit être chiffré au repos par la plateforme.
    let state = bob.export_state().unwrap();
    assert!(!state.is_empty());

    // Il contient bien du matériel de session, pas une coquille vide.
    assert!(state.len() > 100, "état suspicieusement petit : {} octets", state.len());

    let group_id = bob_group.id();
    let recharge = Conversation::load(&bob, &group_id).unwrap();
    assert_eq!(recharge.epoch(), bob_group.epoch());
    assert_eq!(recharge.member_count(), 2);
}

#[test]
fn groupe_inexistant_refuse() {
    let alice = Identity::create("alice").unwrap();
    assert!(Conversation::load(&alice, b"groupe-inexistant").is_err());
}

#[test]
fn identite_et_conversation_survivent_a_un_redemarrage() {
    let (alice, bob, mut alice_group, mut bob_group) = conversation_a_deux();

    let premier = alice_group.encrypt(&alice, "avant".as_bytes()).unwrap();
    bob_group.process(&bob, &premier, &Default::default()).unwrap();

    // Simule la fermeture de l'application : tout l'état passe par le blob exporté.
    let state = bob.export_state().unwrap();
    let group_id = bob_group.id();
    drop(bob);
    drop(bob_group);

    let bob = Identity::restore(&state).unwrap();
    assert_eq!(bob.name(), "bob@device-1");

    let mut bob_group = Conversation::load(&bob, &group_id).unwrap();
    assert_eq!(bob_group.member_count(), 2);

    // La session doit rester utilisable dans les deux sens après restauration.
    let second = alice_group.encrypt(&alice, "après".as_bytes()).unwrap();
    match bob_group.process(&bob, &second, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, "après".as_bytes()),
        other => panic!("attendu un message applicatif, reçu {other:?}"),
    }

    let reponse = bob_group.encrypt(&bob, "je suis revenu".as_bytes()).unwrap();
    match alice_group.process(&alice, &reponse, &Default::default()).unwrap() {
        Incoming::Application { plaintext, sender } => {
            assert_eq!(plaintext, "je suis revenu".as_bytes());
            assert_eq!(sender.as_deref(), Some("bob@device-1"));
        }
        other => panic!("attendu un message applicatif, reçu {other:?}"),
    }
}

#[test]
fn etat_tronque_refuse() {
    let (_, bob, _, _) = conversation_a_deux();
    let state = bob.export_state().unwrap();

    // Un état corrompu ou tronqué doit produire une erreur, jamais une panique : ces octets
    // viennent du disque et peuvent avoir été altérés.
    for taille in [0, 4, 8, state.len() / 2, state.len() - 1] {
        assert!(
            Identity::restore(&state[..taille]).is_err(),
            "état tronqué à {taille} octets accepté"
        );
    }
}

/// Ajouter un troisième membre à un groupe existant impose de livrer le **commit** aux membres
/// déjà présents, pas seulement le Welcome au nouveau.
///
/// Le cas est passé inaperçu tant qu'un compte n'avait qu'un appareil : le groupe était neuf
/// au moment de l'invitation, et le commit n'avait personne à informer. Dès qu'un compte en a
/// deux, l'oublier fige le correspondant à l'ancienne epoch — plus personne ne déchiffre rien,
/// en silence.
#[test]
fn ajouter_un_membre_impose_de_livrer_le_commit_aux_presents() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let tablette = Identity::create("alice-tablette").unwrap();

    let mut groupe = Conversation::create(&alice).unwrap();
    let invitation = groupe.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = groupe.apply_pending(&alice).unwrap();

    let mut chez_bob =
        Conversation::join(&bob, &invitation.welcome, &arbre).unwrap();

    // Alice ajoute sa tablette. Le groupe avance d'epoch.
    let seconde = groupe.invite(&alice, &tablette.publish_key_package().unwrap()).unwrap();
    let arbre = groupe.apply_pending(&alice).unwrap();
    let mut chez_tablette =
        Conversation::join(&tablette, &seconde.welcome, &arbre).unwrap();

    // Sans cette ligne, Bob reste une epoch en arrière et tout ce qui suit est illisible.
    chez_bob.process(&bob, &seconde.commit, &Default::default()).unwrap();

    let chiffre = chez_bob.encrypt(&bob, b"lisible par les deux appareils").unwrap();

    for (nom, session, identite) in
        [("alice", &mut groupe, &alice), ("tablette", &mut chez_tablette, &tablette)]
    {
        match session.process(identite, &chiffre, &Default::default()).unwrap() {
            Incoming::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"lisible par les deux appareils", "chez {nom}");
            }
            autre => panic!("chez {nom} : message applicatif attendu, reçu {autre:?}"),
        }
    }
}

/// Scénario réel complet : une conversation vivante à laquelle on ajoute un second appareil.
///
/// Reproduit l'ordre exact des messages observé côté client, y compris le trafic **antérieur**
/// à l'ajout — c'est ce trafic qui fait avancer le ratchet et qui manquait au test précédent.
#[test]
fn un_appareil_ajoute_a_une_conversation_vivante_recoit_la_suite() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let tablette = Identity::create("alice").unwrap();

    let mut chez_alice = Conversation::create(&alice).unwrap();
    let inv = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &inv.welcome, &arbre).unwrap();

    // Trafic avant l'ajout : c'est lui qui fait avancer le ratchet.
    let m1 = chez_alice.encrypt(&alice, b"avant l'ajout").unwrap();
    assert!(matches!(chez_bob.process(&bob, &m1, &Default::default()).unwrap(), Incoming::Application { .. }));

    // Alice ajoute sa tablette.
    let ajout = chez_alice.invite(&alice, &tablette.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_tablette =
        Conversation::join(&tablette, &ajout.welcome, &arbre).unwrap();
    chez_bob.process(&bob, &ajout.commit, &Default::default()).unwrap();

    // Alice relit son PROPRE commit : c'est ce que fait le client, qui relève tout ce que le
    // serveur lui sert sans distinguer ce qu'il a lui-même déposé. L'opération doit échouer
    // proprement — et surtout ne pas abîmer l'état du groupe.
    assert!(chez_alice.process(&alice, &ajout.commit, &Default::default()).is_err());

    // Bob répond. Les deux appareils d'Alice doivent lire.
    let m2 = chez_bob.encrypt(&bob, b"apres l'ajout").unwrap();

    match chez_alice.process(&alice, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"apres l'ajout"),
        autre => panic!("chez alice : {autre:?}"),
    }
    match chez_tablette.process(&tablette, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"apres l'ajout"),
        autre => panic!("chez la tablette : {autre:?}"),
    }
}

/// Une tentative de déchiffrement qui échoue **consomme quand même** la génération.
///
/// C'est le piège qui a coûté le plus cher côté client : le curseur de lecture et l'état MLS
/// doivent avancer ensemble. Si le curseur est perdu — une erreur réseau après la boucle de
/// relève, et la persistance qui n'a pas lieu — on relit une enveloppe que le ratchet a déjà
/// dépassée, MLS la refuse définitivement, et le message disparaît sans que rien ne le
/// signale.
///
/// Ce test fige le comportement d'OpenMLS sur lequel repose ce raisonnement.
#[test]
fn relire_un_message_deja_traite_est_definitivement_refuse() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut chez_alice = Conversation::create(&alice).unwrap();
    let inv = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &inv.welcome, &arbre).unwrap();

    let chiffre = chez_bob.encrypt(&bob, b"une seule fois").unwrap();

    match chez_alice.process(&alice, &chiffre, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"une seule fois"),
        autre => panic!("message applicatif attendu, reçu {autre:?}"),
    }

    // La seconde lecture échoue : la clé a été détruite pour préserver la forward secrecy.
    // Un client qui relit ses enveloppes après avoir perdu son curseur perd donc le message.
    assert!(chez_alice.process(&alice, &chiffre, &Default::default()).is_err());
}

/// Le client persiste son état après **chaque** opération et le recharge au démarrage.
/// Ce test reproduit ce cycle autour d'un ajout d'appareil, ce que les autres ne font pas.
#[test]
fn l_ajout_d_un_appareil_survit_a_la_persistance() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut chez_alice = Conversation::create(&alice).unwrap();
    let inv = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &inv.welcome, &arbre).unwrap();

    let m1 = chez_alice.encrypt(&alice, b"avant").unwrap();
    chez_bob.process(&bob, &m1, &Default::default()).unwrap();

    // Alice ajoute sa tablette, puis son état est sauvegardé et rechargé — exactement ce que
    // fait le client entre deux relèves.
    let tablette = Identity::create("alice").unwrap();
    let ajout = chez_alice.invite(&alice, &tablette.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();

    let groupe = chez_alice.id();
    let alice = {
        let etat = alice.export_state().unwrap();
        Identity::restore(&etat).unwrap()
    };
    let mut chez_alice = Conversation::load(&alice, &groupe).unwrap();

    let mut chez_tablette =
        Conversation::join(&tablette, &ajout.welcome, &arbre).unwrap();
    chez_bob.process(&bob, &ajout.commit, &Default::default()).unwrap();

    let m2 = chez_bob.encrypt(&bob, b"apres").unwrap();

    match chez_alice.process(&alice, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"apres"),
        autre => panic!("chez alice après rechargement : {autre:?}"),
    }
    match chez_tablette.process(&tablette, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"apres"),
        autre => panic!("chez la tablette : {autre:?}"),
    }
}

/// Envoyer un message ne dispense pas de lire ce qui l'a précédé.
///
/// Le delivery service attribue un numéro de séquence à chaque enveloppe. Le client était
/// tenté d'avancer son curseur de lecture jusqu'au numéro de son propre message — après tout,
/// il n'a pas à se relire. C'est faux : ce numéro ne dit **rien** des enveloppes déposées
/// entre-temps par les autres. Sauter jusque-là enjambe leurs commits, et le groupe se fige à
/// une epoch périmée sans qu'aucune erreur ne le signale.
///
/// Ici Bob écrit sans avoir appliqué le commit d'Alice : son message est illisible pour tout
/// le monde, y compris pour l'appareil qui existait déjà.
#[test]
fn ecrire_sans_avoir_applique_le_commit_rend_le_message_illisible() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let tablette = Identity::create("alice").unwrap();

    let mut chez_alice = Conversation::create(&alice).unwrap();
    let inv = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &inv.welcome, &arbre).unwrap();

    // Alice ajoute sa tablette. Le commit part, mais Bob ne le lit pas.
    let ajout = chez_alice.invite(&alice, &tablette.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_tablette =
        Conversation::join(&tablette, &ajout.welcome, &arbre).unwrap();

    let m = chez_bob.encrypt(&bob, b"ecrit une epoch trop tot").unwrap();

    assert!(chez_alice.process(&alice, &m, &Default::default()).is_err(), "alice ne devrait pas pouvoir lire");
    assert!(chez_tablette.process(&tablette, &m, &Default::default()).is_err(), "la tablette non plus");

    // Une fois le commit appliqué, la suite repasse — mais le message perdu l'est pour de bon.
    chez_bob.process(&bob, &ajout.commit, &Default::default()).unwrap();
    let m2 = chez_bob.encrypt(&bob, b"apres application du commit").unwrap();

    match chez_alice.process(&alice, &m2, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => {
            assert_eq!(plaintext, b"apres application du commit");
        }
        autre => panic!("chez alice : {autre:?}"),
    }
}

/// Publier avant d'appliquer : si la publication échoue, le groupe doit rester utilisable.
///
/// Appliquer le commit avant de l'avoir publié est irrattrapable. L'émetteur change d'epoch
/// pendant que les autres restent à l'ancienne, et le commit qui les aurait réconciliés
/// n'existe plus nulle part — le groupe meurt en silence, sans qu'aucune erreur ne dise
/// pourquoi. C'est exactement ce qui s'est produit côté client avant cette séparation.
#[test]
fn une_invitation_non_appliquee_laisse_le_groupe_intact() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let tablette = Identity::create("alice").unwrap();

    let mut chez_alice = Conversation::create(&alice).unwrap();
    let inv = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &inv.welcome, &arbre).unwrap();

    let epoch_avant = chez_alice.epoch();

    // Alice prépare l'ajout de sa tablette, puis la publication échoue : on n'applique pas.
    let _abandonne = chez_alice.invite(&alice, &tablette.publish_key_package().unwrap()).unwrap();

    assert_eq!(chez_alice.epoch(), epoch_avant, "l'epoch a bougé sans publication");

    // La conversation continue de fonctionner comme si de rien n'était.
    let m = chez_bob.encrypt(&bob, b"toujours lisible").unwrap();
    match chez_alice.process(&alice, &m, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"toujours lisible"),
        autre => panic!("message applicatif attendu, reçu {autre:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// Retrait de membre et post-compromise security
// ---------------------------------------------------------------------------------------

/// **Le test qui compte de cette phase.**
///
/// C'est la propriété pour laquelle ce projet a choisi MLS, et qu'il n'avait jamais démontrée.
///
/// Le retiré n'est pas privé de ses clés : son état de groupe est intact, il détient tout ce
/// qu'il détenait la seconde d'avant, et rien dans le test ne le lui retire. Ce qui change,
/// c'est que le commit de retrait a re-clé l'arbre — TreeKEM, en O(log N) — et que le secret
/// d'epoch suivant ne dérive plus de rien qu'il connaisse.
///
/// Sans ce test, la révocation d'appareil est décorative : filtrer côté serveur n'empêche pas
/// un appareil volé de déchiffrer ce qu'il intercepte autrement.
#[test]
fn un_membre_retire_ne_dechiffre_plus_la_suite() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    // Groupe à trois.
    let mut chez_alice = Conversation::create(&alice).unwrap();
    let vers_bob = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &vers_bob.welcome, &arbre).unwrap();

    let vers_carol = chez_alice.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_carol = Conversation::join(&carol, &vers_carol.welcome, &arbre).unwrap();
    chez_bob.process(&bob, &vers_carol.commit, &Default::default()).unwrap();

    // Avant le retrait, Carol lit comme tout le monde. Sans cette assertion, le test
    // passerait aussi si Carol n'avait jamais rien pu lire.
    let avant = chez_alice.encrypt(&alice, b"avant le retrait").unwrap();
    chez_bob.process(&bob, &avant, &Default::default()).unwrap();
    match chez_carol.process(&carol, &avant, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"avant le retrait"),
        autre => panic!("message applicatif attendu, reçu {autre:?}"),
    }

    // Alice retire Carol. Discipline habituelle : préparer, publier, appliquer.
    let retrait = chez_alice.remove(&alice, carol.signature_key()).unwrap();
    chez_bob.process(&bob, &retrait.commit, &Default::default()).unwrap();
    chez_alice.apply_pending(&alice).unwrap();

    // Carol reçoit le commit qui l'exclut — elle apprend son exclusion plutôt que de
    // constater un silence. L'appliquer ne lui rend rien.
    let _ = chez_carol.process(&carol, &retrait.commit, &Default::default());

    let apres = chez_alice.encrypt(&alice, "après le retrait".as_bytes()).unwrap();

    // Bob, resté membre, lit toujours.
    match chez_bob.process(&bob, &apres, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, "après le retrait".as_bytes()),
        autre => panic!("message applicatif attendu chez Bob, reçu {autre:?}"),
    }

    // Carol, avec tout son état de groupe, ne peut plus rien en faire.
    assert!(
        chez_carol.process(&carol, &apres, &Default::default()).is_err(),
        "un membre retiré déchiffre encore : la post-compromise security n'existe pas, \
         et la révocation d'appareil ne protège de rien",
    );
}

/// Un retrait suit la même discipline qu'une invitation : préparer, publier, appliquer.
/// Appliquer avant d'avoir publié laisse les autres à l'ancienne epoch avec un commit qui
/// n'existe nulle part — le groupe meurt en silence.
#[test]
fn un_retrait_non_applique_laisse_le_groupe_intact() {
    let (alice, _bob, mut chez_alice, _chez_bob) = conversation_a_deux();
    let epoch = chez_alice.epoch();
    let membres = chez_alice.member_count();

    let bob_key = chez_alice.peer_signature_keys(&alice).into_iter().next().unwrap();
    let _retrait = chez_alice.remove(&alice, &bob_key).unwrap();

    assert_eq!(chez_alice.epoch(), epoch, "l'epoch a avancé avant publication");
    assert_eq!(chez_alice.member_count(), membres, "le membre a été retiré avant publication");
}

/// Deux membres peuvent retirer le même appareil en même temps. Le second commit arrive après
/// que le premier a été appliqué : la cible n'est plus là. L'appelant doit distinguer ce cas
/// bénin d'une vraie erreur, sinon il boucle à réessayer une opération déjà accomplie.
#[test]
fn retirer_un_membre_absent_est_signale_distinctement() {
    let (alice, _bob, mut chez_alice, _chez_bob) = conversation_a_deux();
    let inconnu = Identity::create("inconnu").unwrap();

    assert!(matches!(
        chez_alice.remove(&alice, inconnu.signature_key()),
        Err(crypto_core::CryptoError::UnknownMember),
    ));
}

/// Sortir d'un groupe passe par une proposition qu'un **autre** membre commite : la RFC 9420
/// interdit de se retirer soi-même dans un commit qu'on génère.
#[test]
fn quitter_un_groupe_demande_le_commit_d_un_autre() {
    let (alice, bob, mut chez_alice, mut chez_bob) = conversation_a_deux();

    let demande = chez_bob.leave(&bob).unwrap();

    // Tant que personne ne commite, Bob est toujours là — et lit toujours.
    assert_eq!(chez_alice.member_count(), 2);

    assert!(matches!(chez_alice.process(&alice, &demande, &Default::default()).unwrap(), Incoming::Proposal));

    let depart = chez_alice.commit_pending(&alice).unwrap();
    let _ = chez_bob.process(&bob, &depart.commit, &Default::default());
    chez_alice.apply_pending(&alice).unwrap();

    assert_eq!(chez_alice.member_count(), 1, "Bob est encore dans l'arbre après son départ");

    let apres = chez_alice.encrypt(&alice, b"seule").unwrap();
    assert!(chez_bob.process(&bob, &apres, &Default::default()).is_err(), "Bob lit encore après être parti");
}

/// Une proposition reçue doit être conservée jusqu'au commit qui la reprend. La jeter rendait
/// toute demande de sortie inopérante, en silence : le partant restait dans le groupe et
/// aucune erreur ne le signalait.
#[test]
fn une_proposition_recue_est_conservee_jusqu_au_commit() {
    let (alice, bob, mut chez_alice, mut chez_bob) = conversation_a_deux();

    let demande = chez_bob.leave(&bob).unwrap();
    chez_alice.process(&alice, &demande, &Default::default()).unwrap();

    // Si la proposition avait été jetée, il n'y aurait rien à commiter ici.
    let depart = chez_alice.commit_pending(&alice).unwrap();
    let _ = chez_bob.process(&bob, &depart.commit, &Default::default());
    chez_alice.apply_pending(&alice).unwrap();

    assert_eq!(chez_alice.member_count(), 1);
}

// ---------------------------------------------------------------------------------------
// Groupes administrés
// ---------------------------------------------------------------------------------------

/// Le roster voyage dans le group context, donc dans l'état authentifié : un membre qui
/// rejoint le lit tel qu'il est, sans que personne ait à le lui transmettre à part.
#[test]
fn le_roster_est_transmis_par_le_group_context() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut chez_alice =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let invitation = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();

    let chez_bob = Conversation::join(&bob, &invitation.welcome, &arbre).unwrap();

    let roster = chez_bob.roster().unwrap().expect("le roster n'a pas suivi le Welcome");
    assert_eq!(roster.admin(), "alice");
    assert!(roster.moderators().is_empty());
    assert!(!roster.can_moderate("bob"));

    // Une conversation plate, elle, n'en a pas — et n'en veut pas.
    let (_, _, plate, _) = conversation_a_deux();
    assert!(plate.roster().unwrap().is_none());
}

/// **Le test qui compte pour A.4.**
///
/// Bob n'est pas admin. Son commit est cryptographiquement irréprochable — MLS l'accepte, et
/// c'est bien le problème : c'est à l'application de refuser. Alice doit le rejeter **sans
/// avancer d'un pouce**, sinon le refus lui-même casse le groupe.
#[test]
fn un_commit_non_autorise_est_refuse_sans_alterer_l_etat() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    let mut chez_alice =
        Conversation::create_administered(&alice, "alice".into()).unwrap();

    let vers_bob = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &vers_bob.welcome, &arbre).unwrap();

    let vers_carol = chez_alice.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let _chez_carol = Conversation::join(&carol, &vers_carol.welcome, &arbre).unwrap();
    chez_bob.process(&bob, &vers_carol.commit, &Default::default()).unwrap();

    let epoch = chez_alice.epoch();
    let membres = chez_alice.member_count();

    // Bob, simple membre, tente d'évincer Carol.
    let tentative = chez_bob.remove(&bob, carol.signature_key()).unwrap();

    let refus = chez_alice.process(&alice, &tentative.commit, &Default::default());
    assert!(
        matches!(refus, Err(crypto_core::CryptoError::PolicyViolation(_))),
        "commit non autorisé accepté : la politique ne sert à rien — reçu {refus:?}",
    );

    // Un refus qui aurait quand même fait avancer le ratchet serait pire que pas de politique
    // du tout : le groupe divergerait à chaque tentative hostile.
    assert_eq!(chez_alice.epoch(), epoch, "le refus a fait avancer l'epoch");
    assert_eq!(chez_alice.member_count(), membres, "le refus a modifié la composition");

    // Et le groupe fonctionne toujours normalement après.
    let apres = chez_alice.encrypt(&alice, b"toujours vivant").unwrap();
    match chez_bob.process(&bob, &apres, &Default::default()).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"toujours vivant"),
        autre => panic!("message applicatif attendu, reçu {autre:?}"),
    }
}

/// L'exception qui rend la révocation utile : Bob, non-admin, évince l'appareil volé de Carol
/// parce qu'il détient un certificat de révocation vérifié. Sans elle, l'appareil resterait
/// dans le groupe jusqu'au retour en ligne d'un admin.
#[test]
fn un_non_admin_evince_un_appareil_revoque() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    let mut chez_alice =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let vers_bob = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &vers_bob.welcome, &arbre).unwrap();

    let vers_carol = chez_alice.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_carol = Conversation::join(&carol, &vers_carol.welcome, &arbre).unwrap();
    chez_bob.process(&bob, &vers_carol.commit, &Default::default()).unwrap();

    // Le contexte que l'appelant a construit après avoir VÉRIFIÉ le certificat servi par le
    // serveur. `crypto-core` ne fait pas de réseau : c'est au client de le remplir.
    let context = crypto_core::roles::Context {
        revoked: vec![carol.signature_key().to_vec()],
    };

    let retrait = chez_bob.remove(&bob, carol.signature_key()).unwrap();
    chez_alice.process(&alice, &retrait.commit, &context).unwrap();
    chez_bob.apply_pending(&bob).unwrap();

    assert_eq!(chez_alice.member_count(), 2);

    let apres = chez_alice.encrypt(&alice, b"sans carol").unwrap();
    assert!(chez_carol.process(&carol, &apres, &context).is_err());
}

/// Un contexte vide n'est pas neutre : il fait refuser exactement le cas du téléphone volé.
/// C'est le piège d'implémentation le plus probable côté client, d'où ce test.
#[test]
fn sans_certificat_verifie_le_meme_retrait_est_refuse() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    let mut chez_alice =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let vers_bob = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &vers_bob.welcome, &arbre).unwrap();

    let vers_carol = chez_alice.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let _ = Conversation::join(&carol, &vers_carol.welcome, &arbre).unwrap();
    chez_bob.process(&bob, &vers_carol.commit, &Default::default()).unwrap();

    let retrait = chez_bob.remove(&bob, carol.signature_key()).unwrap();

    assert!(matches!(
        chez_alice.process(&alice, &retrait.commit, &Default::default()),
        Err(crypto_core::CryptoError::PolicyViolation(_)),
    ));
}

/// Un admin promeut quelqu'un, qui gagne alors le droit de retirer.
#[test]
fn une_promotion_confere_les_droits_de_moderation() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();
    let carol = Identity::create("carol").unwrap();

    let mut chez_alice =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let vers_bob = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &vers_bob.welcome, &arbre).unwrap();

    let vers_carol = chez_alice.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_carol = Conversation::join(&carol, &vers_carol.welcome, &arbre).unwrap();
    chez_bob.process(&bob, &vers_carol.commit, &Default::default()).unwrap();

    // Alice promeut Bob.
    let promotion =
        chez_alice.set_roles(&alice, "alice".into(), vec!["bob".into()]).unwrap();
    chez_bob.process(&bob, &promotion.commit, &Default::default()).unwrap();
    chez_carol.process(&carol, &promotion.commit, &Default::default()).unwrap();
    chez_alice.apply_pending(&alice).unwrap();

    assert!(chez_bob.roster().unwrap().unwrap().is_moderator("bob"));

    // Le même retrait qu'un test précédent refusait passe désormais.
    let retrait = chez_bob.remove(&bob, carol.signature_key()).unwrap();
    chez_alice.process(&alice, &retrait.commit, &Default::default()).unwrap();
    chez_bob.apply_pending(&bob).unwrap();

    assert_eq!(chez_alice.member_count(), 2);
}

/// Un non-admin qui se promeut lui-même contournerait toute la politique d'un seul commit.
#[test]
fn un_membre_ordinaire_ne_peut_pas_s_auto_promouvoir() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut chez_alice =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let vers_bob = chez_alice.invite(&alice, &bob.publish_key_package().unwrap()).unwrap();
    let arbre = chez_alice.apply_pending(&alice).unwrap();
    let mut chez_bob = Conversation::join(&bob, &vers_bob.welcome, &arbre).unwrap();

    let tentative =
        chez_bob.set_roles(&bob, "bob".into(), Vec::new()).unwrap();

    assert!(matches!(
        chez_alice.process(&alice, &tentative.commit, &Default::default()),
        Err(crypto_core::CryptoError::PolicyViolation(_)),
    ));
    assert_eq!(chez_alice.roster().unwrap().unwrap().admin(), "alice");
}

/// La capacité `0xF100` doit être déclarée dans les feuilles, sinon MLS refuse d'ajouter un
/// membre à un groupe qui porte l'extension. L'erreur ne se manifesterait qu'à l'ajout, loin
/// de sa cause.
#[test]
fn un_membre_rejoint_bien_un_groupe_portant_l_extension() {
    let alice = Identity::create("alice").unwrap();
    let bob = Identity::create("bob").unwrap();

    let mut chez_alice =
        Conversation::create_administered(&alice, "alice".into()).unwrap();
    let invitation = chez_alice
        .invite(&alice, &bob.publish_key_package().unwrap())
        .expect("ajout refusé : la capacité 0xF100 manque aux KeyPackages");
    let arbre = chez_alice.apply_pending(&alice).unwrap();

    let mut chez_bob = Conversation::join(&bob, &invitation.welcome, &arbre).unwrap();
    let m = chez_alice.encrypt(&alice, b"bienvenue").unwrap();
    assert!(matches!(
        chez_bob.process(&bob, &m, &Default::default()).unwrap(),
        Incoming::Application { .. },
    ));
}

/// Les deux membres dérivent la même clé de canal éphémère, sans échanger quoi que ce soit.
///
/// C'est ce qui permet à l'indicateur de frappe de ne rien coûter au protocole : aucune clé à
/// distribuer, aucun message supplémentaire.
#[test]
fn la_cle_de_signal_est_partagee_par_les_membres() {
    let (alice, bob, alice_group, bob_group) = conversation_a_deux();

    let cote_alice = alice_group.signal_key(&alice).unwrap();
    let cote_bob = bob_group.signal_key(&bob).unwrap();

    assert_eq!(cote_alice.len(), 32);
    assert_eq!(cote_alice, cote_bob, "sans accord, les signaux seraient illisibles");
}

/// **La PCS s'applique au canal éphémère sans une ligne de code supplémentaire.**
///
/// La clé est dérivée du secret d'export de l'epoch : tout commit la change. Un membre retiré
/// perd donc l'indicateur de frappe au même instant qu'il perd les messages — ce qu'il aurait
/// fallu implémenter à la main si le canal avait porté sa propre clé long-terme.
#[test]
fn la_cle_de_signal_change_a_chaque_epoch() {
    let (alice, _bob, mut alice_group, _bob_group) = conversation_a_deux();

    let avant = alice_group.signal_key(&alice).unwrap();
    let epoch_avant = alice_group.epoch();

    // Un ajout suffit à faire tourner l'arbre : c'est le commit qui compte, pas sa nature.
    let carol = Identity::create("carol@device-1").unwrap();
    alice_group.invite(&alice, &carol.publish_key_package().unwrap()).unwrap();
    alice_group.apply_pending(&alice).unwrap();

    let apres = alice_group.signal_key(&alice).unwrap();

    assert_ne!(epoch_avant, alice_group.epoch());
    assert_ne!(avant, apres, "sinon un membre retiré continuerait de lire le canal éphémère");
}
