//! Binding WebAssembly de `crypto-core`.
//!
//! # La garantie E2EE est plus faible dans un navigateur
//!
//! Le serveur livre le JavaScript à chaque chargement de page. Rien n'empêche donc un
//! serveur compromis — ou contraint — de servir une version modifiée du code qui exfiltre
//! les clés. Aucune quantité de WebCrypto, de WASM ou de clés non-extractables ne corrige
//! ce problème : il est structurel.
//!
//! Ce que le web permet malgré tout :
//!
//! * garder les clés hors de portée du JS applicatif (`CryptoKey` non-extractable) ;
//! * une CSP stricte et de l'intégrité de sous-ressource pour réduire les scripts tiers ;
//! * de la code transparency pour rendre une livraison ciblée détectable.
//!
//! Ce que seule une application native ou une extension signée apporte : la certitude que
//! le code exécuté aujourd'hui est celui qui a été audité hier.
//!
//! Cette limite doit être **dite à l'utilisateur** dans l'interface, pas enfouie dans une
//! politique de confidentialité.
//!
//! # État en mémoire
//!
//! Ce module garde l'état de session en mémoire linéaire WASM. Il est perdu au rechargement
//! de la page : l'appelant doit persister [`Client::export_state`] et le rechiffrer au repos.

use std::collections::HashMap;

use crypto_core::lock::derive_unlock_key;
use crypto_core::pairing::{PairingOffer, seal};
use crypto_core::{Account, Conversation, Identity, Incoming};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Poignée unique côté JavaScript : une identité d'appareil et ses conversations.
///
/// Les conversations sont indexées par identifiant de groupe plutôt qu'exposées comme objets
/// séparés. Manipuler deux poignées appariées depuis JS — une identité, une conversation —
/// invite à les mélanger, et chiffrer avec la mauvaise identité est une erreur silencieuse.
#[wasm_bindgen]
pub struct Client {
    identity: Identity,
    conversations: HashMap<Vec<u8>, Conversation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationJs {
    #[serde(with = "serde_bytes")]
    commit: Vec<u8>,
    #[serde(with = "serde_bytes")]
    welcome: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum IncomingJs {
    /// Message à afficher.
    Application {
        sender: Option<String>,
        #[serde(with = "serde_bytes")]
        plaintext: Vec<u8>,
    },
    /// La composition du groupe ou ses clés ont changé : rafraîchir les empreintes affichées.
    GroupChanged,
    /// Proposition en attente d'un commit. Rien à afficher.
    Proposal,
}

/// Les rôles d'un groupe, tels que lus dans le group context.
#[derive(Serialize)]
struct RosterJs {
    admin: String,
    moderators: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerJs {
    name: String,
    fingerprint: String,
}

#[wasm_bindgen]
impl Client {
    /// Crée une identité d'appareil.
    ///
    /// `name` est transporté en clair dans le credential MLS et visible du serveur comme de
    /// tous les membres du groupe. N'y mettez rien de sensible.
    #[wasm_bindgen(js_name = create)]
    pub fn create(name: &str) -> Result<Client, JsError> {
        Ok(Self {
            identity: Identity::create(name).map_err(to_js)?,
            conversations: HashMap::new(),
        })
    }

    /// Reconstruit un client depuis un état exporté.
    ///
    /// `groupIds` est la liste des conversations à recharger. Le stockage MLS ne fournit pas
    /// d'énumération : c'est à l'appelant de conserver cette liste, à côté de l'état.
    ///
    /// Ne restaurez **jamais** un état plus ancien que le dernier exporté : les groupes
    /// reculeraient d'epoch et rejoueraient des clés déjà utilisées. Un état MLS n'est pas
    /// une sauvegarde ordinaire — il ne doit exister qu'une seule copie vivante.
    #[wasm_bindgen(js_name = restore)]
    pub fn restore(state: &[u8], group_ids: Vec<js_sys::Uint8Array>) -> Result<Client, JsError> {
        let identity = Identity::restore(state).map_err(to_js)?;

        let mut conversations = HashMap::new();
        for group_id in group_ids {
            let group_id = group_id.to_vec();
            let conversation = Conversation::load(&identity, &group_id).map_err(to_js)?;
            conversations.insert(group_id, conversation);
        }

        Ok(Self { identity, conversations })
    }

    /// Identifiants des conversations ouvertes, à persister à côté de l'état pour pouvoir
    /// les recharger via [`Client::restore`].
    #[wasm_bindgen(js_name = conversationIds)]
    pub fn conversation_ids(&self) -> Vec<js_sys::Uint8Array> {
        self.conversations
            .keys()
            .map(|id| js_sys::Uint8Array::from(id.as_slice()))
            .collect()
    }

    /// Nom de cet appareil, tel qu'inscrit dans le credential MLS.
    #[wasm_bindgen(js_name = name)]
    pub fn name(&self) -> String {
        self.identity.name().to_owned()
    }

    /// Produit un KeyPackage à publier sur le serveur.
    ///
    /// **À usage unique.** Le serveur doit le retirer du stock dès qu'il le sert, et
    /// l'appelant doit en réapprovisionner régulièrement : sans stock disponible, plus
    /// personne ne peut ouvrir de conversation avec cet appareil.
    #[wasm_bindgen(js_name = publishKeyPackage)]
    pub fn publish_key_package(&self) -> Result<Vec<u8>, JsError> {
        self.identity.publish_key_package().map_err(to_js)
    }

    /// Empreinte de cet appareil, à afficher pour que le correspondant la compare.
    /// Clé publique de signature MLS de cet appareil.
    ///
    /// Elle doit être attestée par le compte **en même temps** que la clé d'authentification
    /// HTTP : attestées séparément, on pourrait recombiner l'attestation d'un appareil
    /// légitime avec la clé MLS d'un appareil hostile.
    #[wasm_bindgen(js_name = signatureKey)]
    pub fn signature_key(&self) -> Vec<u8> {
        self.identity.signature_key().to_vec()
    }

    #[wasm_bindgen(js_name = fingerprint)]
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Crée une conversation et retourne son identifiant de groupe.
    #[wasm_bindgen(js_name = createConversation)]
    pub fn create_conversation(&mut self) -> Result<Vec<u8>, JsError> {
        let conversation = Conversation::create(&self.identity).map_err(to_js)?;
        let id = conversation.id();
        self.conversations.insert(id.clone(), conversation);
        Ok(id)
    }

    /// Crée un groupe administré. Le créateur en est l'admin, seul et unique.
    ///
    /// À réserver aux vrais groupes. Un 1-to-1 doit passer par `createConversation` : des rôles
    /// n'y ont aucun sens, et le groupe plat est la forme correcte.
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&mut self, admin: String) -> Result<Vec<u8>, JsError> {
        let conversation =
            Conversation::create_administered(&self.identity, admin).map_err(to_js)?;
        let id = conversation.id();
        self.conversations.insert(id.clone(), conversation);
        Ok(id)
    }

    /// Roster du groupe : `{admin, moderators}`, ou `null` si le groupe est plat.
    #[wasm_bindgen(js_name = roster)]
    pub fn roster(&self, group_id: &[u8]) -> Result<JsValue, JsError> {
        let roster = self
            .conversations
            .get(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .roster()
            .map_err(to_js)?;

        to_value(&roster.map(|r| RosterJs {
            admin: r.admin().to_owned(),
            moderators: r.moderators().to_vec(),
        }))
    }

    /// Remplace les rôles du groupe. Comme tout commit, à publier avant `applyPending`.
    ///
    /// Passer un `admin` différent de l'actuel **transmet le groupe** : l'émetteur ne pourra
    /// pas se le reprendre.
    #[wasm_bindgen(js_name = setRoles)]
    pub fn set_roles(
        &mut self,
        group_id: &[u8],
        admin: String,
        moderators: Vec<String>,
    ) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        Ok(self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .set_roles(identity, admin, moderators)
            .map_err(to_js)?
            .commit)
    }

    /// Prépare le retrait d'un membre, désigné par sa clé de signature MLS.
    ///
    /// C'est ce retrait — et non le filtrage côté serveur — qui prive effectivement l'appareil
    /// de la suite : le commit re-clé l'arbre. Même discipline que `invite` : publier, puis
    /// `applyPending`.
    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&mut self, group_id: &[u8], mls_key: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        Ok(self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .remove(identity, mls_key)
            .map_err(to_js)?
            .commit)
    }

    /// Demande à quitter le groupe. Retourne une **proposition**, pas un commit.
    ///
    /// La RFC 9420 interdit de se retirer soi-même dans un commit qu'on génère : un autre
    /// membre doit la reprendre via `commitPending`. Conséquence à afficher honnêtement —
    /// tant que personne ne commite, le départ n'a pas eu lieu et la conversation continue
    /// d'être lue.
    #[wasm_bindgen(js_name = leaveGroup)]
    pub fn leave_group(&mut self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        self.conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .leave(identity)
            .map_err(to_js)
    }

    /// Commite les propositions en attente — typiquement la demande de sortie d'un membre.
    #[wasm_bindgen(js_name = commitPending)]
    pub fn commit_pending(&mut self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        Ok(self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .commit_pending(identity)
            .map_err(to_js)?
            .commit)
    }

    /// Clés de signature MLS des autres membres, telles qu'elles figurent dans l'arbre.
    ///
    /// Vient de l'état authentifié, pas du serveur. C'est ce qui permet au client de constater
    /// qu'un membre de l'arbre ne figure plus parmi les appareils actifs de son compte.
    #[wasm_bindgen(js_name = peerSignatureKeys)]
    pub fn peer_signature_keys(&self, group_id: &[u8]) -> Result<JsValue, JsError> {
        let keys = self
            .conversations
            .get(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .peer_signature_keys(&self.identity);

        to_value(&keys.into_iter().map(serde_bytes::ByteBuf::from).collect::<Vec<_>>())
    }

    /// Prépare l'ajout d'un membre. Retourne `{commit, welcome}` **sans rien appliquer**.
    ///
    /// Les deux parties ne vont pas au même endroit : le `commit` aux membres déjà présents,
    /// le `welcome` au seul invité.
    ///
    /// Le groupe reste à son epoch actuelle jusqu'à [`Client::applyPending`]. Publier d'abord,
    /// appliquer ensuite : l'inverse casse le groupe sans recours si la publication échoue —
    /// l'émetteur aurait changé d'epoch, les autres non, et le commit serait perdu.
    #[wasm_bindgen(js_name = invite)]
    pub fn invite(&mut self, group_id: &[u8], key_package: &[u8]) -> Result<JsValue, JsError> {
        // `identity` est sorti du `self` avant l'emprunt mutable de la map : les deux champs
        // sont disjoints, mais passer par une méthode emprunterait `self` en entier.
        let identity = &self.identity;
        let invitation = self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .invite(identity, key_package)
            .map_err(to_js)?;

        to_value(&InvitationJs {
            commit: invitation.commit,
            welcome: invitation.welcome,
        })
    }

    /// Applique le commit préparé par `invite`, une fois celui-ci publié.
    ///
    /// Retourne l'arbre de ratchet à jour, à transmettre à l'invité avec son Welcome. Il ne
    /// peut pas être produit plus tôt : tant que le commit n'est pas appliqué, l'arbre ne
    /// contient pas le nouveau membre et son Welcome serait rejeté.
    #[wasm_bindgen(js_name = applyPending)]
    pub fn apply_pending(&mut self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        self.conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .apply_pending(identity)
            .map_err(to_js)
    }

    /// Rejoint une conversation depuis un Welcome. Retourne l'identifiant de groupe.
    #[wasm_bindgen(js_name = join)]
    pub fn join(&mut self, welcome: &[u8], ratchet_tree: &[u8]) -> Result<Vec<u8>, JsError> {
        let conversation =
            Conversation::join(&self.identity, welcome, ratchet_tree).map_err(to_js)?;
        let id = conversation.id();
        self.conversations.insert(id.clone(), conversation);
        Ok(id)
    }

    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let identity = &self.identity;
        self.conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .encrypt(identity, plaintext)
            .map_err(to_js)
    }

    /// Traite un message entrant : applicatif ou changement de groupe.
    ///
    /// Le résultat doit être traité dans les deux cas. Ignorer un `groupChanged` laisse
    /// l'appareil à une epoch périmée, et tout ce qui suit devient indéchiffrable.
    #[wasm_bindgen(js_name = process)]
    pub fn process(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        revoked: Vec<js_sys::Uint8Array>,
    ) -> Result<JsValue, JsError> {
        // Clés de signature MLS dont le client a **vérifié** le certificat de révocation.
        //
        // Une liste vide n'est pas neutre : elle fait refuser le retrait d'un appareil révoqué
        // par un membre non-admin, c'est-à-dire exactement le cas du téléphone volé. Le client
        // doit la remplir depuis la liste d'appareils du compte concerné, après vérification.
        let context = crypto_core::roles::Context {
            revoked: revoked.iter().map(|k| k.to_vec()).collect(),
        };

        let identity = &self.identity;
        let incoming = self
            .conversations
            .get_mut(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))?
            .process(identity, message, &context)
            .map_err(to_js)?;

        to_value(&match incoming {
            Incoming::Application { sender, plaintext } => {
                IncomingJs::Application { sender, plaintext }
            }
            Incoming::GroupChanged => IncomingJs::GroupChanged,
            Incoming::Proposal => IncomingJs::Proposal,
        })
    }

    /// Empreintes des autres membres, à comparer hors bande.
    ///
    /// L'interface doit rendre cette comparaison possible et compréhensible. Sans elle, un
    /// serveur malveillant peut se placer au milieu de deux sessions parfaitement chiffrées
    /// sans qu'aucune vérification cryptographique ne le détecte.
    #[wasm_bindgen(js_name = peerFingerprints)]
    pub fn peer_fingerprints(&self, group_id: &[u8]) -> Result<JsValue, JsError> {
        let peers: Vec<PeerJs> = self
            .conversation(group_id)?
            .peer_fingerprints(&self.identity)
            .into_iter()
            .map(|(name, fingerprint)| PeerJs { name, fingerprint })
            .collect();

        to_value(&peers)
    }

    /// Clé symétrique du canal éphémère de ce groupe, pour l'epoch courante.
    ///
    /// **Ces octets ne doivent servir qu'aux signaux jetables.** Ils ne passent pas par le
    /// ratchet applicatif, donc ils n'offrent aucune forward secrecy à l'intérieur d'une
    /// epoch, et ils n'authentifient pas l'émetteur — la clé est celle du groupe. Y faire
    /// transiter un message vaudrait annuler les deux propriétés pour lesquelles MLS a été
    /// choisi.
    ///
    /// La clé change à chaque commit : un membre retiré perd ce canal en même temps que le
    /// reste, sans traitement particulier.
    #[wasm_bindgen(js_name = signalKey)]
    pub fn signal_key(&self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.conversation(group_id)?.signal_key(&self.identity)?)
    }

    /// Epoch courante du groupe. Deux membres à des epochs différentes ne peuvent pas se
    /// lire : c'est la première chose à regarder quand un message ne passe pas.
    #[wasm_bindgen(js_name = epoch)]
    pub fn epoch(&self, group_id: &[u8]) -> Result<u64, JsError> {
        Ok(self.conversation(group_id)?.epoch())
    }

    /// Exporte l'état complet des sessions.
    ///
    /// **Ce blob contient les clés privées en clair.** Il ne doit jamais atteindre
    /// `localStorage`, ni un backup, ni le serveur. Le chiffrer d'abord avec une clé
    /// `CryptoKey` non-extractable détenue dans IndexedDB.
    ///
    /// Ne jamais restaurer un état *ancien* : cela fait reculer le groupe d'epoch et rejoue
    /// des clés déjà utilisées, ce qui détruit la forward secrecy.
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Result<Vec<u8>, JsError> {
        self.identity.export_state().map_err(to_js)
    }

    fn conversation(&self, group_id: &[u8]) -> Result<&Conversation, JsError> {
        self.conversations
            .get(group_id)
            .ok_or_else(|| JsError::new("conversation inconnue"))
    }
}

/// Les erreurs traversant la frontière WASM sont aplaties en message.
///
/// Elles ne doivent jamais contenir de matériel secret : un message d'erreur finit dans la
/// console, dans un rapport de crash, ou dans un service de télémétrie tiers.
fn to_js(err: crypto_core::CryptoError) -> JsError {
    JsError::new(&err.to_string())
}

/// Sérialise vers JavaScript en produisant de vrais `Uint8Array`.
///
/// `serde_wasm_bindgen` produit bien un `Uint8Array` — mais seulement pour les valeurs qui
/// passent par `serialize_bytes`. Or `Vec<u8>` emprunte par défaut le chemin « séquence » et
/// ressort en `Array` de nombres. Le
/// code JavaScript reçoit alors quelque chose qui *ressemble* à un tableau d'octets mais que
/// `TextDecoder`, `fetch` ou `crypto.subtle` refusent. Combiné à `#[serde(with =
/// "serde_bytes")]` sur les champs concernés, ce sérialiseur produit le bon type.
///
/// À noter : les tests `wasm-bindgen-test` ne détectent pas ce défaut, parce qu'ils
/// désérialisent vers des types Rust, lesquels acceptent les deux représentations. Seul un
/// vrai client JavaScript le révèle.
fn to_value<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    let serializer = serde_wasm_bindgen::Serializer::new();
    value
        .serialize(&serializer)
        .map_err(|e| JsError::new(&e.to_string()))
}


/// Poignée du compte pseudonyme.
///
/// Séparée de [`Client`] à dessein : un compte survit à ses appareils, et un appareil peut
/// exister le temps d'un appairage sans détenir la clé du compte. Les fusionner ferait croire
/// que l'un implique l'autre.
///
/// **Cet objet détient la clé racine du compte.** La perdre équivaut à perdre le compte ; la
/// divulguer équivaut à le céder.
#[wasm_bindgen]
pub struct AccountKey {
    inner: Account,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedAccountJs {
    /// À afficher **une seule fois**. Elle n'est pas conservée et ne peut pas être réaffichée :
    /// une phrase que l'application peut remontrer est une phrase qu'un voleur d'appareil
    /// déverrouillé peut remontrer aussi.
    phrase: String,
    #[serde(with = "serde_bytes")]
    identity_key: Vec<u8>,
}

#[wasm_bindgen]
impl AccountKey {
    /// Crée un compte et retourne `{phrase, identityKey}`.
    pub fn generate() -> Result<JsValue, JsError> {
        let (inner, phrase) = Account::generate().map_err(to_js)?;
        let identity_key = inner.identity_key().to_vec();

        // La poignée est jetée ici : l'appelant rappelle `restore` avec la phrase. Retourner
        // à la fois un objet et une poignée obligerait à les tenir appariés côté JS, et une
        // phrase orpheline d'un compte est exactement le bug qu'on ne veut pas.
        drop(inner);
        to_value(&CreatedAccountJs { phrase, identity_key })
    }

    /// Reconstruit le compte depuis sa phrase de récupération.
    pub fn restore(phrase: &str) -> Result<AccountKey, JsError> {
        Ok(Self { inner: Account::from_phrase(phrase).map_err(to_js)? })
    }

    /// Reconstruit le compte depuis la graine reçue lors d'un appairage.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> Result<AccountKey, JsError> {
        let seed: [u8; 64] = seed
            .try_into()
            .map_err(|_| JsError::new("graine de compte de taille invalide"))?;
        Ok(Self { inner: Account::from_seed(seed) })
    }

    #[wasm_bindgen(js_name = identityKey)]
    pub fn identity_key(&self) -> Vec<u8> {
        self.inner.identity_key().to_vec()
    }

    /// Empreinte du compte, à comparer hors bande.
    ///
    /// Stable quand le compte gagne ou perd un appareil : la détection d'un appareil hostile
    /// passe par la notification d'ajout, pas par un changement d'empreinte qui serait ignoré
    /// à force de se produire légitimement.
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    /// Signe l'appartenance d'un appareil à ce compte.
    pub fn attest(
        &self,
        handle: &str,
        device_id: &str,
        auth_key: &[u8],
        mls_key: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.attest(handle, device_id, auth_key, mls_key).map_err(to_js)?.to_vec())
    }

    /// Signe la révocation d'un appareil de ce compte.
    ///
    /// Le certificat est vérifiable par n'importe qui détenant la clé publique du compte :
    /// c'est ce qui permet à un **autre** membre du groupe de commiter le retrait sans croire
    /// le serveur sur parole.
    pub fn revoke(
        &self,
        handle: &str,
        device_id: &str,
        revoked_at: u64,
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.revoke(handle, device_id, revoked_at).map_err(to_js)?.to_vec())
    }

    /// Signe le passage de ce compte à une nouvelle clé d'identité.
    ///
    /// À appeler sur l'**ancien** compte, qui désigne ainsi son successeur.
    ///
    /// C'est la seule réponse réelle à un appareil volé : celui-ci détient la graine, donc le
    /// compte entier, et le révoquer ne l'empêche pas d'en attester un nouveau. La rotation,
    /// elle, rend invérifiables toutes les attestations d'un coup.
    pub fn rotate(
        &self,
        handle: &str,
        new_identity_key: &[u8],
        rotated_at: u64,
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.rotate(handle, new_identity_key, rotated_at).map_err(to_js)?.to_vec())
    }

    /// Graine à transmettre à un appareil qu'on appaire. **Vaut le compte entier.**
    #[wasm_bindgen(js_name = exportSeed)]
    pub fn export_seed(&self) -> Vec<u8> {
        self.inner.export_seed().to_vec()
    }

    /// Clé symétrique du coffre de sauvegarde, dérivée à la demande.
    #[wasm_bindgen(js_name = vaultKey)]
    pub fn vault_key(&self) -> Vec<u8> {
        self.inner.vault_key().to_vec()
    }
}

/// Vérifie une attestation d'appareil servie par le serveur.
///
/// **À rappeler systématiquement côté client.** Le serveur vérifie déjà à l'écriture, mais
/// c'est précisément le serveur qu'on soupçonne : sa vérification n'est qu'un filtre précoce,
/// jamais une garantie. Voir le test
/// `un_appareil_fantome_injecte_en_sql_ne_passe_pas_la_verification_du_client`.
#[wasm_bindgen(js_name = verifyAttestation)]
pub fn verify_attestation(
    identity_key: &[u8],
    handle: &str,
    device_id: &str,
    auth_key: &[u8],
    mls_key: &[u8],
    attestation: &[u8],
) -> bool {
    let claim = attest::DeviceClaim { handle, device_id, auth_key, mls_key };
    attest::verify(identity_key, &claim, attestation).is_ok()
}

/// Vérifie un certificat de révocation servi par le serveur.
///
/// **À appeler systématiquement.** Un client qui croirait le serveur sur parole lui rendrait
/// le pouvoir de faire évincer les appareils de son choix — de la censure ciblée, durable, et
/// indiscernable d'une révocation légitime.
#[wasm_bindgen(js_name = verifyRevocation)]
pub fn verify_revocation(
    identity_key: &[u8],
    handle: &str,
    device_id: &str,
    revoked_at: u64,
    revocation: &[u8],
) -> bool {
    let claim = attest::RevocationClaim { handle, device_id, revoked_at };
    attest::verify_revocation(identity_key, &claim, revocation).is_ok()
}

// ---------------------------------------------------------------- dépôt anonyme

/// Authentifie un dépôt d'enveloppe sans révéler qui dépose.
///
/// # Ce que ce MAC dit au serveur
///
/// Que le déposant détient la clé du groupe, donc qu'il en est membre. Rien de plus. Le serveur
/// n'a jamais eu besoin de savoir **qui** poste — seulement que le posteur a le droit de le
/// faire, pour ne pas servir de boîte aux lettres ouverte. Ce sont deux choses distinctes, et
/// la seconde suffit.
///
/// L'expéditeur réel reste authentifié **par MLS**, à l'intérieur du chiffré : les
/// destinataires le lisent, le serveur non.
///
/// # Pourquoi le calcul est fait ici et pas en JavaScript
///
/// Le message authentifié a un format canonique, partagé avec le vérificateur. Le réécrire côté
/// client dupliquerait la définition — exactement ce que la crate `attest` existe pour
/// supprimer. Un octet de divergence, et tous les dépôts sont refusés.
#[wasm_bindgen(js_name = postMac)]
pub fn post_mac(
    posting_key: &[u8],
    group_id: &[u8],
    nonce: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, JsError> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let message = attest::post_message(group_id, nonce, &Sha256::digest(body))
        .map_err(|_| JsError::new("dépôt mal formé"))?;

    let mut mac = <Hmac<Sha256>>::new_from_slice(posting_key)
        .map_err(|_| JsError::new("clé de dépôt invalide"))?;
    mac.update(&message);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// MAC accompagnant le dépôt d'un **signal éphémère**.
///
/// Jumeau de [`post_mac`], au domaine près — voir `attest::signal_message` pour la raison de
/// cette séparation. Il prouve la même chose : l'appartenance au groupe, pas l'identité.
#[wasm_bindgen(js_name = signalMac)]
pub fn signal_mac(
    posting_key: &[u8],
    group_id: &[u8],
    nonce: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, JsError> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let message = attest::signal_message(group_id, nonce, &Sha256::digest(body))
        .map_err(|_| JsError::new("signal mal formé"))?;

    let mut mac = <Hmac<Sha256>>::new_from_slice(posting_key)
        .map_err(|_| JsError::new("clé de dépôt invalide"))?;
    mac.update(&message);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Message à signer pour ouvrir une session gateway.
///
/// Retourne les octets à signer, **pas la signature** : la clé d'authentification de l'appareil
/// est une clé WebCrypto non extractible, qui ne quitte jamais le navigateur et n'entre donc
/// jamais dans ce module. La séparation est délibérée — c'est elle qui fait qu'un bug ici ne
/// peut pas divulguer la clé.
///
/// Même argument que pour [`post_mac`] quant au lieu du calcul : le format canonique vit dans la
/// crate `attest`, et le réécrire en JavaScript le dupliquerait. Un octet de divergence, et
/// aucune session ne s'ouvre.
#[wasm_bindgen(js_name = gatewayChallenge)]
pub fn gateway_challenge(device_id: &str, nonce: &[u8]) -> Result<Vec<u8>, JsError> {
    attest::gateway_message(device_id, nonce).map_err(|_| JsError::new("défi mal formé"))
}

// ---------------------------------------------------------------- journal de transparence

/// Hash de feuille d'une entrée du journal, tel que le serveur doit l'avoir calculé.
///
/// Le client le recalcule lui-même à partir du handle et de la clé qu'on lui sert : accepter le
/// hash fourni par le serveur reviendrait à lui demander de prouver ce qu'il affirme avec ce
/// qu'il affirme.
#[wasm_bindgen(js_name = logLeaf)]
pub fn log_leaf(handle: &str, identity_key: &[u8]) -> Vec<u8> {
    transparency::leaf_hash(&transparency::entry(handle, identity_key)).to_vec()
}

/// Vérifie qu'une clé figure bien dans le journal, à l'indice annoncé.
///
/// **C'est ce qui ferme le trou du premier contact.** Les attestations empêchent le serveur
/// d'ajouter un appareil ; elles ne l'empêchent pas de servir sa propre clé de compte à
/// quelqu'un qui n'a rien à quoi comparer. Une preuve d'inclusion, elle, ne se fabrique pas.
#[wasm_bindgen(js_name = verifyInclusion)]
pub fn verify_inclusion(
    leaf: &[u8],
    index: usize,
    size: usize,
    proof: Vec<js_sys::Uint8Array>,
    root: &[u8],
) -> bool {
    let (Ok(leaf), Ok(root)) = (to_hash(leaf), to_hash(root)) else { return false };
    let Some(proof) = to_hashes(&proof) else { return false };

    transparency::verify_inclusion(&leaf, index, size, &proof, &root).is_ok()
}

/// Vérifie que le journal actuel **prolonge** celui qu'on avait déjà vu, sans réécriture.
///
/// Sans ce contrôle, le serveur pourrait remplacer une clé déjà publiée et servir un journal
/// tout aussi cohérent : le journal ne prouverait plus rien sur le passé.
#[wasm_bindgen(js_name = verifyConsistency)]
pub fn verify_consistency(
    from: usize,
    old_root: &[u8],
    to: usize,
    new_root: &[u8],
    proof: Vec<js_sys::Uint8Array>,
) -> bool {
    let (Ok(old_root), Ok(new_root)) = (to_hash(old_root), to_hash(new_root)) else {
        return false;
    };
    let Some(proof) = to_hashes(&proof) else { return false };

    transparency::verify_consistency(from, &old_root, to, &new_root, &proof).is_ok()
}

/// Vérifie qu'une tête de journal a bien été signée par le journal.
///
/// **Ce que cela prouve est étroit** : que la tête vient du journal. Pas qu'elle soit la seule
/// qu'il ait émise. Un serveur qui tient deux journaux signe deux têtes également valides ;
/// seule la comparaison entre clients l'attrape.
#[wasm_bindgen(js_name = verifyTreeHead)]
pub fn verify_tree_head(
    log_key: &[u8],
    size: u64,
    root: &[u8],
    timestamp: u64,
    signature: &[u8],
) -> bool {
    let Ok(root) = to_hash(root) else { return false };
    transparency::TreeHead { size, root, timestamp }.verify(log_key, signature).is_ok()
}

fn to_hash(bytes: &[u8]) -> Result<transparency::Hash, ()> {
    bytes.try_into().map_err(|_| ())
}

fn to_hashes(values: &[js_sys::Uint8Array]) -> Option<Vec<transparency::Hash>> {
    values.iter().map(|v| to_hash(&v.to_vec()).ok()).collect()
}

/// Empreinte d'un compte dont on ne détient que la clé publique.
#[wasm_bindgen(js_name = accountFingerprint)]
pub fn account_fingerprint(identity_key: &[u8]) -> String {
    attest::fingerprint(identity_key)
}


/// Offre d'appairage détenue par le **nouvel** appareil.
///
/// C'est lui qui affiche le QR, l'ancien qui scanne. Ce sens est obligatoire : un QR est
/// photographiable, il ne doit donc contenir aucun secret. Ici il ne porte qu'une clé publique
/// éphémère et une adresse de dépôt.
#[wasm_bindgen]
pub struct Pairing {
    offer: Option<PairingOffer>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedJs {
    #[serde(with = "serde_bytes")]
    plaintext: Vec<u8>,
    /// Code court à comparer de visu sur les deux écrans.
    confirmation: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedJs {
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    confirmation: String,
}

#[wasm_bindgen]
impl Pairing {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Pairing {
        Self { offer: Some(PairingOffer::generate()) }
    }

    /// Identifiant d'appairage : l'adresse de dépôt sur le serveur. Public, sans valeur seul.
    pub fn id(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.expect()?.id().to_vec())
    }

    /// Clé publique éphémère à publier dans le QR.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.expect()?.public_key().to_vec())
    }

    /// Ouvre le paquet déposé par l'appareil d'origine.
    ///
    /// Consomme l'offre : le secret éphémère ne sert qu'une fois, ce qui interdit de rejouer
    /// un ancien paquet contre la même clé. Un second appel échoue, délibérément.
    pub fn open(&mut self, sealed: &[u8]) -> Result<JsValue, JsError> {
        let offer = self
            .offer
            .take()
            .ok_or_else(|| JsError::new("offre d'appairage déjà consommée"))?;

        let opened = offer.open(sealed).map_err(to_js)?;
        to_value(&OpenedJs { plaintext: opened.plaintext, confirmation: opened.confirmation })
    }

    fn expect(&self) -> Result<&PairingOffer, JsError> {
        self.offer.as_ref().ok_or_else(|| JsError::new("offre d'appairage déjà consommée"))
    }
}

impl Default for Pairing {
    fn default() -> Self {
        Self::new()
    }
}

/// Scelle un paquet à destination du nouvel appareil, depuis les valeurs lues dans le QR.
///
/// Retourne `{payload, confirmation}`. Le code de confirmation doit être **affiché des deux
/// côtés et comparé par l'utilisateur** : c'est ce qui atteste que les deux appareils parlent
/// bien du même échange.
#[wasm_bindgen(js_name = sealPairing)]
pub fn seal_pairing(
    offer_public: &[u8],
    offer_id: &[u8],
    plaintext: &[u8],
) -> Result<JsValue, JsError> {
    let (payload, confirmation) = seal(offer_public, offer_id, plaintext).map_err(to_js)?;
    to_value(&SealedJs { payload, confirmation })
}


/// Dérive la clé de déverrouillage locale depuis un mot de passe.
///
/// Argon2id, 64 Mio, 3 passes. **Environ une seconde** : c'est le prix à payer une fois par
/// déverrouillage, et à chaque essai par un attaquant qui aurait obtenu la base.
///
/// Cette fonction n'existe pas dans WebCrypto. PBKDF2, lui, y est — mais il ne coûte que du
/// calcul, ce qu'un GPU fait par milliards. Le coût mémoire d'Argon2id est ce qui ramène une
/// attaque parallèle au niveau d'un processeur ordinaire.
///
/// Appeler cette fonction gèle le fil d'exécution pendant sa durée. À lancer depuis un Worker
/// si l'interface doit rester réactive.
#[wasm_bindgen(js_name = deriveUnlockKey)]
pub fn derive_unlock_key_js(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(derive_unlock_key(password, salt).map_err(to_js)?.to_vec())
}
