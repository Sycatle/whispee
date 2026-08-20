//! Une conversation = un groupe MLS.
//!
//! Un 1-to-1 est un groupe de 2. C'est tout l'intérêt de MLS ici : passer aux groupes plus
//! tard ne demandera aucune réécriture, là où la stack Signal imposerait d'ajouter Sender
//! Keys, un mécanisme entièrement distinct du Double Ratchet.

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

use crate::error::{CryptoError, Result, mls};
use crate::identity::{Identity, fingerprint, parse_key_package};
use crate::roles::{self, ROSTER_EXTENSION, Roster};

/// Ce que produit l'ajout d'un membre. Les trois parties partent par des chemins différents :
/// le commit va aux membres déjà présents, le welcome au seul nouvel arrivant.
pub struct Invitation {
    /// À diffuser aux membres existants pour qu'ils avancent d'epoch.
    pub commit: Vec<u8>,
    /// À remettre au seul invité. Contient les secrets qui lui permettent de rejoindre.
    ///
    /// L'arbre public qui l'accompagne n'est pas ici : il n'existe qu'une fois le commit
    /// appliqué, et sort donc de [`Conversation::apply_pending`].
    pub welcome: Vec<u8>,
}

/// Un changement d'état de groupe prêt à publier : retrait, sortie commitée, changement de
/// roster. Un seul destinataire, contrairement à [`Invitation`] : il n'y a personne à
/// accueillir, seulement les membres à faire avancer d'epoch.
///
/// Un exclu reçoit le commit lui aussi, s'il est encore branché — c'est ainsi qu'il apprend
/// son exclusion plutôt que de constater un silence. Il ne peut plus rien déchiffrer ensuite.
pub struct Change {
    pub commit: Vec<u8>,
}

pub struct Conversation {
    group: MlsGroup,
}

/// Emballe le roster dans les extensions de group context, avec la capacité qui va avec.
///
/// # Pourquoi `RequiredCapabilities` accompagne le roster
///
/// MLS exige que toute extension du group context figure dans les capacités requises. C'est
/// une contrainte utile plutôt qu'une formalité : elle interdit à un client qui **ne sait pas
/// lire le roster** de rejoindre un groupe administré. Sans elle, un tel client entrerait,
/// appliquerait une politique vide, accepterait les commits que les autres refusent — et
/// forkerait le groupe sans que rien ne le signale.
///
/// L'erreur est propagée plutôt que supposée impossible : une constante mal choisie serait
/// ainsi refusée à la création du groupe, et non des mois plus tard sur un changement de
/// roster.
fn roster_extension(roster: &Roster) -> Result<Extensions<GroupContext>> {
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(ROSTER_EXTENSION)],
            &[],
            &[],
        )),
        Extension::Unknown(ROSTER_EXTENSION, UnknownExtension(roster.encode()?)),
    ])
    .map_err(mls)
}

/// Handle porté par un credential MLS. Un credential non basique n'a pas de handle exploitable
/// et ne peut donc satisfaire aucune règle : la chaîne vide n'appartient à aucun roster.
fn handle_of(credential: &Credential) -> String {
    BasicCredential::try_from(credential.clone())
        .ok()
        .map(|c| String::from_utf8_lossy(c.identity()).into_owned())
        .unwrap_or_default()
}

impl Conversation {
    /// Crée une conversation **plate** : aucun rôle, tout le monde peut tout faire.
    ///
    /// C'est la forme correcte d'un 1-to-1, où des rôles d'administration n'auraient aucun
    /// sens. Pour un groupe administré, voir [`Conversation::create_administered`].
    pub fn create(identity: &Identity) -> Result<Self> {
        Self::create_with(identity, None)
    }

    /// Crée un groupe administré. Le créateur en est l'admin, seul et unique.
    ///
    /// Le roster entre dans le **group context**, donc dans l'état authentifié et haché par
    /// chaque commit. Voir `roles.rs` pour ce que cela implique — et pour l'avertissement
    /// essentiel : MLS n'applique pas ces règles, ce sont les clients qui le font.
    pub fn create_administered(identity: &Identity, admin: String) -> Result<Self> {
        Self::create_with(identity, Some(Roster::new(admin, Vec::new())?))
    }

    fn create_with(identity: &Identity, roster: Option<Roster>) -> Result<Self> {
        // Les capacités du créateur sont configurées ICI, et non par `publish_key_package` :
        // le créateur n'a pas de KeyPackage, sa feuille est construite depuis cette config.
        // Les oublier fait échouer le premier ajout de membre, avec une erreur qui désigne
        // les extensions sans dire laquelle des deux feuilles est en cause.
        let mut builder = MlsGroupCreateConfig::builder()
            .ciphersuite(crate::identity::CIPHERSUITE)
            .capabilities(crate::identity::capabilities());

        if let Some(roster) = &roster {
            builder = builder.with_group_context_extensions(roster_extension(roster)?);
        }

        let group = MlsGroup::new(
            &identity.provider,
            &identity.signer,
            &builder.build(),
            identity.credential.clone(),
        )
        .map_err(mls)?;

        Ok(Self { group })
    }

    /// Roster du groupe, ou `None` si le groupe est plat.
    ///
    /// Lu dans le group context, donc dans l'état authentifié : ce n'est pas une information
    /// que le serveur ou un membre pourrait falsifier isolément.
    pub fn roster(&self) -> Result<Option<Roster>> {
        match self.group.extensions().unknown(ROSTER_EXTENSION) {
            Some(raw) => Roster::decode(&raw.0).map(Some),
            None => Ok(None),
        }
    }

    /// Remplace le roster : admin et modérateurs. Soumis à la politique comme tout le reste —
    /// les autres membres refuseront le commit s'il ne vient pas de l'admin en place.
    ///
    /// Passer un `admin` différent de l'actuel **transmet le groupe**. C'est irréversible du
    /// point de vue de l'émetteur : il ne pourra pas se le reprendre.
    ///
    /// Même discipline que le reste : publier le commit avant [`Conversation::apply_pending`].
    pub fn set_roles(
        &mut self,
        identity: &Identity,
        admin: String,
        moderators: Vec<String>,
    ) -> Result<Change> {
        let roster = Roster::new(admin, moderators)?;

        let (commit, _welcome, _group_info) = self
            .group
            .update_group_context_extensions(
                &identity.provider,
                roster_extension(&roster)?,
                &identity.signer,
            )
            .map_err(mls)?;

        Ok(Change { commit: commit.tls_serialize_detached().map_err(mls)? })
    }

    /// Ajoute un membre à partir du KeyPackage publié sur le serveur. L'invité peut être
    /// hors ligne : c'est ce qui rend la messagerie asynchrone possible.
    /// Prépare l'ajout d'un membre **sans l'appliquer**.
    ///
    /// Le commit reste en attente : le groupe est encore à l'ancienne epoch tant que
    /// [`Conversation::apply_pending`] n'a pas été appelé.
    ///
    /// Cette séparation n'est pas un raffinement. Appliquer le commit avant de l'avoir publié
    /// est irrattrapable : si la publication échoue — réseau coupé, serveur en erreur —
    /// l'émetteur a changé d'epoch pendant que les autres membres restent à l'ancienne, et le
    /// commit qui les aurait réconciliés n'existe plus nulle part. Le groupe est alors mort,
    /// silencieusement : plus personne ne déchiffre plus rien, et aucune erreur ne dit
    /// pourquoi.
    ///
    /// L'ordre correct est donc : préparer, publier, puis seulement appliquer.
    pub fn invite(&mut self, identity: &Identity, key_package: &[u8]) -> Result<Invitation> {
        let key_package = parse_key_package(&identity.provider, key_package)?;

        let (commit, welcome, _group_info) = self
            .group
            .add_members(&identity.provider, &identity.signer, &[key_package])
            .map_err(mls)?;

        Ok(Invitation {
            commit: commit.tls_serialize_detached().map_err(mls)?,
            welcome: welcome.tls_serialize_detached().map_err(mls)?,
        })
    }

    /// Applique le commit préparé par [`Conversation::invite`], une fois celui-ci publié.
    ///
    /// À n'appeler qu'après une publication réussie. Voir la note sur `invite` : l'inverse
    /// casse le groupe sans recours.
    /// Retourne l'arbre de ratchet **à jour**, à transmettre à l'invité avec son Welcome.
    ///
    /// L'arbre ne peut pas être produit plus tôt : tant que le commit n'est pas appliqué, il
    /// ne contient pas le nouveau membre, et le Welcome est alors rejeté avec une erreur de
    /// hash d'arbre.
    pub fn apply_pending(&mut self, identity: &Identity) -> Result<Vec<u8>> {
        self.group.merge_pending_commit(&identity.provider).map_err(mls)?;
        self.group.export_ratchet_tree().tls_serialize_detached().map_err(mls)
    }

    /// Prépare le retrait d'un membre **sans l'appliquer**.
    ///
    /// # Ce que le retrait apporte, et que rien d'autre n'apporte
    ///
    /// Retirer un appareil de la liste de diffusion du serveur ne le prive de rien : il détient
    /// les secrets du groupe et déchiffre tout ce qu'il obtient par un autre chemin. Le
    /// `Remove` MLS, lui, re-clé l'arbre — c'est la **post-compromise security**, et c'est la
    /// raison pour laquelle ce projet a choisi MLS. Un téléphone volé cesse effectivement de
    /// lire à partir du commit, et pas avant.
    ///
    /// # Désignation par la clé de signature MLS
    ///
    /// On ne peut pas désigner une feuille par son credential : il porte le *handle*, commun à
    /// tous les appareils d'un même compte. La clé de signature, elle, est propre à l'appareil
    /// et couverte par son attestation — le lien appareil ↔ feuille est donc authentifié de
    /// bout en bout, sans rien devoir au serveur.
    ///
    /// # Même discipline que `invite`
    ///
    /// Le commit reste en attente. Appliquer avant d'avoir publié casse le groupe sans
    /// recours : voir la note détaillée sur [`Conversation::invite`]. L'ordre est préparer,
    /// publier, puis [`Conversation::apply_pending`].
    pub fn remove(&mut self, identity: &Identity, mls_key: &[u8]) -> Result<Change> {
        let leaf = self
            .group
            .members()
            .find(|member| member.signature_key == mls_key)
            .map(|member| member.index)
            .ok_or(CryptoError::UnknownMember)?;

        let (commit, _welcome, _group_info) = self
            .group
            .remove_members(&identity.provider, &identity.signer, &[leaf])
            .map_err(mls)?;

        Ok(Change { commit: commit.tls_serialize_detached().map_err(mls)? })
    }

    /// Demande à sortir du groupe. Retourne une **proposition**, pas un commit.
    ///
    /// # Pourquoi on ne peut pas se retirer soi-même
    ///
    /// La RFC 9420 l'interdit : un membre ne peut pas figurer dans les retraits d'un commit
    /// qu'il génère. Ce n'est pas une lacune d'OpenMLS. Le commit doit être signé sous le
    /// secret de l'epoch qu'il produit, et cette epoch est justement celle dont l'émetteur
    /// vient d'être exclu — il ne peut pas produire une clé qu'il n'aura plus.
    ///
    /// La sortie passe donc par une proposition, qu'**un autre membre** doit commiter avec
    /// [`Conversation::commit_pending`].
    ///
    /// # La conséquence, qui n'est pas anodine
    ///
    /// Personne ne quitte un groupe où plus personne n'écoute. Tant qu'aucun autre membre ne
    /// commite, le partant reste dans l'arbre et continue de recevoir. Une interface honnête
    /// affiche « départ en attente » plutôt que de faire disparaître la conversation, sans
    /// quoi l'utilisateur se croit sorti d'un groupe qui le lit toujours.
    pub fn leave(&mut self, identity: &Identity) -> Result<Vec<u8>> {
        self.group
            .leave_group(&identity.provider, &identity.signer)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Commite les propositions reçues et mises en file — typiquement la demande de sortie
    /// d'un autre membre.
    ///
    /// Même discipline que le reste : le commit retourné doit être publié avant
    /// [`Conversation::apply_pending`].
    pub fn commit_pending(&mut self, identity: &Identity) -> Result<Change> {
        let (commit, _welcome, _group_info) = self
            .group
            .commit_to_pending_proposals(&identity.provider, &identity.signer)
            .map_err(mls)?;

        Ok(Change { commit: commit.tls_serialize_detached().map_err(mls)? })
    }

    /// Rejoint une conversation depuis un Welcome.
    pub fn join(identity: &Identity, welcome: &[u8], ratchet_tree: &[u8]) -> Result<Self> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|_| CryptoError::Malformed("welcome illisible"))?;

        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(CryptoError::UnexpectedMessage);
        };

        let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree)
            .map_err(|_| CryptoError::Malformed("arbre de ratchet illisible"))?;

        let staged = StagedWelcome::new_from_welcome(
            &identity.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(ratchet_tree),
        )
        .map_err(mls)?;

        // L'étape « staged » permet d'inspecter qui est dans le groupe avant de s'engager.
        // On rejoint directement ici ; une UI sérieuse afficherait d'abord les membres.
        let group = staged.into_group(&identity.provider).map_err(mls)?;
        Ok(Self { group })
    }

    pub fn encrypt(&mut self, identity: &Identity, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.group
            .create_message(&identity.provider, &identity.signer, plaintext)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Traite un message entrant.
    ///
    /// Un flux MLS mélange messages applicatifs et messages de gestion de groupe (commits,
    /// propositions). Le point d'entrée est donc unique, et l'appelant doit gérer les deux :
    /// ignorer les commits ferait diverger l'epoch et rendrait toute la suite indéchiffrable.
    ///
    /// # Le contexte de politique
    ///
    /// `context` porte les révocations que **l'appelant a vérifiées** — ce module ne fait pas
    /// de réseau. Un contexte vide n'est pas neutre : il fait refuser le retrait d'un appareil
    /// révoqué par un non-admin, qui est précisément le cas d'un téléphone volé. L'appelant
    /// doit donc le tenir à jour depuis la liste d'appareils du compte concerné.
    pub fn process(
        &mut self,
        identity: &Identity,
        message: &[u8],
        context: &roles::Context,
    ) -> Result<Incoming> {
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|_| CryptoError::Malformed("message illisible"))?;

        let protocol_message: ProtocolMessage = match message.extract() {
            MlsMessageBodyIn::PrivateMessage(m) => m.into(),
            MlsMessageBodyIn::PublicMessage(m) => m.into(),
            _ => return Err(CryptoError::UnexpectedMessage),
        };

        let processed = self
            .group
            .process_message(&identity.provider, protocol_message)
            .map_err(mls)?;

        // L'expéditeur est authentifié par MLS : cette valeur ne peut pas être falsifiée par
        // un autre membre du groupe. Elle reste relative aux identités du groupe, dont
        // l'authenticité dépend toujours de la vérification d'empreinte.
        let sender = match processed.credential().credential_type() {
            CredentialType::Basic => BasicCredential::try_from(processed.credential().clone())
                .ok()
                .map(|c| String::from_utf8_lossy(c.identity()).into_owned()),
            _ => None,
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                Ok(Incoming::Application { sender, plaintext: app.into_bytes() })
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                // **Le point où la politique s'applique.** Entre la validation
                // cryptographique, qui vient d'aboutir, et l'application, qui est
                // irréversible.
                //
                // Refuser fait diverger de quiconque aurait accepté. C'est acceptable parce
                // que la règle est déterministe et dérivée d'un état authentifié : tous les
                // clients honnêtes refusent identiquement, et seul un committer malveillant
                // se retrouve seul avec son epoch. Voir `roles.rs`.
                let committer = sender.as_deref().unwrap_or_default();
                self.authorize_commit(committer, &commit, context)?;

                self.group
                    .merge_staged_commit(&identity.provider, *commit)
                    .map_err(mls)?;
                Ok(Incoming::GroupChanged)
            }
            // Une proposition n'a d'effet que si elle est CONSERVÉE jusqu'au commit qui la
            // reprend. La jeter ici — ce que faisait la version précédente — rendait toute
            // demande de sortie inopérante : `commit_pending` ne trouvait rien à commiter, et
            // le partant restait indéfiniment dans le groupe sans qu'aucune erreur ne le dise.
            ProcessedMessageContent::ProposalMessage(proposal) => {
                self.group
                    .store_pending_proposal(identity.provider.storage(), *proposal)
                    .map_err(|e| CryptoError::Storage(e.to_string()))?;
                Ok(Incoming::Proposal)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(Incoming::Proposal),
        }
    }

    /// Traduit un commit MLS en résumé pour la politique, puis tranche.
    ///
    /// Toute la traduction est ici, et la décision est ailleurs (`roles::authorize`, pure et
    /// testée isolément). Mélanger les deux rendrait la règle intestable : il faudrait monter
    /// un vrai groupe MLS pour couvrir chaque cas limite, et on n'en couvrirait qu'une part.
    fn authorize_commit(
        &self,
        committer: &str,
        commit: &StagedCommit,
        context: &roles::Context,
    ) -> Result<()> {
        let Some(roster) = self.roster()? else { return Ok(()) };

        // L'arbre d'AVANT le commit : c'est le roster en vigueur au moment où le committer a
        // agi qui décide, pas celui que son commit installerait.
        let membres: Vec<(LeafNodeIndex, String, Vec<u8>)> = self
            .group
            .members()
            .map(|m| (m.index, handle_of(&m.credential), m.signature_key.as_slice().to_vec()))
            .collect();

        let mut removals = Vec::new();
        for proposal in commit.remove_proposals() {
            let index = proposal.remove_proposal().removed();
            let Some((_, target, target_key)) = membres.iter().find(|(i, _, _)| *i == index)
            else {
                // Retrait d'une feuille absente de l'arbre : MLS l'aurait refusé. Par
                // prudence on ne laisse pas passer ce qu'on ne sait pas décrire.
                return Err(CryptoError::PolicyViolation("retrait d'un membre inconnu"));
            };

            // Un départ volontaire : la proposition vient de l'appareil lui-même. Le
            // committer ne fait que la reprendre, ce que la politique autorise à tous.
            let self_requested = matches!(
                proposal.sender(),
                Sender::Member(sender_index) if *sender_index == index
            );

            removals.push(roles::Removal { target, target_key, self_requested });
        }

        let retires: Vec<LeafNodeIndex> =
            commit.remove_proposals().map(|p| p.remove_proposal().removed()).collect();
        let remaining: Vec<&str> = membres
            .iter()
            .filter(|(index, _, _)| !retires.contains(index))
            .map(|(_, handle, _)| handle.as_str())
            .collect();

        let summary = roles::CommitSummary {
            committer,
            removals: removals
                .iter()
                .map(|r| roles::Removal {
                    target: r.target,
                    target_key: r.target_key,
                    self_requested: r.self_requested,
                })
                .collect(),
            adds: commit.add_proposals().count(),
            changes_roster: commit
                .queued_proposals()
                .any(|p| matches!(p.proposal(), Proposal::GroupContextExtensions(_))),
            remaining,
        };

        roles::authorize(Some(&roster), &summary, context)
    }

    /// Empreintes des autres membres, à comparer hors bande.
    ///
    /// **Sans cette comparaison, le E2EE est décoratif.** Le serveur distribue les
    /// KeyPackages ; rien ne l'empêche de servir les siens en se faisant passer pour le
    /// correspondant, puis de relayer en clair entre deux sessions parfaitement chiffrées.
    /// Toutes les vérifications cryptographiques passeront. Seul un canal hors bande —
    /// de visu, QR code, ou un log de transparence auditable — ferme cette faille.
    pub fn peer_fingerprints(&self, identity: &Identity) -> Vec<(String, String)> {
        self.group
            .members()
            .filter(|member| member.signature_key != identity.signature_key())
            .map(|member| {
                let name = BasicCredential::try_from(member.credential.clone())
                    .ok()
                    .map(|c| String::from_utf8_lossy(c.identity()).into_owned())
                    .unwrap_or_else(|| "<credential non basique>".to_owned());
                (name, fingerprint(&member.signature_key))
            })
            .collect()
    }

    /// Clés de signature MLS des autres membres.
    ///
    /// C'est par cette clé qu'on désigne une feuille dans [`Conversation::remove`] : le
    /// credential ne suffit pas, il porte le handle du compte, commun à tous ses appareils.
    ///
    /// La liste vient de l'arbre, donc de l'état authentifié — pas du serveur. C'est ce qui
    /// permet au client de constater qu'un membre de l'arbre ne figure plus parmi les
    /// appareils actifs de son compte, et donc de le retirer.
    pub fn peer_signature_keys(&self, identity: &Identity) -> Vec<Vec<u8>> {
        self.group
            .members()
            .filter(|member| member.signature_key != identity.signature_key())
            .map(|member| member.signature_key.as_slice().to_vec())
            .collect()
    }

    /// Epoch courante. Avance à chaque commit ; deux membres à des epochs différentes ne
    /// peuvent pas se lire. C'est la première chose à regarder quand un message ne passe pas.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// Clé symétrique du canal éphémère, dérivée du secret d'export de l'epoch courante.
    ///
    /// # Pourquoi pas le ratchet applicatif
    ///
    /// Parce que le ratchet est fait pour ne rien perdre : chaque message consomme une
    /// génération, et un trou trop large casse le déchiffrement de la suite. Un indicateur de
    /// frappe, lui, est fait pour être perdu — il n'est jamais stocké, jamais réémis, et sans
    /// valeur passées quelques secondes. Le faire passer par le ratchet ferait payer à
    /// l'historique le prix d'un signal jetable.
    ///
    /// # Ce que cette clé ne donne pas
    ///
    /// Pas de forward secrecy à l'intérieur d'une epoch : tous les signaux d'une même epoch
    /// tombent ensemble si le secret fuit. C'est le bon compromis pour une donnée dont la
    /// valeur expire en quelques secondes, mais il faut l'énoncer.
    ///
    /// Pas d'authentification de l'émetteur non plus : la clé est celle du groupe, donc tout
    /// membre peut produire un signal qui semble venir d'un autre. Sans conséquence à deux,
    /// à documenter au-delà.
    ///
    /// Ce qu'elle donne en revanche est réel : elle change à chaque commit. Un membre retiré
    /// perd le canal éphémère au même instant qu'il perd le reste — la PCS s'applique ici
    /// sans code supplémentaire.
    pub fn signal_key(&self, identity: &Identity) -> Result<Vec<u8>> {
        self.group
            .export_secret(identity.provider.crypto(), "wac-signal-key-v1", &[], 32)
            .map_err(|e| CryptoError::Storage(format!("export du secret d'epoch : {e}")))
    }

    /// Identifiant du groupe, à utiliser comme clé de routage côté serveur.
    pub fn id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    /// Recharge une conversation depuis l'état persisté du provider.
    pub fn load(identity: &Identity, group_id: &[u8]) -> Result<Self> {
        let group = MlsGroup::load(identity.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(mls)?
            .ok_or_else(|| CryptoError::Storage("groupe absent du stockage".into()))?;
        Ok(Self { group })
    }
}

#[derive(Debug)]
pub enum Incoming {
    Application { sender: Option<String>, plaintext: Vec<u8> },
    /// Un commit a été appliqué : la composition du groupe ou les clés ont changé.
    GroupChanged,
    /// Proposition en attente d'un commit. Rien à afficher.
    Proposal,
}
