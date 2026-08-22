//! A conversation = an MLS group.
//!
//! A 1-to-1 is a group of 2. That is the whole point of MLS here: moving to larger groups later
//! needs no rewrite, where the Signal stack would force us to add Sender Keys, a mechanism
//! entirely separate from the Double Ratchet.

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

use crate::error::{CryptoError, Result, mls};
use crate::identity::{Identity, fingerprint, parse_key_package};
use crate::roles::{self, ROSTER_EXTENSION, Roster};

/// What adding a member produces. The parts travel by different paths: the commit goes to the
/// members already present, the welcome to the newcomer alone.
pub struct Invitation {
    /// To broadcast to existing members so they move to the next epoch.
    pub commit: Vec<u8>,
    /// To hand to the invitee alone. Holds the secrets that let them join.
    ///
    /// The public tree that goes with it is not here: it only exists once the commit is
    /// applied, and so comes out of [`Conversation::apply_pending`].
    pub welcome: Vec<u8>,
}

/// A group state change ready to publish: removal, committed departure, roster change. A single
/// recipient, unlike [`Invitation`]: there is nobody to welcome, only members to move forward an
/// epoch.
///
/// An excluded member receives the commit too, if still connected — that is how they learn of
/// their exclusion rather than noticing silence. They can decrypt nothing afterwards.
pub struct Change {
    pub commit: Vec<u8>,
}

pub struct Conversation {
    group: MlsGroup,
}

/// Wraps the roster into the group context extensions, with the matching capability.
///
/// # Why `RequiredCapabilities` accompanies the roster
///
/// MLS requires every group context extension to appear in the required capabilities. That is
/// a useful constraint rather than a formality: it stops a client that **cannot read the
/// roster** from joining an administered group. Without it, such a client would join, apply an
/// empty policy, accept commits the others refuse — and fork the group with nothing to signal
/// it.
///
/// The error is propagated rather than assumed impossible: a badly chosen constant is then
/// rejected at group creation, and not months later on a roster change.
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

/// Handle carried by an MLS credential. A non-basic credential has no usable handle and can
/// therefore satisfy no rule: the empty string belongs to no roster.
fn handle_of(credential: &Credential) -> String {
    BasicCredential::try_from(credential.clone())
        .ok()
        .map(|c| String::from_utf8_lossy(c.identity()).into_owned())
        .unwrap_or_default()
}

impl Conversation {
    /// Creates a **flat** conversation: no roles, everyone can do everything.
    ///
    /// That is the correct shape for a 1-to-1, where admin roles would make no sense. For an
    /// administered group, see [`Conversation::create_administered`].
    pub fn create(identity: &Identity) -> Result<Self> {
        Self::create_with(identity, None)
    }

    /// Creates an administered group. The creator is its admin, sole and only.
    ///
    /// The roster goes into the **group context**, hence into the authenticated state hashed by
    /// every commit. See `roles.rs` for what that implies — and for the essential warning: MLS
    /// does not enforce these rules, the clients do.
    pub fn create_administered(identity: &Identity, admin: String) -> Result<Self> {
        Self::create_with(identity, Some(Roster::new(admin, Vec::new())?))
    }

    fn create_with(identity: &Identity, roster: Option<Roster>) -> Result<Self> {
        // The creator's capabilities are configured HERE, not by `publish_key_package`: the
        // creator has no KeyPackage, its leaf is built from this config. Forgetting them makes
        // the first member add fail, with an error that points at extensions without saying
        // which of the two leaves is at fault.
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

    /// The group's roster, or `None` if the group is flat.
    ///
    /// Read from the group context, hence from authenticated state: this is not something the
    /// server or a single member could forge.
    pub fn roster(&self) -> Result<Option<Roster>> {
        match self.group.extensions().unknown(ROSTER_EXTENSION) {
            Some(raw) => Roster::decode(&raw.0).map(Some),
            None => Ok(None),
        }
    }

    /// Replaces the roster: admin and moderators. Subject to the policy like everything else —
    /// the other members will refuse the commit if it does not come from the sitting admin.
    ///
    /// Passing an `admin` other than the current one **hands over the group**. That is
    /// irreversible from the sender's point of view: they cannot take it back.
    ///
    /// Same discipline as the rest: publish the commit before [`Conversation::apply_pending`].
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

    /// Adds a member from the KeyPackage published on the server. The invitee may be offline:
    /// that is what makes asynchronous messaging possible.
    /// Prepares a member add **without applying it**.
    ///
    /// The commit stays pending: the group is still on the old epoch until
    /// [`Conversation::apply_pending`] has been called.
    ///
    /// This separation is not a refinement. Applying the commit before publishing it cannot be
    /// undone: if publication fails — network down, server error — the sender has changed epoch
    /// while the other members stay on the old one, and the commit that would have reconciled
    /// them no longer exists anywhere. The group is then dead, silently: nobody decrypts
    /// anything any more, and no error says why.
    ///
    /// The correct order is therefore: prepare, publish, and only then apply.
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

    /// Applies the commit prepared by [`Conversation::invite`], once it has been published.
    ///
    /// Only call it after a successful publication. See the note on `invite`: the other way
    /// round breaks the group beyond repair.
    /// Returns the **up-to-date** ratchet tree, to send to the invitee with their Welcome.
    ///
    /// The tree cannot be produced earlier: until the commit is applied it does not contain the
    /// new member, and the Welcome is then rejected with a tree hash error.
    pub fn apply_pending(&mut self, identity: &Identity) -> Result<Vec<u8>> {
        self.group.merge_pending_commit(&identity.provider).map_err(mls)?;
        self.group.export_ratchet_tree().tls_serialize_detached().map_err(mls)
    }

    /// Prepares a member removal **without applying it**.
    ///
    /// # What removal buys that nothing else does
    ///
    /// Taking a device off the server's fan-out list deprives it of nothing: it holds the group
    /// secrets and decrypts whatever it obtains by another route. The MLS `Remove`, on the other
    /// hand, re-keys the tree — that is **post-compromise security**, and it is why this project
    /// chose MLS. A stolen phone effectively stops reading from the commit onward, and not
    /// before.
    ///
    /// # Designation by MLS signature key
    ///
    /// A leaf cannot be designated by its credential: that carries the *handle*, shared by all
    /// devices of one account. The signature key is device-specific and covered by its
    /// attestation — so the device ↔ leaf binding is authenticated end to end, owing nothing to
    /// the server.
    ///
    /// # Same discipline as `invite`
    ///
    /// The commit stays pending. Applying before publishing breaks the group beyond repair: see
    /// the detailed note on [`Conversation::invite`]. The order is prepare, publish, then
    /// [`Conversation::apply_pending`].
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

    /// Asks to leave the group. Returns a **proposal**, not a commit.
    ///
    /// # Why you cannot remove yourself
    ///
    /// RFC 9420 forbids it: a member cannot appear among the removals of a commit they generate.
    /// This is not an OpenMLS shortcoming. The commit must be signed under the secret of the
    /// epoch it produces, and that epoch is precisely the one the sender has just been excluded
    /// from — they cannot produce a key they will no longer have.
    ///
    /// Leaving therefore goes through a proposal, which **another member** must commit with
    /// [`Conversation::commit_pending`].
    ///
    /// # The consequence, which is not trivial
    ///
    /// Nobody leaves a group where nobody is listening any more. Until another member commits,
    /// the leaver stays in the tree and keeps receiving. An honest interface shows "departure
    /// pending" rather than making the conversation disappear, or the user believes they left a
    /// group that is still reading them.
    pub fn leave(&mut self, identity: &Identity) -> Result<Vec<u8>> {
        self.group
            .leave_group(&identity.provider, &identity.signer)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Commits the proposals received and queued — typically another member's request to leave.
    ///
    /// Same discipline as the rest: the returned commit must be published before
    /// [`Conversation::apply_pending`].
    pub fn commit_pending(&mut self, identity: &Identity) -> Result<Change> {
        let (commit, _welcome, _group_info) = self
            .group
            .commit_to_pending_proposals(&identity.provider, &identity.signer)
            .map_err(mls)?;

        Ok(Change { commit: commit.tls_serialize_detached().map_err(mls)? })
    }

    /// Joins a conversation from a Welcome.
    pub fn join(identity: &Identity, welcome: &[u8], ratchet_tree: &[u8]) -> Result<Self> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|_| CryptoError::Malformed("unreadable welcome"))?;

        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(CryptoError::UnexpectedMessage);
        };

        let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree)
            .map_err(|_| CryptoError::Malformed("unreadable ratchet tree"))?;

        let staged = StagedWelcome::new_from_welcome(
            &identity.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(ratchet_tree),
        )
        .map_err(mls)?;

        // The "staged" step allows inspecting who is in the group before committing to it. We
        // join straight away here; a serious UI would show the members first.
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

    /// Processes an incoming message.
    ///
    /// An MLS stream mixes application messages and group management messages (commits,
    /// proposals). There is therefore a single entry point, and the caller must handle both:
    /// ignoring commits would make the epoch diverge and render everything after it
    /// undecryptable.
    ///
    /// # The policy context
    ///
    /// `context` carries the revocations **the caller has verified** — this module does no
    /// networking. An empty context is not neutral: it makes a non-admin's removal of a revoked
    /// device be refused, which is exactly the stolen-phone case. The caller must therefore keep
    /// it up to date from the device list of the account concerned.
    pub fn process(
        &mut self,
        identity: &Identity,
        message: &[u8],
        context: &roles::Context,
    ) -> Result<Incoming> {
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|_| CryptoError::Malformed("unreadable message"))?;

        let protocol_message: ProtocolMessage = match message.extract() {
            MlsMessageBodyIn::PrivateMessage(m) => m.into(),
            MlsMessageBodyIn::PublicMessage(m) => m.into(),
            _ => return Err(CryptoError::UnexpectedMessage),
        };

        let processed = self
            .group
            .process_message(&identity.provider, protocol_message)
            .map_err(mls)?;

        // The sender is authenticated by MLS: this value cannot be forged by another group
        // member. It stays relative to the group's identities, whose authenticity still depends
        // on fingerprint verification.
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
                // **This is where the policy applies.** Between cryptographic validation, which
                // has just succeeded, and application, which is irreversible.
                //
                // Refusing diverges from anyone who would have accepted. That is acceptable
                // because the rule is deterministic and derived from authenticated state: every
                // honest client refuses identically, and only a malicious committer ends up
                // alone on its epoch. See `roles.rs`.
                let committer = sender.as_deref().unwrap_or_default();
                self.authorize_commit(committer, &commit, context)?;

                self.group
                    .merge_staged_commit(&identity.provider, *commit)
                    .map_err(mls)?;
                Ok(Incoming::GroupChanged)
            }
            // A proposal only has effect if it is KEPT until the commit that picks it up.
            // Dropping it here — as the previous version did — made every leave request inert:
            // `commit_pending` found nothing to commit, and the leaver stayed in the group
            // indefinitely with no error saying so.
            ProcessedMessageContent::ProposalMessage(proposal) => {
                self.group
                    .store_pending_proposal(identity.provider.storage(), *proposal)
                    .map_err(|e| CryptoError::Storage(e.to_string()))?;
                Ok(Incoming::Proposal)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(Incoming::Proposal),
        }
    }

    /// Translates an MLS commit into a summary for the policy, then rules on it.
    ///
    /// All the translation is here, and the decision is elsewhere (`roles::authorize`, pure and
    /// tested in isolation). Mixing the two would make the rule untestable: you would have to
    /// stand up a real MLS group to cover each edge case, and would only cover some of them.
    fn authorize_commit(
        &self,
        committer: &str,
        commit: &StagedCommit,
        context: &roles::Context,
    ) -> Result<()> {
        let Some(roster) = self.roster()? else { return Ok(()) };

        // The tree from BEFORE the commit: what decides is the roster in force when the
        // committer acted, not the one their commit would install.
        let members: Vec<(LeafNodeIndex, String, Vec<u8>)> = self
            .group
            .members()
            .map(|m| (m.index, handle_of(&m.credential), m.signature_key.as_slice().to_vec()))
            .collect();

        let mut removals = Vec::new();
        for proposal in commit.remove_proposals() {
            let index = proposal.remove_proposal().removed();
            let Some((_, target, target_key)) = members.iter().find(|(i, _, _)| *i == index)
            else {
                // Removal of a leaf absent from the tree: MLS would have refused it. Out of
                // caution we do not let through what we cannot describe.
                return Err(CryptoError::PolicyViolation("removal of an unknown member"));
            };

            // A voluntary departure: the proposal comes from the device itself. The committer
            // only picks it up, which the policy allows anyone to do.
            let self_requested = matches!(
                proposal.sender(),
                Sender::Member(sender_index) if *sender_index == index
            );

            removals.push(roles::Removal { target, target_key, self_requested });
        }

        let removed: Vec<LeafNodeIndex> =
            commit.remove_proposals().map(|p| p.remove_proposal().removed()).collect();
        let remaining: Vec<&str> = members
            .iter()
            .filter(|(index, _, _)| !removed.contains(index))
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

    /// Fingerprints of the other members, to compare out of band.
    ///
    /// **Without that comparison, E2EE is decorative.** The server distributes the KeyPackages;
    /// nothing stops it serving its own while posing as the peer, then relaying in the clear
    /// between two perfectly encrypted sessions. Every cryptographic check will pass. Only an
    /// out-of-band channel — in person, QR code, or an auditable transparency log — closes this
    /// hole.
    pub fn peer_fingerprints(&self, identity: &Identity) -> Vec<(String, String)> {
        self.group
            .members()
            .filter(|member| member.signature_key != identity.signature_key())
            .map(|member| {
                let name = BasicCredential::try_from(member.credential.clone())
                    .ok()
                    .map(|c| String::from_utf8_lossy(c.identity()).into_owned())
                    .unwrap_or_else(|| "<non-basic credential>".to_owned());
                (name, fingerprint(&member.signature_key))
            })
            .collect()
    }

    /// MLS signature keys of the other members.
    ///
    /// This key is how a leaf is designated in [`Conversation::remove`]: the credential is not
    /// enough, it carries the account handle, shared by all its devices.
    ///
    /// The list comes from the tree, hence from authenticated state — not from the server. That
    /// is what lets a client observe that a member of the tree no longer appears among the
    /// active devices of its account, and therefore remove it.
    pub fn peer_signature_keys(&self, identity: &Identity) -> Vec<Vec<u8>> {
        self.group
            .members()
            .filter(|member| member.signature_key != identity.signature_key())
            .map(|member| member.signature_key.as_slice().to_vec())
            .collect()
    }

    /// Current epoch. Advances on every commit; two members on different epochs cannot read each
    /// other. It is the first thing to look at when a message does not get through.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// Symmetric key for the ephemeral channel, derived from the current epoch's exporter
    /// secret.
    ///
    /// # Why not the application ratchet
    ///
    /// Because the ratchet is built to lose nothing: every message consumes a generation, and
    /// too wide a gap breaks decryption of what follows. A typing indicator, by contrast, is
    /// built to be lost — never stored, never resent, and worthless after a few seconds. Routing
    /// it through the ratchet would make the history pay the price of a disposable signal.
    ///
    /// # What this key does not give
    ///
    /// No forward secrecy within an epoch: every signal of one epoch falls together if the
    /// secret leaks. That is the right trade-off for data whose value expires in seconds, but it
    /// has to be stated.
    ///
    /// No sender authentication either: the key belongs to the group, so any member can produce
    /// a signal that appears to come from another. Harmless with two, to be documented beyond.
    ///
    /// What it does give is real: it changes on every commit. A removed member loses the
    /// ephemeral channel at the same instant they lose the rest — PCS applies here with no extra
    /// code.
    pub fn signal_key(&self, identity: &Identity) -> Result<Vec<u8>> {
        self.group
            .export_secret(identity.provider.crypto(), "wac-signal-key-v1", &[], 32)
            .map_err(|e| CryptoError::Storage(format!("epoch secret export: {e}")))
    }

    /// Symmetric key protecting one call's audio, derived from the current epoch's exporter
    /// secret.
    ///
    /// # Why the media needs a key of its own
    ///
    /// The media server terminates the transport encryption — that is what lets it route a
    /// stream to five people without holding five conversations. So the audio has to be
    /// encrypted *before* it reaches that server, under a key the server never sees. That is
    /// what these bytes are, and they are handed to the frame-level encryption the browser
    /// exposes, never to the transport.
    ///
    /// # Why nothing is distributed
    ///
    /// Same reasoning as [`Self::signal_key`], and it is the whole argument for deriving rather
    /// than agreeing: every member computes these bytes locally from state MLS already gave
    /// them. A call therefore costs no key exchange, and the media server has no point at which
    /// it could be asked to hand a key out — it is never in possession of one.
    ///
    /// # Why the call id is the context, not a separate label
    ///
    /// Two calls in the same epoch must not share a key: replaying one call's audio into
    /// another would otherwise decrypt. The exporter's context field is exactly the mechanism
    /// for that, and it keeps the label a constant, which is what makes the label auditable.
    ///
    /// # What it inherits from the epoch
    ///
    /// The key changes on every commit, so a member removed mid-call loses the audio at the
    /// same instant they lose the messages. The caller has to *act* on that — the media layer
    /// must be handed the new key at each epoch — but the property itself costs nothing here.
    pub fn call_key(&self, identity: &Identity, call_id: &[u8]) -> Result<Vec<u8>> {
        self.group
            .export_secret(identity.provider.crypto(), "wac-call-key-v1", call_id, 32)
            .map_err(|e| CryptoError::Storage(format!("epoch secret export: {e}")))
    }

    /// The group identifier, to use as the routing key on the server side.
    pub fn id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    /// Reloads a conversation from the provider's persisted state.
    pub fn load(identity: &Identity, group_id: &[u8]) -> Result<Self> {
        let group = MlsGroup::load(identity.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(mls)?
            .ok_or_else(|| CryptoError::Storage("group not found in storage".into()))?;
        Ok(Self { group })
    }
}

#[derive(Debug)]
pub enum Incoming {
    Application { sender: Option<String>, plaintext: Vec<u8> },
    /// A commit was applied: group membership or keys have changed.
    GroupChanged,
    /// Proposal awaiting a commit. Nothing to display.
    Proposal,
}
