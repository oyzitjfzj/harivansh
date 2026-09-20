use crate::{GoalPatch, GoalPatchRelation, VersionedRef};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GoalConstitutionField {
    Reason,
    DesiredLevel,
    NonNegotiable,
    AcceptedDecision,
    RejectedDecision,
    Correction,
    OpenQuestion,
    CompletionCriterion,
    QualityRequirement,
    PermissionBoundary,
}

const GOAL_FIELDS: [GoalConstitutionField; 10] = [
    GoalConstitutionField::Reason,
    GoalConstitutionField::DesiredLevel,
    GoalConstitutionField::NonNegotiable,
    GoalConstitutionField::AcceptedDecision,
    GoalConstitutionField::RejectedDecision,
    GoalConstitutionField::Correction,
    GoalConstitutionField::OpenQuestion,
    GoalConstitutionField::CompletionCriterion,
    GoalConstitutionField::QualityRequirement,
    GoalConstitutionField::PermissionBoundary,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalConstitutionSnapshot {
    pub goal_revision: VersionedRef,
    pub fingerprint_ref: String,
    pub fingerprint_evidence_refs: BTreeSet<String>,
    pub original_goal_evidence_refs: BTreeSet<String>,
    pub fields: BTreeMap<GoalConstitutionField, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalAmendmentAuthorization {
    pub authorization_ref: String,
    pub principal_context_ref: String,
    pub base_goal_revision: VersionedRef,
    pub base_fingerprint_ref: String,
    pub authorized_fields: BTreeSet<GoalConstitutionField>,
    pub authority_evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalAmendmentCandidate {
    pub patch: GoalPatch,
    pub base_fingerprint_ref: String,
    pub resulting_fingerprint_ref: String,
    pub resulting_fingerprint_evidence_refs: BTreeSet<String>,
    pub resulting_fields: BTreeMap<GoalConstitutionField, BTreeSet<String>>,
    pub changed_fields: BTreeSet<GoalConstitutionField>,
    pub authorization: GoalAmendmentAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GoalDependencyScope {
    WholeConstitution,
    Fields(BTreeSet<GoalConstitutionField>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GoalDependencyBinding {
    pub goal_revision: VersionedRef,
    pub constitution_fingerprint_ref: String,
    pub scope: GoalDependencyScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyRecord {
    pub artifact_ref: String,
    pub depends_on: BTreeSet<GoalDependencyBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DependencyIndex {
    by_artifact: BTreeMap<String, DependencyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyRegistrationError {
    EmptyArtifactRef,
    EmptyDependencySet,
    InvalidGoalReference,
    InvalidFingerprintRef,
    EmptyFieldDependency,
    InvalidDependencyRef,
    ConflictingArtifactDefinition,
}

impl DependencyIndex {
    pub fn register(
        &mut self,
        record: DependencyRecord,
    ) -> Result<(), DependencyRegistrationError> {
        if record.artifact_ref.trim().is_empty() {
            return Err(DependencyRegistrationError::EmptyArtifactRef);
        }
        if record.depends_on.is_empty() {
            return Err(DependencyRegistrationError::EmptyDependencySet);
        }
        for dependency in &record.depends_on {
            if dependency.goal_revision.reference.trim().is_empty() {
                return Err(DependencyRegistrationError::InvalidGoalReference);
            }
            if dependency.constitution_fingerprint_ref.trim().is_empty() {
                return Err(DependencyRegistrationError::InvalidFingerprintRef);
            }
            if let GoalDependencyScope::Fields(fields) = &dependency.scope
                && fields.is_empty()
            {
                return Err(DependencyRegistrationError::EmptyFieldDependency);
            }
        }

        match self.by_artifact.get(&record.artifact_ref) {
            Some(existing) if existing == &record => Ok(()),
            Some(_) => Err(DependencyRegistrationError::ConflictingArtifactDefinition),
            None => {
                self.by_artifact.insert(record.artifact_ref.clone(), record);
                Ok(())
            }
        }
    }

    pub fn invalidated_by_amendment(
        &self,
        prior: &GoalConstitutionSnapshot,
        relation: GoalPatchRelation,
        changed_fields: &BTreeSet<GoalConstitutionField>,
    ) -> BTreeSet<String> {
        self.by_artifact
            .values()
            .filter(|record| {
                record.depends_on.iter().any(|dependency| {
                    if dependency.goal_revision != prior.goal_revision
                        || dependency.constitution_fingerprint_ref != prior.fingerprint_ref
                    {
                        return false;
                    }
                    if relation == GoalPatchRelation::Supersede {
                        return true;
                    }
                    match &dependency.scope {
                        GoalDependencyScope::WholeConstitution => true,
                        GoalDependencyScope::Fields(fields) => !fields.is_disjoint(changed_fields),
                    }
                })
            })
            .map(|record| record.artifact_ref.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalRevisionCommit {
    pub prior_state: GoalConstitutionSnapshot,
    pub current_state: GoalConstitutionSnapshot,
    pub committed_patch: GoalPatch,
    pub changed_fields: BTreeSet<GoalConstitutionField>,
    pub authorization: GoalAmendmentAuthorization,
    pub invalidated_dependency_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentGoalHandoff {
    pub handoff_ref: String,
    pub patch_id: String,
    pub parent_goal_revision: VersionedRef,
    pub parent_constitution_fingerprint_ref: String,
    pub proposed_goal_ref: String,
    pub exact_source_refs: BTreeSet<String>,
    pub acceptance_evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalCommitDisposition {
    Committed(GoalRevisionCommit),
    AlreadyCommitted(GoalRevisionCommit),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndependentGoalDisposition {
    Admitted(IndependentGoalHandoff),
    AlreadyAdmitted(IndependentGoalHandoff),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalCommitError {
    InvalidInitialState,
    EmptyPatchId,
    EmptyAcceptanceEvidence,
    EmptySourceEvidence,
    EmptyProposedDeltaRef,
    InvalidEvidenceRef,
    PatchIdentityConflict,
    StaleBaseRevision,
    BaseFingerprintMismatch,
    CandidateAlreadyClaimsCommittedRevision,
    IndependentRequiresSeparateAdmission,
    NonIndependentRequired,
    ChangedFieldSetEmpty,
    ChangedFieldSetMismatch,
    AuthorizationMismatch,
    FingerprintInvalid,
    FingerprintReused,
    UnknownIndependentBaseRevision,
    RevisionOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GoalPatchBinding {
    base_goal_revision: VersionedRef,
    relation: GoalPatchRelation,
    proposed_delta_ref: String,
    exact_source_refs: BTreeSet<String>,
    affected_work_refs: BTreeSet<String>,
    affected_plan_refs: BTreeSet<String>,
    affected_context_refs: BTreeSet<String>,
    acceptance_evidence_refs: BTreeSet<String>,
}

impl From<&GoalPatch> for GoalPatchBinding {
    fn from(patch: &GoalPatch) -> Self {
        Self {
            base_goal_revision: patch.base_goal_revision.clone(),
            relation: patch.relation,
            proposed_delta_ref: patch.proposed_delta_ref.clone(),
            exact_source_refs: patch.exact_source_refs.clone(),
            affected_work_refs: patch.affected_work_refs.clone(),
            affected_plan_refs: patch.affected_plan_refs.clone(),
            affected_context_refs: patch.affected_context_refs.clone(),
            acceptance_evidence_refs: patch.acceptance_evidence_refs.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GoalAmendmentBinding {
    patch: GoalPatchBinding,
    base_fingerprint_ref: String,
    resulting_fingerprint_ref: String,
    resulting_fingerprint_evidence_refs: BTreeSet<String>,
    resulting_fields: BTreeMap<GoalConstitutionField, BTreeSet<String>>,
    changed_fields: BTreeSet<GoalConstitutionField>,
    authorization: GoalAmendmentAuthorization,
}

impl From<&GoalAmendmentCandidate> for GoalAmendmentBinding {
    fn from(candidate: &GoalAmendmentCandidate) -> Self {
        Self {
            patch: GoalPatchBinding::from(&candidate.patch),
            base_fingerprint_ref: candidate.base_fingerprint_ref.clone(),
            resulting_fingerprint_ref: candidate.resulting_fingerprint_ref.clone(),
            resulting_fingerprint_evidence_refs: candidate
                .resulting_fingerprint_evidence_refs
                .clone(),
            resulting_fields: candidate.resulting_fields.clone(),
            changed_fields: candidate.changed_fields.clone(),
            authorization: candidate.authorization.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordedPatch {
    Committed {
        binding: GoalAmendmentBinding,
        commit: Box<GoalRevisionCommit>,
    },
    Independent {
        binding: GoalPatchBinding,
        handoff: IndependentGoalHandoff,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalConstitution {
    current: GoalConstitutionSnapshot,
    recorded_patches: BTreeMap<String, RecordedPatch>,
    accepted_history: Vec<GoalRevisionCommit>,
}

impl GoalConstitution {
    pub fn new(initial: GoalConstitutionSnapshot) -> Result<Self, GoalCommitError> {
        validate_constitution_snapshot(&initial)
            .map_err(|_| GoalCommitError::InvalidInitialState)?;
        Ok(Self {
            current: initial,
            recorded_patches: BTreeMap::new(),
            accepted_history: Vec::new(),
        })
    }

    pub fn current(&self) -> &GoalConstitutionSnapshot {
        &self.current
    }

    pub fn accepted_history(&self) -> &[GoalRevisionCommit] {
        &self.accepted_history
    }

    pub fn commit_amendment(
        &mut self,
        candidate: GoalAmendmentCandidate,
        dependencies: &DependencyIndex,
    ) -> Result<GoalCommitDisposition, GoalCommitError> {
        validate_amendment_candidate(&candidate)?;
        let patch_id = candidate.patch.patch_id.clone();
        let binding = GoalAmendmentBinding::from(&candidate);

        if let Some(recorded) = self.recorded_patches.get(&patch_id) {
            return match recorded {
                RecordedPatch::Committed {
                    binding: existing,
                    commit,
                } if existing == &binding => Ok(GoalCommitDisposition::AlreadyCommitted(
                    commit.as_ref().clone(),
                )),
                _ => Err(GoalCommitError::PatchIdentityConflict),
            };
        }

        if candidate.patch.relation == GoalPatchRelation::Independent {
            return Err(GoalCommitError::IndependentRequiresSeparateAdmission);
        }
        if candidate.patch.base_goal_revision != self.current.goal_revision {
            return Err(GoalCommitError::StaleBaseRevision);
        }
        if candidate.base_fingerprint_ref != self.current.fingerprint_ref {
            return Err(GoalCommitError::BaseFingerprintMismatch);
        }

        validate_fields(&candidate.resulting_fields)?;
        let actual_changed = changed_fields(&self.current.fields, &candidate.resulting_fields);
        if actual_changed.is_empty() {
            return Err(GoalCommitError::ChangedFieldSetEmpty);
        }
        if actual_changed != candidate.changed_fields {
            return Err(GoalCommitError::ChangedFieldSetMismatch);
        }
        validate_authorization(&candidate.authorization, &self.current, &actual_changed)?;
        if candidate.resulting_fingerprint_ref == self.current.fingerprint_ref {
            return Err(GoalCommitError::FingerprintReused);
        }

        let next_version = self
            .current
            .goal_revision
            .version
            .checked_add(1)
            .ok_or(GoalCommitError::RevisionOverflow)?;
        let next_revision = VersionedRef {
            reference: self.current.goal_revision.reference.clone(),
            version: next_version,
        };
        let prior_state = self.current.clone();
        let current_state = GoalConstitutionSnapshot {
            goal_revision: next_revision.clone(),
            fingerprint_ref: candidate.resulting_fingerprint_ref.clone(),
            fingerprint_evidence_refs: candidate.resulting_fingerprint_evidence_refs.clone(),
            original_goal_evidence_refs: prior_state.original_goal_evidence_refs.clone(),
            fields: candidate.resulting_fields.clone(),
        };
        validate_constitution_snapshot(&current_state)?;

        let invalidated_dependency_refs = dependencies.invalidated_by_amendment(
            &prior_state,
            candidate.patch.relation,
            &actual_changed,
        );
        let mut committed_patch = candidate.patch;
        committed_patch.resulting_goal_revision = Some(next_revision);
        let commit = GoalRevisionCommit {
            prior_state,
            current_state: current_state.clone(),
            committed_patch,
            changed_fields: actual_changed,
            authorization: candidate.authorization,
            invalidated_dependency_refs,
        };

        self.current = current_state;
        self.recorded_patches.insert(
            patch_id,
            RecordedPatch::Committed {
                binding,
                commit: Box::new(commit.clone()),
            },
        );
        self.accepted_history.push(commit.clone());
        Ok(GoalCommitDisposition::Committed(commit))
    }

    pub fn admit_independent_goal(
        &mut self,
        patch: GoalPatch,
    ) -> Result<IndependentGoalDisposition, GoalCommitError> {
        validate_patch_candidate(&patch)?;
        if patch.relation != GoalPatchRelation::Independent {
            return Err(GoalCommitError::NonIndependentRequired);
        }
        let patch_id = patch.patch_id.clone();
        let binding = GoalPatchBinding::from(&patch);

        if let Some(recorded) = self.recorded_patches.get(&patch_id) {
            return match recorded {
                RecordedPatch::Independent {
                    binding: existing,
                    handoff,
                } if existing == &binding => {
                    Ok(IndependentGoalDisposition::AlreadyAdmitted(handoff.clone()))
                }
                _ => Err(GoalCommitError::PatchIdentityConflict),
            };
        }

        let parent = self
            .snapshot_for_revision(&patch.base_goal_revision)
            .ok_or(GoalCommitError::UnknownIndependentBaseRevision)?;
        let handoff = IndependentGoalHandoff {
            handoff_ref: format!("independent-goal-handoff:{}", patch.patch_id),
            patch_id: patch.patch_id.clone(),
            parent_goal_revision: patch.base_goal_revision.clone(),
            parent_constitution_fingerprint_ref: parent.fingerprint_ref.clone(),
            proposed_goal_ref: patch.proposed_delta_ref.clone(),
            exact_source_refs: patch.exact_source_refs.clone(),
            acceptance_evidence_refs: patch.acceptance_evidence_refs.clone(),
        };
        self.recorded_patches.insert(
            patch_id,
            RecordedPatch::Independent {
                binding,
                handoff: handoff.clone(),
            },
        );
        Ok(IndependentGoalDisposition::Admitted(handoff))
    }

    pub fn has_accepted_patch(&self, patch_id: &str) -> bool {
        matches!(
            self.recorded_patches.get(patch_id),
            Some(RecordedPatch::Committed { .. })
        )
    }

    pub fn has_independent_handoff(&self, patch_id: &str) -> bool {
        matches!(
            self.recorded_patches.get(patch_id),
            Some(RecordedPatch::Independent { .. })
        )
    }

    fn snapshot_for_revision(&self, revision: &VersionedRef) -> Option<&GoalConstitutionSnapshot> {
        if &self.current.goal_revision == revision {
            return Some(&self.current);
        }
        self.accepted_history.iter().find_map(|commit| {
            if &commit.prior_state.goal_revision == revision {
                Some(&commit.prior_state)
            } else if &commit.current_state.goal_revision == revision {
                Some(&commit.current_state)
            } else {
                None
            }
        })
    }
}

fn validate_constitution_snapshot(
    snapshot: &GoalConstitutionSnapshot,
) -> Result<(), GoalCommitError> {
    if snapshot.goal_revision.reference.trim().is_empty()
        || snapshot.fingerprint_ref.trim().is_empty()
        || !clean_nonempty_set(&snapshot.fingerprint_evidence_refs)
        || !clean_nonempty_set(&snapshot.original_goal_evidence_refs)
    {
        return Err(GoalCommitError::FingerprintInvalid);
    }
    validate_fields(&snapshot.fields)
}

fn validate_fields(
    fields: &BTreeMap<GoalConstitutionField, BTreeSet<String>>,
) -> Result<(), GoalCommitError> {
    if fields.len() != GOAL_FIELDS.len()
        || GOAL_FIELDS.iter().any(|field| !fields.contains_key(field))
        || fields
            .values()
            .any(|values| values.iter().any(|value| value.trim().is_empty()))
    {
        return Err(GoalCommitError::InvalidEvidenceRef);
    }
    Ok(())
}

fn changed_fields(
    before: &BTreeMap<GoalConstitutionField, BTreeSet<String>>,
    after: &BTreeMap<GoalConstitutionField, BTreeSet<String>>,
) -> BTreeSet<GoalConstitutionField> {
    GOAL_FIELDS
        .iter()
        .copied()
        .filter(|field| before.get(field) != after.get(field))
        .collect()
}

fn validate_authorization(
    authorization: &GoalAmendmentAuthorization,
    current: &GoalConstitutionSnapshot,
    changed: &BTreeSet<GoalConstitutionField>,
) -> Result<(), GoalCommitError> {
    if authorization.authorization_ref.trim().is_empty()
        || authorization.principal_context_ref.trim().is_empty()
        || authorization.base_goal_revision != current.goal_revision
        || authorization.base_fingerprint_ref != current.fingerprint_ref
        || authorization.authorized_fields != *changed
        || !clean_nonempty_set(&authorization.authority_evidence_refs)
    {
        return Err(GoalCommitError::AuthorizationMismatch);
    }
    Ok(())
}

fn validate_amendment_candidate(candidate: &GoalAmendmentCandidate) -> Result<(), GoalCommitError> {
    validate_patch_candidate(&candidate.patch)?;
    if candidate.base_fingerprint_ref.trim().is_empty()
        || candidate.resulting_fingerprint_ref.trim().is_empty()
        || !clean_nonempty_set(&candidate.resulting_fingerprint_evidence_refs)
    {
        return Err(GoalCommitError::FingerprintInvalid);
    }
    if candidate.changed_fields.is_empty() {
        return Err(GoalCommitError::ChangedFieldSetEmpty);
    }
    Ok(())
}

fn validate_patch_candidate(patch: &GoalPatch) -> Result<(), GoalCommitError> {
    if patch.patch_id.trim().is_empty() {
        return Err(GoalCommitError::EmptyPatchId);
    }
    if patch.proposed_delta_ref.trim().is_empty() {
        return Err(GoalCommitError::EmptyProposedDeltaRef);
    }
    if patch.resulting_goal_revision.is_some() {
        return Err(GoalCommitError::CandidateAlreadyClaimsCommittedRevision);
    }
    if !clean_nonempty_set(&patch.acceptance_evidence_refs) {
        return Err(GoalCommitError::EmptyAcceptanceEvidence);
    }
    if !clean_nonempty_set(&patch.exact_source_refs) {
        return Err(GoalCommitError::EmptySourceEvidence);
    }
    if patch.base_goal_revision.reference.trim().is_empty()
        || !clean_set_allow_empty(&patch.affected_work_refs)
        || !clean_set_allow_empty(&patch.affected_plan_refs)
        || !clean_set_allow_empty(&patch.affected_context_refs)
    {
        return Err(GoalCommitError::InvalidEvidenceRef);
    }
    Ok(())
}

fn clean_nonempty_set(values: &BTreeSet<String>) -> bool {
    !values.is_empty() && clean_set_allow_empty(values)
}

fn clean_set_allow_empty(values: &BTreeSet<String>) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
}
