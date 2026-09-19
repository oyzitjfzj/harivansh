use crate::{
    AdaptivePolicyRef, ContextCandidateDescriptor, ContextDeliveryBoundary,
    ContextSelectionBinding, ContextSelectionReceipt, ContextValidityFrontier, GoalPatch,
    GoalPatchRelation, ModelQualificationProfile, ModelRequest, ModelRoutingReceipt, PlanProposal,
    ProgressEvidence, ProtectedEvidenceRef, ReceiverContextProfileRef, SchedulerCandidate,
    SchedulerDecision, TrajectoryCheckpoint, VersionedRef,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptivePolicyError {
    pub error_ref: String,
    pub evidence_refs: BTreeSet<String>,
}

/// Structural failure of a bound adaptive proposal. This is deliberately
/// separate from `AdaptivePolicyError`: an adaptive policy may fail internally,
/// while this error means its returned protocol object is not safe to consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptiveProposalProtocolError {
    InvalidRequest(&'static str),
    BindingMismatch,
    MissingDecisionEvidence,
    RerankCandidateSetMismatch,
    RerankProtectedCandidateOutsideSelection,
    TrajectoryStateMismatch,
    TrajectoryEffectMismatch,
    GoalPatchSourceMismatch,
    GoalPatchDispositionMismatch,
}

/// Evidence-bearing request for adaptive context selection.
///
/// This is proposal data only. It carries no permission, credential or effect
/// authority. `resource_budget_ref` is advisory inside the declared quality
/// floor; protected evidence cannot be dropped merely to satisfy that budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSelectionRequest {
    pub tenant_ref: String,
    pub principal_context_ref: String,
    pub purpose_ref: String,
    pub candidate_set_revision_ref: String,
    pub candidates: Vec<ContextCandidateDescriptor>,
    pub delivery_boundaries: Vec<ContextDeliveryBoundary>,
    pub protected_evidence: Vec<ProtectedEvidenceRef>,
    pub validity_frontier: ContextValidityFrontier,
    pub receiver_profile: ReceiverContextProfileRef,
    pub unresolved_gap_refs: BTreeSet<String>,
    pub selector_policy: AdaptivePolicyRef,
    pub resource_budget_ref: Option<String>,
}

impl ContextSelectionRequest {
    pub fn binding(&self) -> ContextSelectionBinding {
        ContextSelectionBinding {
            tenant_ref: self.tenant_ref.clone(),
            principal_context_ref: self.principal_context_ref.clone(),
            purpose_ref: self.purpose_ref.clone(),
            candidate_set_revision_ref: self.candidate_set_revision_ref.clone(),
            validity_frontier: self.validity_frontier.clone(),
            receiver_profile: self.receiver_profile.clone(),
            selector_policy: self.selector_policy.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundContextSelectionReceipt {
    pub binding: ContextSelectionBinding,
    pub receipt: ContextSelectionReceipt,
}

pub trait ContextSelector {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRerankBinding {
    pub selection_binding: ContextSelectionBinding,
    pub selected_candidate_refs: BTreeSet<String>,
    pub protected_candidate_refs: BTreeSet<String>,
    pub reranker_policy: AdaptivePolicyRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRerankRequest {
    pub selection_binding: ContextSelectionBinding,
    pub selected_candidate_refs: BTreeSet<String>,
    pub protected_candidate_refs: BTreeSet<String>,
    pub reranker_policy: AdaptivePolicyRef,
}

impl ContextRerankRequest {
    pub fn binding(&self) -> ContextRerankBinding {
        ContextRerankBinding {
            selection_binding: self.selection_binding.clone(),
            selected_candidate_refs: self.selected_candidate_refs.clone(),
            protected_candidate_refs: self.protected_candidate_refs.clone(),
            reranker_policy: self.reranker_policy.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRerankProposal {
    pub ordered_candidate_refs: Vec<String>,
    pub decision_evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundContextRerankProposal {
    pub binding: ContextRerankBinding,
    pub proposal: ContextRerankProposal,
}

impl BoundContextRerankProposal {
    pub fn validate_for(
        &self,
        request: &ContextRerankRequest,
    ) -> Result<(), AdaptiveProposalProtocolError> {
        if request.selected_candidate_refs.is_empty()
            || !clean_nonempty_set(&request.selected_candidate_refs)
            || !clean_set_allow_empty(&request.protected_candidate_refs)
            || !qualified_policy(&request.reranker_policy)
        {
            return Err(AdaptiveProposalProtocolError::InvalidRequest(
                "context_rerank",
            ));
        }
        if !request
            .protected_candidate_refs
            .is_subset(&request.selected_candidate_refs)
        {
            return Err(AdaptiveProposalProtocolError::RerankProtectedCandidateOutsideSelection);
        }
        if self.binding != request.binding() {
            return Err(AdaptiveProposalProtocolError::BindingMismatch);
        }
        if !clean_nonempty_set(&self.proposal.decision_evidence_refs) {
            return Err(AdaptiveProposalProtocolError::MissingDecisionEvidence);
        }
        let ordered: BTreeSet<&str> = self
            .proposal
            .ordered_candidate_refs
            .iter()
            .map(String::as_str)
            .collect();
        if ordered.len() != self.proposal.ordered_candidate_refs.len()
            || self
                .proposal
                .ordered_candidate_refs
                .iter()
                .any(|candidate| candidate.trim().is_empty())
            || ordered
                != request
                    .selected_candidate_refs
                    .iter()
                    .map(String::as_str)
                    .collect()
        {
            return Err(AdaptiveProposalProtocolError::RerankCandidateSetMismatch);
        }
        Ok(())
    }
}

pub trait ContextReranker {
    fn propose_order(
        &self,
        request: &ContextRerankRequest,
    ) -> Result<BoundContextRerankProposal, AdaptivePolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningRequest {
    pub context_manifest_ref: String,
    pub accepted_goal: VersionedRef,
    pub accepted_work: VersionedRef,
    pub current_state_refs: BTreeSet<String>,
    pub quality_requirement_refs: BTreeSet<String>,
    pub unresolved_question_refs: BTreeSet<String>,
    pub resource_envelope_ref: Option<String>,
}

pub trait PlanningPolicy {
    fn propose_plan(&self, request: &PlanningRequest) -> Result<PlanProposal, AdaptivePolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryEvaluationBinding {
    pub previous_checkpoint_ref: Option<String>,
    pub original_goal: VersionedRef,
    pub current_goal: VersionedRef,
    pub current_work: VersionedRef,
    pub accepted_correction_refs: BTreeSet<String>,
    pub current_policy_refs: BTreeSet<String>,
    pub current_authority_refs: BTreeSet<String>,
    pub effect_refs: BTreeSet<String>,
    pub progress_evidence: Vec<ProgressEvidence>,
    pub unresolved_assumption_refs: BTreeSet<String>,
    pub evaluator_policy: AdaptivePolicyRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryEvaluationRequest {
    pub previous_checkpoint_ref: Option<String>,
    pub original_goal: VersionedRef,
    pub current_goal: VersionedRef,
    pub current_work: VersionedRef,
    pub accepted_correction_refs: BTreeSet<String>,
    pub current_policy_refs: BTreeSet<String>,
    pub current_authority_refs: BTreeSet<String>,
    pub effect_refs: BTreeSet<String>,
    pub progress_evidence: Vec<ProgressEvidence>,
    pub unresolved_assumption_refs: BTreeSet<String>,
    pub evaluator_policy: AdaptivePolicyRef,
}

impl TrajectoryEvaluationRequest {
    pub fn binding(&self) -> TrajectoryEvaluationBinding {
        TrajectoryEvaluationBinding {
            previous_checkpoint_ref: self.previous_checkpoint_ref.clone(),
            original_goal: self.original_goal.clone(),
            current_goal: self.current_goal.clone(),
            current_work: self.current_work.clone(),
            accepted_correction_refs: self.accepted_correction_refs.clone(),
            current_policy_refs: self.current_policy_refs.clone(),
            current_authority_refs: self.current_authority_refs.clone(),
            effect_refs: self.effect_refs.clone(),
            progress_evidence: self.progress_evidence.clone(),
            unresolved_assumption_refs: self.unresolved_assumption_refs.clone(),
            evaluator_policy: self.evaluator_policy.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundTrajectoryCheckpoint {
    pub binding: TrajectoryEvaluationBinding,
    pub checkpoint: TrajectoryCheckpoint,
    pub decision_evidence_refs: BTreeSet<String>,
}

impl BoundTrajectoryCheckpoint {
    pub fn validate_for(
        &self,
        request: &TrajectoryEvaluationRequest,
    ) -> Result<(), AdaptiveProposalProtocolError> {
        validate_trajectory_request(request)?;
        if self.binding != request.binding() {
            return Err(AdaptiveProposalProtocolError::BindingMismatch);
        }
        if !clean_nonempty_set(&self.decision_evidence_refs) {
            return Err(AdaptiveProposalProtocolError::MissingDecisionEvidence);
        }
        let checkpoint = &self.checkpoint;
        if checkpoint.original_goal_revision != request.original_goal
            || checkpoint.current_goal_revision != request.current_goal
            || checkpoint.correction_refs != request.accepted_correction_refs
            || checkpoint.policy_revision_refs != request.current_policy_refs
            || checkpoint.authority_revision_refs != request.current_authority_refs
            || checkpoint.progress_evidence != request.progress_evidence
            || checkpoint.unresolved_assumption_refs != request.unresolved_assumption_refs
            || checkpoint.evaluator_policy != request.evaluator_policy
        {
            return Err(AdaptiveProposalProtocolError::TrajectoryStateMismatch);
        }
        if !checkpoint
            .planned_effect_refs
            .is_subset(&request.effect_refs)
            || !checkpoint
                .attempted_effect_refs
                .is_subset(&request.effect_refs)
            || !checkpoint
                .accepted_effect_refs
                .is_subset(&request.effect_refs)
            || !checkpoint
                .observed_effect_refs
                .is_subset(&request.effect_refs)
            || !checkpoint
                .attempted_effect_refs
                .is_subset(&checkpoint.planned_effect_refs)
            || !checkpoint
                .accepted_effect_refs
                .is_subset(&checkpoint.attempted_effect_refs)
            || !checkpoint
                .observed_effect_refs
                .is_subset(&checkpoint.accepted_effect_refs)
        {
            return Err(AdaptiveProposalProtocolError::TrajectoryEffectMismatch);
        }
        Ok(())
    }
}

pub trait TrajectoryEvaluator {
    fn evaluate(
        &self,
        request: &TrajectoryEvaluationRequest,
    ) -> Result<BoundTrajectoryCheckpoint, AdaptivePolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerRequest {
    pub ready_set_revision_ref: String,
    pub candidates: Vec<SchedulerCandidate>,
    pub available_resource_refs: BTreeSet<String>,
    pub protected_conflict_refs: BTreeSet<String>,
    pub current_commitment_refs: BTreeSet<String>,
}

pub trait SchedulerPolicy {
    fn allocate(
        &self,
        request: &SchedulerRequest,
    ) -> Result<SchedulerDecision, AdaptivePolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressEvaluationRequest {
    pub task_ref: String,
    pub expected_completion_evidence_ref: String,
    pub observed_progress: Vec<ProgressEvidence>,
    pub blocked_dependency_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvaluation {
    Sufficient {
        evidence_refs: BTreeSet<String>,
    },
    Continue {
        next_evidence_need_refs: BTreeSet<String>,
    },
    Retrieve {
        missing_evidence_refs: BTreeSet<String>,
    },
    Replan {
        reason_evidence_refs: BTreeSet<String>,
    },
    Ask {
        irreducible_information_refs: BTreeSet<String>,
    },
    Defer {
        blocked_dependency_refs: BTreeSet<String>,
    },
}

pub trait ProgressEvaluator {
    fn evaluate_progress(
        &self,
        request: &ProgressEvaluationRequest,
    ) -> Result<ProgressEvaluation, AdaptivePolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedModelRoutingCandidate {
    pub candidate_ref: String,
    pub profile: ModelQualificationProfile,
    pub qualification_profile_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRoutingRequest {
    pub request: ModelRequest,
    pub qualified_candidates: Vec<QualifiedModelRoutingCandidate>,
}

pub trait ModelRouter {
    fn route(
        &self,
        request: &ModelRoutingRequest,
    ) -> Result<ModelRoutingReceipt, AdaptivePolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalPatchEvaluationBinding {
    pub patch: GoalPatch,
    pub current_goal: VersionedRef,
    pub current_constitution_fingerprint_ref: String,
    pub exact_source_refs: BTreeSet<String>,
    pub evaluator_policy: AdaptivePolicyRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalPatchEvaluationRequest {
    pub patch: GoalPatch,
    pub current_goal: VersionedRef,
    pub current_constitution_fingerprint_ref: String,
    pub exact_source_refs: BTreeSet<String>,
    pub evaluator_policy: AdaptivePolicyRef,
}

impl GoalPatchEvaluationRequest {
    pub fn binding(&self) -> GoalPatchEvaluationBinding {
        GoalPatchEvaluationBinding {
            patch: self.patch.clone(),
            current_goal: self.current_goal.clone(),
            current_constitution_fingerprint_ref: self.current_constitution_fingerprint_ref.clone(),
            exact_source_refs: self.exact_source_refs.clone(),
            evaluator_policy: self.evaluator_policy.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalPatchProposalDisposition {
    AcceptCandidate,
    RejectAsStale,
    RequireGrounding { missing_ref: String },
    KeepIndependent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundGoalPatchProposalDisposition {
    pub binding: GoalPatchEvaluationBinding,
    pub disposition: GoalPatchProposalDisposition,
    pub decision_evidence_refs: BTreeSet<String>,
}

impl BoundGoalPatchProposalDisposition {
    pub fn validate_for(
        &self,
        request: &GoalPatchEvaluationRequest,
    ) -> Result<(), AdaptiveProposalProtocolError> {
        if request.current_goal.reference.trim().is_empty()
            || request
                .current_constitution_fingerprint_ref
                .trim()
                .is_empty()
            || !clean_nonempty_set(&request.exact_source_refs)
            || !qualified_policy(&request.evaluator_policy)
        {
            return Err(AdaptiveProposalProtocolError::InvalidRequest(
                "goal_patch_evaluation",
            ));
        }
        if !request
            .patch
            .exact_source_refs
            .is_subset(&request.exact_source_refs)
        {
            return Err(AdaptiveProposalProtocolError::GoalPatchSourceMismatch);
        }
        if self.binding != request.binding() {
            return Err(AdaptiveProposalProtocolError::BindingMismatch);
        }
        if !clean_nonempty_set(&self.decision_evidence_refs) {
            return Err(AdaptiveProposalProtocolError::MissingDecisionEvidence);
        }
        let disposition_matches = match &self.disposition {
            GoalPatchProposalDisposition::AcceptCandidate => {
                request.patch.relation != GoalPatchRelation::Independent
                    && request.patch.base_goal_revision == request.current_goal
            }
            GoalPatchProposalDisposition::RejectAsStale => true,
            GoalPatchProposalDisposition::RequireGrounding { missing_ref } => {
                !missing_ref.trim().is_empty()
            }
            GoalPatchProposalDisposition::KeepIndependent => {
                request.patch.relation == GoalPatchRelation::Independent
            }
        };
        if !disposition_matches {
            return Err(AdaptiveProposalProtocolError::GoalPatchDispositionMismatch);
        }
        Ok(())
    }
}

pub trait GoalPatchEvaluator {
    fn evaluate_patch(
        &self,
        request: &GoalPatchEvaluationRequest,
    ) -> Result<BoundGoalPatchProposalDisposition, AdaptivePolicyError>;
}

fn validate_trajectory_request(
    request: &TrajectoryEvaluationRequest,
) -> Result<(), AdaptiveProposalProtocolError> {
    if request.original_goal.reference.trim().is_empty()
        || request.current_goal.reference.trim().is_empty()
        || request.current_work.reference.trim().is_empty()
        || request.original_goal.reference != request.current_goal.reference
        || request.original_goal.version > request.current_goal.version
        || optional_ref_is_empty(request.previous_checkpoint_ref.as_deref())
        || !clean_set_allow_empty(&request.accepted_correction_refs)
        || !clean_nonempty_set(&request.current_policy_refs)
        || !clean_nonempty_set(&request.current_authority_refs)
        || !clean_set_allow_empty(&request.effect_refs)
        || !clean_set_allow_empty(&request.unresolved_assumption_refs)
        || !qualified_policy(&request.evaluator_policy)
    {
        return Err(AdaptiveProposalProtocolError::InvalidRequest(
            "trajectory_evaluation",
        ));
    }
    if request.progress_evidence.iter().any(|evidence| {
        evidence.evidence_ref.trim().is_empty()
            || evidence.task_ref.trim().is_empty()
            || !clean_nonempty_set(&evidence.source_refs)
    }) {
        return Err(AdaptiveProposalProtocolError::InvalidRequest(
            "trajectory_progress_evidence",
        ));
    }
    Ok(())
}

fn qualified_policy(policy: &AdaptivePolicyRef) -> bool {
    !policy.policy_ref.trim().is_empty()
        && !policy.version.trim().is_empty()
        && clean_nonempty_set(&policy.qualification_evidence_refs)
}

fn clean_nonempty_set(values: &BTreeSet<String>) -> bool {
    !values.is_empty() && clean_set_allow_empty(values)
}

fn clean_set_allow_empty(values: &BTreeSet<String>) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
}

fn optional_ref_is_empty(value: Option<&str>) -> bool {
    value.is_some_and(|reference| reference.trim().is_empty())
}
