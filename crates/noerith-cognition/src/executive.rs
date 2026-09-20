use crate::{
    AdaptivePolicyError, AdaptivePolicyRef, ModelEligibilityProof, ModelQualificationProfile,
    ModelRequest, ModelRouter, ModelRoutingReceipt, ModelRoutingRequest, PlanProposal,
    PlanningPolicy, PlanningRequest, ProgressEvaluation, ProgressEvaluationRequest,
    ProgressEvaluator, QualifiedModelRoutingCandidate, ReadySetSnapshot, SchedulerCandidate,
    SchedulerDecision, SchedulerPolicy, SchedulerRequest, TaskGraph, validate_model_eligibility,
    validate_task_graph,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutiveError {
    Adaptive(AdaptivePolicyError),
    InvalidRequest(&'static str),
    InvalidPlanGraph,
    InvalidPlanEvidence,
    PlanGoalMismatch,
    PlanWorkMismatch,
    PlanDroppedQualityRequirement,
    PlanDroppedUnresolvedQuestion,
    SchedulerCandidateOutsideReadySet,
    SchedulerDuplicateCandidate,
    SchedulerReadySetMismatch,
    SchedulerSelectionOutsideCandidateSet,
    SchedulerDispositionOverlap,
    SchedulerIncompleteDisposition,
    SchedulerUnsupportedPreemption,
    SchedulerMissingDecisionEvidence,
    NoEligibleModel,
    DuplicateModelCandidate,
    AmbiguousModelIdentity,
    RouterRequestMismatch,
    RouterEligibleSetMismatch,
    RouterSelectedIneligibleModel,
    RouterSelectedVersionMismatch,
    RouterMissingReceiptEvidence,
    MissingEligibilityProof,
    InvalidProgressEvidence,
    InvalidProgressDisposition,
}

pub struct PlannerController<P> {
    policy: P,
}

impl<P> PlannerController<P>
where
    P: PlanningPolicy,
{
    pub const fn new(policy: P) -> Self {
        Self { policy }
    }

    pub fn propose(&self, request: &PlanningRequest) -> Result<PlanProposal, ExecutiveError> {
        validate_planning_request(request)?;
        let proposal = self
            .policy
            .propose_plan(request)
            .map_err(ExecutiveError::Adaptive)?;
        validate_task_graph(&proposal.task_graph).map_err(|_| ExecutiveError::InvalidPlanGraph)?;

        if proposal.goal_revision != request.accepted_goal
            || proposal
                .task_graph
                .nodes
                .iter()
                .any(|node| node.goal != request.accepted_goal)
        {
            return Err(ExecutiveError::PlanGoalMismatch);
        }
        if proposal
            .task_graph
            .nodes
            .iter()
            .any(|node| node.work != request.accepted_work)
        {
            return Err(ExecutiveError::PlanWorkMismatch);
        }
        if !request
            .quality_requirement_refs
            .is_subset(&proposal.quality_requirement_refs)
        {
            return Err(ExecutiveError::PlanDroppedQualityRequirement);
        }
        if !request
            .unresolved_question_refs
            .is_subset(&proposal.unresolved_question_refs)
        {
            return Err(ExecutiveError::PlanDroppedUnresolvedQuestion);
        }
        validate_plan_evidence(&proposal)?;
        Ok(proposal)
    }
}

pub struct SchedulerController<P> {
    policy: P,
}

impl<P> SchedulerController<P>
where
    P: SchedulerPolicy,
{
    pub const fn new(policy: P) -> Self {
        Self { policy }
    }

    /// Canonical scheduling path. Readiness is produced by `ExecutionGraph` and
    /// cannot be reconstructed from caller-supplied task IDs.
    pub fn propose_allocation(
        &self,
        ready: &ReadySetSnapshot,
        candidates: Vec<SchedulerCandidate>,
        available_resource_refs: BTreeSet<String>,
        protected_conflict_refs: BTreeSet<String>,
        current_commitment_refs: BTreeSet<String>,
    ) -> Result<SchedulerDecision, ExecutiveError> {
        if ready.snapshot_ref().trim().is_empty() {
            return Err(ExecutiveError::InvalidRequest("ready_set_revision_ref"));
        }

        let mut candidate_refs = BTreeSet::new();
        for candidate in &candidates {
            if candidate.task_ref.trim().is_empty() {
                return Err(ExecutiveError::InvalidRequest("scheduler.task_ref"));
            }
            if !candidate_refs.insert(candidate.task_ref.clone()) {
                return Err(ExecutiveError::SchedulerDuplicateCandidate);
            }
        }
        if candidate_refs != *ready.ready_task_refs() {
            return Err(ExecutiveError::SchedulerCandidateOutsideReadySet);
        }

        let request = SchedulerRequest {
            ready_set_revision_ref: ready.snapshot_ref().to_owned(),
            candidates,
            available_resource_refs,
            protected_conflict_refs,
            current_commitment_refs,
        };
        let decision = self
            .policy
            .allocate(&request)
            .map_err(ExecutiveError::Adaptive)?;

        if decision.ready_set_revision_ref != request.ready_set_revision_ref {
            return Err(ExecutiveError::SchedulerReadySetMismatch);
        }
        if !decision.admitted_task_refs.is_subset(&candidate_refs)
            || !decision.deferred_task_refs.is_subset(&candidate_refs)
            || !decision.preempted_task_refs.is_subset(&candidate_refs)
        {
            return Err(ExecutiveError::SchedulerSelectionOutsideCandidateSet);
        }
        if !decision
            .admitted_task_refs
            .is_disjoint(&decision.deferred_task_refs)
            || !decision
                .admitted_task_refs
                .is_disjoint(&decision.preempted_task_refs)
            || !decision
                .deferred_task_refs
                .is_disjoint(&decision.preempted_task_refs)
        {
            return Err(ExecutiveError::SchedulerDispositionOverlap);
        }
        if !decision.preempted_task_refs.is_empty() {
            // The current request carries no separately versioned running set.
            // Treating a ready candidate as preemptible would manufacture state.
            return Err(ExecutiveError::SchedulerUnsupportedPreemption);
        }
        let covered: BTreeSet<String> = decision
            .admitted_task_refs
            .union(&decision.deferred_task_refs)
            .cloned()
            .collect();
        if covered != candidate_refs {
            return Err(ExecutiveError::SchedulerIncompleteDisposition);
        }
        if decision.decision_id.trim().is_empty()
            || !clean_policy(&decision.policy)
            || !clean_nonempty_set(&decision.decision_evidence_refs)
        {
            return Err(ExecutiveError::SchedulerMissingDecisionEvidence);
        }
        Ok(decision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCandidate {
    pub candidate_ref: String,
    pub profile: ModelQualificationProfile,
    pub eligibility_proof: ModelEligibilityProof,
}

pub struct ModelFabric<R> {
    router: R,
}

impl<R> ModelFabric<R>
where
    R: ModelRouter,
{
    pub const fn new(router: R) -> Self {
        Self { router }
    }

    pub fn route(
        &self,
        request: ModelRequest,
        candidates: Vec<ModelCandidate>,
    ) -> Result<ModelRoutingReceipt, ExecutiveError> {
        if request.request_id.trim().is_empty() {
            return Err(ExecutiveError::InvalidRequest("model.request_id"));
        }

        let mut seen_candidate_refs = BTreeSet::new();
        let mut seen_model_identities = BTreeSet::new();
        let mut qualified = Vec::new();
        let mut eligible_refs = BTreeSet::new();
        let mut qualification_refs = BTreeSet::new();
        let mut profile_by_candidate = BTreeMap::<String, ModelQualificationProfile>::new();

        for candidate in candidates {
            if candidate.candidate_ref.trim().is_empty() {
                return Err(ExecutiveError::InvalidRequest("model.candidate_ref"));
            }
            if !seen_candidate_refs.insert(candidate.candidate_ref.clone()) {
                return Err(ExecutiveError::DuplicateModelCandidate);
            }
            let model_identity = (
                candidate.profile.provider_ref.clone(),
                candidate.profile.model_ref.clone(),
                candidate.profile.model_version.clone(),
                candidate.profile.adapter_version.clone(),
            );
            if !seen_model_identities.insert(model_identity) {
                return Err(ExecutiveError::AmbiguousModelIdentity);
            }

            if validate_model_eligibility(
                &request,
                &candidate.profile,
                &candidate.eligibility_proof,
            )
            .is_err()
            {
                continue;
            }
            if candidate
                .eligibility_proof
                .qualification_profile_ref
                .trim()
                .is_empty()
                || !clean_nonempty_set(&candidate.eligibility_proof.evidence_refs)
            {
                return Err(ExecutiveError::MissingEligibilityProof);
            }

            eligible_refs.insert(candidate.candidate_ref.clone());
            qualification_refs.insert(
                candidate
                    .eligibility_proof
                    .qualification_profile_ref
                    .clone(),
            );
            profile_by_candidate.insert(candidate.candidate_ref.clone(), candidate.profile.clone());
            qualified.push(QualifiedModelRoutingCandidate {
                candidate_ref: candidate.candidate_ref,
                profile: candidate.profile,
                qualification_profile_ref: candidate.eligibility_proof.qualification_profile_ref,
            });
        }

        if qualified.is_empty() {
            return Err(ExecutiveError::NoEligibleModel);
        }

        let routing_request = ModelRoutingRequest {
            request: request.clone(),
            qualified_candidates: qualified,
        };
        let receipt = self
            .router
            .route(&routing_request)
            .map_err(ExecutiveError::Adaptive)?;

        if receipt.request_ref != request.request_id {
            return Err(ExecutiveError::RouterRequestMismatch);
        }
        if receipt.eligible_candidate_refs != eligible_refs {
            return Err(ExecutiveError::RouterEligibleSetMismatch);
        }
        let Some(selected) = receipt.selected_candidate_ref.as_ref() else {
            return Err(ExecutiveError::RouterSelectedIneligibleModel);
        };
        let Some(selected_profile) = profile_by_candidate.get(selected) else {
            return Err(ExecutiveError::RouterSelectedIneligibleModel);
        };
        if receipt.selected_model_version.as_deref()
            != Some(selected_profile.model_version.as_str())
        {
            return Err(ExecutiveError::RouterSelectedVersionMismatch);
        }

        let required_constraints: BTreeSet<String> = request
            .privacy_constraint_refs
            .union(&request.data_constraint_refs)
            .cloned()
            .collect();
        if receipt.qualification_profile_refs != qualification_refs
            || !clean_nonempty_set(&receipt.evaluation_version_refs)
            || !required_constraints.is_subset(&receipt.constraint_refs)
            || receipt.fallback_behavior_ref.trim().is_empty()
            || !clean_policy(&receipt.optimization_policy)
        {
            return Err(ExecutiveError::RouterMissingReceiptEvidence);
        }
        Ok(receipt)
    }
}

pub struct ProgressController<E> {
    evaluator: E,
}

impl<E> ProgressController<E>
where
    E: ProgressEvaluator,
{
    pub const fn new(evaluator: E) -> Self {
        Self { evaluator }
    }

    pub fn evaluate(
        &self,
        request: &ProgressEvaluationRequest,
    ) -> Result<ProgressEvaluation, ExecutiveError> {
        validate_progress_request(request)?;
        let result = self
            .evaluator
            .evaluate_progress(request)
            .map_err(ExecutiveError::Adaptive)?;

        let observed_evidence_refs: BTreeSet<&str> = request
            .observed_progress
            .iter()
            .map(|evidence| evidence.evidence_ref.as_str())
            .collect();

        let valid = match &result {
            ProgressEvaluation::Sufficient { evidence_refs } => {
                clean_nonempty_set(evidence_refs)
                    && evidence_refs.contains(&request.expected_completion_evidence_ref)
                    && observed_evidence_refs
                        .contains(request.expected_completion_evidence_ref.as_str())
            }
            ProgressEvaluation::Continue {
                next_evidence_need_refs,
            } => clean_nonempty_set(next_evidence_need_refs),
            ProgressEvaluation::Retrieve {
                missing_evidence_refs,
            } => clean_nonempty_set(missing_evidence_refs),
            ProgressEvaluation::Replan {
                reason_evidence_refs,
            } => clean_nonempty_set(reason_evidence_refs),
            ProgressEvaluation::Ask {
                irreducible_information_refs,
            } => clean_nonempty_set(irreducible_information_refs),
            ProgressEvaluation::Defer {
                blocked_dependency_refs,
            } => {
                clean_nonempty_set(blocked_dependency_refs)
                    && blocked_dependency_refs.is_subset(&request.blocked_dependency_refs)
            }
        };
        if !valid {
            return Err(ExecutiveError::InvalidProgressDisposition);
        }
        Ok(result)
    }
}

/// This is a type-boundary assertion, not a semantic permission check. A
/// `TaskGraph` contains requirements and evidence references but no credential,
/// dispatch lease or controlled-release token; protected effect authority lives
/// outside this crate.
pub const fn plan_contains_no_direct_effect_commit_authority(_graph: &TaskGraph) -> bool {
    true
}

fn validate_planning_request(request: &PlanningRequest) -> Result<(), ExecutiveError> {
    for (name, value) in [
        (
            "planning.context_manifest_ref",
            request.context_manifest_ref.as_str(),
        ),
        (
            "planning.accepted_goal.reference",
            request.accepted_goal.reference.as_str(),
        ),
        (
            "planning.accepted_work.reference",
            request.accepted_work.reference.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(ExecutiveError::InvalidRequest(name));
        }
    }
    if !clean_nonempty_set(&request.current_state_refs)
        || !clean_nonempty_set(&request.quality_requirement_refs)
        || request
            .unresolved_question_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        || request
            .resource_envelope_ref
            .as_deref()
            .is_some_and(|reference| reference.trim().is_empty())
    {
        return Err(ExecutiveError::InvalidRequest("planning.evidence_or_scope"));
    }
    Ok(())
}

fn validate_plan_evidence(proposal: &PlanProposal) -> Result<(), ExecutiveError> {
    if proposal.proposal_id.trim().is_empty()
        || !clean_nonempty_set(&proposal.source_evidence_refs)
        || !clean_nonempty_set(&proposal.candidate_path_refs)
        || !clean_nonempty_set(&proposal.selection_reason_evidence_refs)
        || !clean_nonempty_set(&proposal.consequence_estimate_refs)
        || !clean_nonempty_set(&proposal.quality_requirement_refs)
        || !clean_nonempty_set(&proposal.stop_condition_refs)
        || proposal.resource_estimate_ref.trim().is_empty()
        || !clean_policy(&proposal.trajectory_policy)
        || !clean_policy(&proposal.planner_policy)
        || proposal
            .assumption_refs
            .iter()
            .chain(proposal.unresolved_question_refs.iter())
            .any(|reference| reference.trim().is_empty())
    {
        return Err(ExecutiveError::InvalidPlanEvidence);
    }
    Ok(())
}

fn validate_progress_request(request: &ProgressEvaluationRequest) -> Result<(), ExecutiveError> {
    if request.task_ref.trim().is_empty()
        || request.expected_completion_evidence_ref.trim().is_empty()
        || request
            .blocked_dependency_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
    {
        return Err(ExecutiveError::InvalidRequest("progress.request"));
    }
    for evidence in &request.observed_progress {
        if evidence.task_ref != request.task_ref
            || evidence.evidence_ref.trim().is_empty()
            || !clean_nonempty_set(&evidence.source_refs)
        {
            return Err(ExecutiveError::InvalidProgressEvidence);
        }
    }
    Ok(())
}

fn clean_policy(policy: &AdaptivePolicyRef) -> bool {
    !policy.policy_ref.trim().is_empty()
        && !policy.version.trim().is_empty()
        && clean_nonempty_set(&policy.qualification_evidence_refs)
}

fn clean_nonempty_set(values: &BTreeSet<String>) -> bool {
    !values.is_empty() && values.iter().all(|value| !value.trim().is_empty())
}
