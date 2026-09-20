use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

struct FirstListedScheduler;

impl SchedulerPolicy for FirstListedScheduler {
    fn allocate(
        &self,
        request: &SchedulerRequest,
    ) -> Result<SchedulerDecision, AdaptivePolicyError> {
        let first = request
            .candidates
            .first()
            .map(|candidate| candidate.task_ref.clone())
            .into_iter()
            .collect();
        Ok(SchedulerDecision {
            decision_id: "first-listed".into(),
            ready_set_revision_ref: request.ready_set_revision_ref.clone(),
            admitted_task_refs: first,
            deferred_task_refs: request
                .candidates
                .iter()
                .skip(1)
                .map(|candidate| candidate.task_ref.clone())
                .collect(),
            preempted_task_refs: BTreeSet::new(),
            resource_reservation_refs: BTreeSet::new(),
            placement_reservation_refs: BTreeSet::new(),
            protected_conflict_evidence_refs: request.protected_conflict_refs.clone(),
            fairness_observation_refs: BTreeSet::new(),
            policy: AdaptivePolicyRef {
                policy_ref: "test-first-listed".into(),
                version: "1".into(),
                qualification_evidence_refs: set(&["test-only"]),
            },
            decision_evidence_refs: set(&["explicit-test-policy"]),
            reevaluation_trigger_refs: BTreeSet::new(),
        })
    }
}

struct LastListedScheduler;

impl SchedulerPolicy for LastListedScheduler {
    fn allocate(
        &self,
        request: &SchedulerRequest,
    ) -> Result<SchedulerDecision, AdaptivePolicyError> {
        let selected = request
            .candidates
            .last()
            .map(|candidate| candidate.task_ref.clone());
        Ok(SchedulerDecision {
            decision_id: "last-listed".into(),
            ready_set_revision_ref: request.ready_set_revision_ref.clone(),
            admitted_task_refs: selected.iter().cloned().collect(),
            deferred_task_refs: request
                .candidates
                .iter()
                .filter(|candidate| Some(&candidate.task_ref) != selected.as_ref())
                .map(|candidate| candidate.task_ref.clone())
                .collect(),
            preempted_task_refs: BTreeSet::new(),
            resource_reservation_refs: BTreeSet::new(),
            placement_reservation_refs: BTreeSet::new(),
            protected_conflict_evidence_refs: request.protected_conflict_refs.clone(),
            fairness_observation_refs: BTreeSet::new(),
            policy: AdaptivePolicyRef {
                policy_ref: "test-last-listed".into(),
                version: "1".into(),
                qualification_evidence_refs: set(&["test-only"]),
            },
            decision_evidence_refs: set(&["explicit-test-policy"]),
            reevaluation_trigger_refs: BTreeSet::new(),
        })
    }
}

fn candidate(name: &str) -> SchedulerCandidate {
    SchedulerCandidate {
        task_ref: name.into(),
        semantic_priority_evidence_refs: BTreeSet::new(),
        commitment_refs: BTreeSet::new(),
        deadline_refs: BTreeSet::new(),
        risk_refs: BTreeSet::new(),
        resource_pressure_refs: BTreeSet::new(),
        preemption_cost_refs: BTreeSet::new(),
        fairness_evidence_refs: BTreeSet::new(),
    }
}

#[test]
fn s04_scheduler_preference_is_replaceable_not_core_hard_coded() {
    let request = SchedulerRequest {
        ready_set_revision_ref: "ready@1".into(),
        candidates: vec![candidate("task-a"), candidate("task-b")],
        available_resource_refs: BTreeSet::new(),
        protected_conflict_refs: BTreeSet::new(),
        current_commitment_refs: BTreeSet::new(),
    };

    let first = FirstListedScheduler.allocate(&request).unwrap();
    let last = LastListedScheduler.allocate(&request).unwrap();

    assert_eq!(first.admitted_task_refs, set(&["task-a"]));
    assert_eq!(last.admitted_task_refs, set(&["task-b"]));
    assert_ne!(first.policy.policy_ref, last.policy.policy_ref);
}

struct ExplicitRouter;

impl ModelRouter for ExplicitRouter {
    fn route(
        &self,
        request: &ModelRoutingRequest,
    ) -> Result<ModelRoutingReceipt, AdaptivePolicyError> {
        let selected = request.qualified_candidates.first();
        let selected_ref = selected.map(|candidate| candidate.candidate_ref.clone());
        Ok(ModelRoutingReceipt {
            receipt_id: "route-test".into(),
            request_ref: request.request.request_id.clone(),
            eligible_candidate_refs: request
                .qualified_candidates
                .iter()
                .map(|candidate| candidate.candidate_ref.clone())
                .collect(),
            rejected_candidates: Vec::new(),
            selected_candidate_ref: selected_ref,
            selected_model_version: selected
                .map(|candidate| candidate.profile.model_version.clone()),
            qualification_profile_refs: request
                .qualified_candidates
                .iter()
                .map(|candidate| candidate.qualification_profile_ref.clone())
                .collect(),
            evaluation_version_refs: set(&["test-eval"]),
            constraint_refs: request.request.privacy_constraint_refs.clone(),
            optimization_policy: AdaptivePolicyRef {
                policy_ref: "explicit-test-router".into(),
                version: "1".into(),
                qualification_evidence_refs: set(&["test-only"]),
            },
            fallback_behavior_ref: "explicit-no-eligible-behavior".into(),
        })
    }
}

#[test]
fn s04_model_router_returns_auditable_receipt_instead_of_direct_commit() {
    let request = ModelRoutingRequest {
        request: ModelRequest {
            request_id: "model-request".into(),
            regime_refs: set(&["coding"]),
            domain_refs: set(&["rust"]),
            quality_floor_ref: "floor".into(),
            privacy_constraint_refs: set(&["private"]),
            data_constraint_refs: BTreeSet::new(),
            required_modalities: set(&["text"]),
            structured_output_requirement_ref: None,
            tool_requirement_refs: BTreeSet::new(),
            context_requirement_ref: "context".into(),
            deadline_resource_envelope_ref: None,
            verification_plan_ref: "verify".into(),
        },
        qualified_candidates: vec![QualifiedModelRoutingCandidate {
            candidate_ref: "candidate-a".into(),
            profile: ModelQualificationProfile {
                model_ref: "model-a".into(),
                provider_ref: "provider-a".into(),
                model_version: "m1".into(),
                adapter_version: "a1".into(),
                regime_evidence_refs: set(&["regime"]),
                domain_evidence_refs: set(&["domain"]),
                heldout_distribution_refs: set(&["heldout"]),
                structured_output_evidence_refs: BTreeSet::new(),
                tool_reliability_evidence_refs: BTreeSet::new(),
                modality_refs: set(&["text"]),
                context_behavior_evidence_refs: set(&["context-eval"]),
                privacy_policy_refs: set(&["private"]),
                data_residency_refs: BTreeSet::new(),
                retention_policy_refs: BTreeSet::new(),
                provenance_ref: "provenance".into(),
                health_ref: "health".into(),
                calibration_validity_ref: "validity".into(),
            },
            qualification_profile_ref: "eligibility-proof".into(),
        }],
    };

    let receipt = ExplicitRouter.route(&request).unwrap();
    assert_eq!(
        receipt.selected_candidate_ref.as_deref(),
        Some("candidate-a")
    );
    assert_eq!(receipt.request_ref, "model-request");
}
