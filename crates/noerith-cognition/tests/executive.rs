use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy(name: &str) -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: name.into(),
        version: "qualified".into(),
        qualification_evidence_refs: set(&["heldout-evidence"]),
    }
}

fn versioned(reference: &str, version: u64) -> VersionedRef {
    VersionedRef {
        reference: reference.into(),
        version,
    }
}

fn task(name: &str) -> TaskNode {
    TaskNode {
        task_ref: name.into(),
        goal: versioned("goal-a", 3),
        work: versioned("work-a", 2),
        semantic_operation_ref: format!("operation-{name}"),
        required_capability_refs: set(&["capability-a"]),
        required_evidence_refs: set(&["evidence-plan-a"]),
        state_class_ref: "S2".into(),
        protected_aggregate_refs: BTreeSet::new(),
        resource_envelope: ResourceEnvelope {
            resource_refs: BTreeSet::new(),
            placement_constraints: BTreeSet::new(),
            externally_calibrated_budget_ref: None,
        },
        timing: None,
        waiting_condition_ref: None,
        wake_condition_ref: None,
        permission_requirement_ref: Some("authority-required-downstream".into()),
        blocker_refs: BTreeSet::new(),
        completion_test_ref: "completion-test-a".into(),
        trajectory_checkpoint_ref: Some("trajectory-a".into()),
        interrupt_scope_ref: Some("interrupt-a".into()),
        cancellation_scope_ref: Some("cancel-a".into()),
    }
}

fn planning_request() -> PlanningRequest {
    PlanningRequest {
        context_manifest_ref: "context-a".into(),
        accepted_goal: versioned("goal-a", 3),
        accepted_work: versioned("work-a", 2),
        current_state_refs: set(&["belief-state-a"]),
        quality_requirement_refs: set(&["quality-floor-a"]),
        unresolved_question_refs: set(&["question-a"]),
        resource_envelope_ref: None,
    }
}

fn valid_plan(request: &PlanningRequest) -> PlanProposal {
    PlanProposal {
        proposal_id: "plan-a".into(),
        goal_revision: request.accepted_goal.clone(),
        source_evidence_refs: set(&["source-a"]),
        assumption_refs: BTreeSet::new(),
        unresolved_question_refs: request.unresolved_question_refs.clone(),
        candidate_path_refs: set(&["candidate-path-a"]),
        task_graph: TaskGraph {
            graph_id: "graph-a".into(),
            revision: 1,
            nodes: vec![task("task-a")],
            edges: Vec::new(),
            promise_refs: BTreeSet::new(),
            recurrence_revision_refs: BTreeSet::new(),
        },
        selection_reason_evidence_refs: set(&["selection-evidence"]),
        consequence_estimate_refs: set(&["consequence-a"]),
        quality_requirement_refs: request.quality_requirement_refs.clone(),
        stop_condition_refs: set(&["stop-if-evidence-missing"]),
        trajectory_policy: policy("trajectory-policy"),
        resource_estimate_ref: "resource-estimate-a".into(),
        planner_policy: policy("planner-policy"),
    }
}

struct ValidPlanner;

impl PlanningPolicy for ValidPlanner {
    fn propose_plan(&self, request: &PlanningRequest) -> Result<PlanProposal, AdaptivePolicyError> {
        Ok(valid_plan(request))
    }
}

#[test]
fn s04_planner_proposes_exact_goal_work_graph_without_effect_commit_authority() {
    let request = planning_request();
    let proposal = PlannerController::new(ValidPlanner)
        .propose(&request)
        .unwrap();
    assert_eq!(proposal.goal_revision, versioned("goal-a", 3));
    assert_eq!(proposal.task_graph.nodes[0].work, versioned("work-a", 2));
    assert!(plan_contains_no_direct_effect_commit_authority(
        &proposal.task_graph
    ));
}

struct StaleWorkPlanner;

impl PlanningPolicy for StaleWorkPlanner {
    fn propose_plan(&self, request: &PlanningRequest) -> Result<PlanProposal, AdaptivePolicyError> {
        let mut proposal = valid_plan(request);
        proposal.task_graph.nodes[0].work.version = 1;
        Ok(proposal)
    }
}

#[test]
fn s04_planner_cannot_smuggle_stale_work_revision() {
    assert_eq!(
        PlannerController::new(StaleWorkPlanner).propose(&planning_request()),
        Err(ExecutiveError::PlanWorkMismatch)
    );
}

struct WrongTaskGoalPlanner;

impl PlanningPolicy for WrongTaskGoalPlanner {
    fn propose_plan(&self, request: &PlanningRequest) -> Result<PlanProposal, AdaptivePolicyError> {
        let mut proposal = valid_plan(request);
        proposal.task_graph.nodes[0].goal.version += 1;
        Ok(proposal)
    }
}

#[test]
fn s04_planner_cannot_bind_tasks_to_a_different_goal_revision() {
    assert_eq!(
        PlannerController::new(WrongTaskGoalPlanner).propose(&planning_request()),
        Err(ExecutiveError::PlanGoalMismatch)
    );
}

struct DropsQualityPlanner;

impl PlanningPolicy for DropsQualityPlanner {
    fn propose_plan(&self, request: &PlanningRequest) -> Result<PlanProposal, AdaptivePolicyError> {
        let mut proposal = valid_plan(request);
        proposal.quality_requirement_refs.clear();
        Ok(proposal)
    }
}

#[test]
fn s04_planner_cannot_silently_lower_quality_floor() {
    assert_eq!(
        PlannerController::new(DropsQualityPlanner).propose(&planning_request()),
        Err(ExecutiveError::PlanDroppedQualityRequirement)
    );
}

struct DropsQuestionPlanner;

impl PlanningPolicy for DropsQuestionPlanner {
    fn propose_plan(&self, request: &PlanningRequest) -> Result<PlanProposal, AdaptivePolicyError> {
        let mut proposal = valid_plan(request);
        proposal.unresolved_question_refs.clear();
        Ok(proposal)
    }
}

#[test]
fn s04_planner_cannot_make_unresolved_question_disappear() {
    assert_eq!(
        PlannerController::new(DropsQuestionPlanner).propose(&planning_request()),
        Err(ExecutiveError::PlanDroppedUnresolvedQuestion)
    );
}

fn scheduler_candidate(task_ref: &str) -> SchedulerCandidate {
    SchedulerCandidate {
        task_ref: task_ref.into(),
        semantic_priority_evidence_refs: set(&["semantic-evidence"]),
        commitment_refs: BTreeSet::new(),
        deadline_refs: BTreeSet::new(),
        risk_refs: BTreeSet::new(),
        resource_pressure_refs: BTreeSet::new(),
        preemption_cost_refs: BTreeSet::new(),
        fairness_evidence_refs: BTreeSet::new(),
    }
}

fn ready_graph(names: &[&str]) -> (ExecutionGraph, ReadySetSnapshot) {
    let graph = TaskGraph {
        graph_id: "graph-ready".into(),
        revision: 5,
        nodes: names.iter().map(|name| task(name)).collect(),
        edges: Vec::new(),
        promise_refs: BTreeSet::new(),
        recurrence_revision_refs: BTreeSet::new(),
    };
    let runtime = ExecutionGraph::new(graph).unwrap();
    let ready = runtime.ready_set_snapshot(&[]).unwrap();
    (runtime, ready)
}

struct AdmitFirstDeferRest;

impl SchedulerPolicy for AdmitFirstDeferRest {
    fn allocate(
        &self,
        request: &SchedulerRequest,
    ) -> Result<SchedulerDecision, AdaptivePolicyError> {
        let first = request.candidates.first().unwrap().task_ref.clone();
        let all: BTreeSet<String> = request
            .candidates
            .iter()
            .map(|candidate| candidate.task_ref.clone())
            .collect();
        Ok(SchedulerDecision {
            decision_id: "schedule-a".into(),
            ready_set_revision_ref: request.ready_set_revision_ref.clone(),
            admitted_task_refs: BTreeSet::from([first.clone()]),
            deferred_task_refs: all.into_iter().filter(|item| item != &first).collect(),
            preempted_task_refs: BTreeSet::new(),
            resource_reservation_refs: BTreeSet::new(),
            placement_reservation_refs: BTreeSet::new(),
            protected_conflict_evidence_refs: BTreeSet::new(),
            fairness_observation_refs: BTreeSet::new(),
            policy: policy("scheduler-policy"),
            decision_evidence_refs: set(&["scheduler-evidence"]),
            reevaluation_trigger_refs: set(&["resource-change"]),
        })
    }
}

#[test]
fn s04_scheduler_consumes_graph_owned_ready_snapshot_and_total_disposition() {
    let (_runtime, ready) = ready_graph(&["task-a", "task-b"]);
    let decision = SchedulerController::new(AdmitFirstDeferRest)
        .propose_allocation(
            &ready,
            vec![scheduler_candidate("task-a"), scheduler_candidate("task-b")],
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(decision.ready_set_revision_ref, ready.snapshot_ref());
    assert_eq!(decision.admitted_task_refs.len(), 1);
    assert_eq!(decision.deferred_task_refs.len(), 1);
}

#[test]
fn s04_scheduler_rejects_duplicate_or_incomplete_candidate_surface() {
    let (_runtime, ready) = ready_graph(&["task-a", "task-b"]);
    assert_eq!(
        SchedulerController::new(AdmitFirstDeferRest).propose_allocation(
            &ready,
            vec![scheduler_candidate("task-a"), scheduler_candidate("task-a")],
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        ),
        Err(ExecutiveError::SchedulerDuplicateCandidate)
    );

    assert_eq!(
        SchedulerController::new(AdmitFirstDeferRest).propose_allocation(
            &ready,
            vec![scheduler_candidate("task-a")],
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        ),
        Err(ExecutiveError::SchedulerCandidateOutsideReadySet)
    );
}

struct StaleSchedulerReceipt;

impl SchedulerPolicy for StaleSchedulerReceipt {
    fn allocate(
        &self,
        request: &SchedulerRequest,
    ) -> Result<SchedulerDecision, AdaptivePolicyError> {
        let all: BTreeSet<String> = request
            .candidates
            .iter()
            .map(|candidate| candidate.task_ref.clone())
            .collect();
        Ok(SchedulerDecision {
            decision_id: "stale".into(),
            ready_set_revision_ref: "old-ready-set".into(),
            admitted_task_refs: all,
            deferred_task_refs: BTreeSet::new(),
            preempted_task_refs: BTreeSet::new(),
            resource_reservation_refs: BTreeSet::new(),
            placement_reservation_refs: BTreeSet::new(),
            protected_conflict_evidence_refs: BTreeSet::new(),
            fairness_observation_refs: BTreeSet::new(),
            policy: policy("scheduler-policy"),
            decision_evidence_refs: set(&["evidence"]),
            reevaluation_trigger_refs: BTreeSet::new(),
        })
    }
}

#[test]
fn s04_scheduler_cannot_replay_decision_for_old_ready_set() {
    let (_runtime, ready) = ready_graph(&["task-a"]);
    assert_eq!(
        SchedulerController::new(StaleSchedulerReceipt).propose_allocation(
            &ready,
            vec![scheduler_candidate("task-a")],
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        ),
        Err(ExecutiveError::SchedulerReadySetMismatch)
    );
}

fn profile(model_ref: &str) -> ModelQualificationProfile {
    ModelQualificationProfile {
        model_ref: model_ref.into(),
        provider_ref: "provider-a".into(),
        model_version: "m7".into(),
        adapter_version: "a3".into(),
        regime_evidence_refs: set(&["regime-eval"]),
        domain_evidence_refs: set(&["domain-eval"]),
        heldout_distribution_refs: set(&["heldout-eval"]),
        structured_output_evidence_refs: set(&["structured-eval"]),
        tool_reliability_evidence_refs: set(&["tool-eval"]),
        modality_refs: set(&["text"]),
        context_behavior_evidence_refs: set(&["context-eval"]),
        privacy_policy_refs: set(&["private-only"]),
        data_residency_refs: set(&["residency"]),
        retention_policy_refs: set(&["retention"]),
        provenance_ref: "provenance".into(),
        health_ref: "health-current".into(),
        calibration_validity_ref: "calibration-current".into(),
    }
}

fn model_request() -> ModelRequest {
    ModelRequest {
        request_id: "request-a".into(),
        regime_refs: set(&["coding"]),
        domain_refs: set(&["rust"]),
        quality_floor_ref: "floor-high".into(),
        privacy_constraint_refs: set(&["private-only"]),
        data_constraint_refs: set(&["no-training"]),
        required_modalities: set(&["text"]),
        structured_output_requirement_ref: Some("typed-json".into()),
        tool_requirement_refs: set(&["compiler"]),
        context_requirement_ref: "context-a".into(),
        deadline_resource_envelope_ref: None,
        verification_plan_ref: "verify-a".into(),
    }
}

fn eligibility(model_version: &str, floor: &str, qualification: &str) -> ModelEligibilityProof {
    ModelEligibilityProof {
        qualification_profile_ref: qualification.into(),
        current_model_version: model_version.into(),
        current_adapter_version: "a3".into(),
        quality_floor_ref: floor.into(),
        satisfied_privacy_constraint_refs: set(&["private-only"]),
        satisfied_data_constraint_refs: set(&["no-training"]),
        supported_modality_refs: set(&["text"]),
        supported_tool_requirement_refs: set(&["compiler"]),
        context_requirement_ref: "context-a".into(),
        structured_output_requirement_ref: Some("typed-json".into()),
        evidence_refs: set(&["eligibility-a"]),
    }
}

struct SelectFirstEligible;

impl ModelRouter for SelectFirstEligible {
    fn route(
        &self,
        request: &ModelRoutingRequest,
    ) -> Result<ModelRoutingReceipt, AdaptivePolicyError> {
        let selected = request
            .qualified_candidates
            .first()
            .expect("eligible candidate");
        let eligible_candidate_refs = request
            .qualified_candidates
            .iter()
            .map(|candidate| candidate.candidate_ref.clone())
            .collect();
        let qualification_profile_refs = request
            .qualified_candidates
            .iter()
            .map(|candidate| candidate.qualification_profile_ref.clone())
            .collect();
        Ok(ModelRoutingReceipt {
            receipt_id: "routing-a".into(),
            request_ref: request.request.request_id.clone(),
            eligible_candidate_refs,
            rejected_candidates: Vec::new(),
            selected_candidate_ref: Some(selected.candidate_ref.clone()),
            selected_model_version: Some(selected.profile.model_version.clone()),
            qualification_profile_refs,
            evaluation_version_refs: set(&["heldout-eval"]),
            constraint_refs: set(&["private-only", "no-training"]),
            optimization_policy: policy("routing-policy"),
            fallback_behavior_ref: "no-silent-quality-drop".into(),
        })
    }
}

#[test]
fn s04_model_fabric_filters_stale_or_lower_quality_before_adaptive_router() {
    let mut stale_profile = profile("model-stale");
    stale_profile.model_version = "m-old".into();

    let receipt = ModelFabric::new(SelectFirstEligible)
        .route(
            model_request(),
            vec![
                ModelCandidate {
                    candidate_ref: "candidate-good".into(),
                    profile: profile("model-a"),
                    eligibility_proof: eligibility("m7", "floor-high", "qualification-good"),
                },
                ModelCandidate {
                    candidate_ref: "candidate-stale".into(),
                    profile: stale_profile,
                    eligibility_proof: eligibility("m7", "floor-low", "qualification-stale"),
                },
            ],
        )
        .unwrap();
    assert_eq!(
        receipt.selected_candidate_ref.as_deref(),
        Some("candidate-good")
    );
}

struct AliasRouter;

impl ModelRouter for AliasRouter {
    fn route(
        &self,
        request: &ModelRoutingRequest,
    ) -> Result<ModelRoutingReceipt, AdaptivePolicyError> {
        let candidate = request.qualified_candidates.first().unwrap();
        Ok(ModelRoutingReceipt {
            receipt_id: "routing-alias".into(),
            request_ref: request.request.request_id.clone(),
            eligible_candidate_refs: set(&["model-a@m7"]),
            rejected_candidates: Vec::new(),
            selected_candidate_ref: Some("model-a@m7".into()),
            selected_model_version: Some(candidate.profile.model_version.clone()),
            qualification_profile_refs: set(&[candidate.qualification_profile_ref.as_str()]),
            evaluation_version_refs: set(&["heldout-eval"]),
            constraint_refs: set(&["private-only", "no-training"]),
            optimization_policy: policy("routing-policy"),
            fallback_behavior_ref: "no-silent-quality-drop".into(),
        })
    }
}

#[test]
fn s04_model_router_cannot_substitute_synthetic_model_alias_for_candidate_identity() {
    assert_eq!(
        ModelFabric::new(AliasRouter).route(
            model_request(),
            vec![ModelCandidate {
                candidate_ref: "candidate-good".into(),
                profile: profile("model-a"),
                eligibility_proof: eligibility("m7", "floor-high", "qualification-good"),
            }],
        ),
        Err(ExecutiveError::RouterEligibleSetMismatch)
    );
}

#[test]
fn s04_model_fabric_rejects_duplicate_model_identity_even_with_different_aliases() {
    assert_eq!(
        ModelFabric::new(SelectFirstEligible).route(
            model_request(),
            vec![
                ModelCandidate {
                    candidate_ref: "candidate-a".into(),
                    profile: profile("model-a"),
                    eligibility_proof: eligibility("m7", "floor-high", "qualification-a"),
                },
                ModelCandidate {
                    candidate_ref: "candidate-b".into(),
                    profile: profile("model-a"),
                    eligibility_proof: eligibility("m7", "floor-high", "qualification-b"),
                },
            ],
        ),
        Err(ExecutiveError::AmbiguousModelIdentity)
    );
}

struct CompletionEvaluator;

impl ProgressEvaluator for CompletionEvaluator {
    fn evaluate_progress(
        &self,
        request: &ProgressEvaluationRequest,
    ) -> Result<ProgressEvaluation, AdaptivePolicyError> {
        Ok(ProgressEvaluation::Sufficient {
            evidence_refs: set(&[request.expected_completion_evidence_ref.as_str()]),
        })
    }
}

#[test]
fn s04_progress_sufficient_requires_observed_same_task_completion_evidence() {
    let request = ProgressEvaluationRequest {
        task_ref: "task-a".into(),
        expected_completion_evidence_ref: "completion-proof-a".into(),
        observed_progress: vec![ProgressEvidence {
            evidence_ref: "completion-proof-a".into(),
            task_ref: "task-a".into(),
            kind: ProgressKind::MilestoneVerified,
            source_refs: set(&["test-run-a"]),
        }],
        blocked_dependency_refs: BTreeSet::new(),
    };
    assert!(
        ProgressController::new(CompletionEvaluator)
            .evaluate(&request)
            .is_ok()
    );
}

#[test]
fn s04_progress_cannot_use_other_task_evidence() {
    let request = ProgressEvaluationRequest {
        task_ref: "task-a".into(),
        expected_completion_evidence_ref: "completion-proof-a".into(),
        observed_progress: vec![ProgressEvidence {
            evidence_ref: "completion-proof-a".into(),
            task_ref: "task-b".into(),
            kind: ProgressKind::MilestoneVerified,
            source_refs: set(&["test-run-a"]),
        }],
        blocked_dependency_refs: BTreeSet::new(),
    };
    assert_eq!(
        ProgressController::new(CompletionEvaluator).evaluate(&request),
        Err(ExecutiveError::InvalidProgressEvidence)
    );
}

struct InventedBlockerEvaluator;

impl ProgressEvaluator for InventedBlockerEvaluator {
    fn evaluate_progress(
        &self,
        _request: &ProgressEvaluationRequest,
    ) -> Result<ProgressEvaluation, AdaptivePolicyError> {
        Ok(ProgressEvaluation::Defer {
            blocked_dependency_refs: set(&["invented-blocker"]),
        })
    }
}

#[test]
fn s04_progress_evaluator_cannot_invent_blocker_to_defer_forever() {
    let request = ProgressEvaluationRequest {
        task_ref: "task-a".into(),
        expected_completion_evidence_ref: "completion-proof-a".into(),
        observed_progress: Vec::new(),
        blocked_dependency_refs: set(&["real-blocker"]),
    };
    assert_eq!(
        ProgressController::new(InventedBlockerEvaluator).evaluate(&request),
        Err(ExecutiveError::InvalidProgressDisposition)
    );
}

struct EmptyReplanReason;

impl ProgressEvaluator for EmptyReplanReason {
    fn evaluate_progress(
        &self,
        _request: &ProgressEvaluationRequest,
    ) -> Result<ProgressEvaluation, AdaptivePolicyError> {
        Ok(ProgressEvaluation::Replan {
            reason_evidence_refs: BTreeSet::new(),
        })
    }
}

#[test]
fn s04_no_progress_logic_stays_adaptive_but_empty_reason_cannot_control_flow() {
    let request = ProgressEvaluationRequest {
        task_ref: "task-a".into(),
        expected_completion_evidence_ref: "completion-test".into(),
        observed_progress: Vec::new(),
        blocked_dependency_refs: BTreeSet::new(),
    };
    assert_eq!(
        ProgressController::new(EmptyReplanReason).evaluate(&request),
        Err(ExecutiveError::InvalidProgressDisposition)
    );
}
