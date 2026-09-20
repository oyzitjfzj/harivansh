use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy(name: &str) -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: name.to_owned(),
        version: "qualified-candidate".to_owned(),
        qualification_evidence_refs: set(&["heldout-evidence"]),
    }
}

fn versioned(reference: &str, version: u64) -> VersionedRef {
    VersionedRef {
        reference: reference.to_owned(),
        version,
    }
}

#[test]
fn s04_context_keeps_protected_evidence_distinct_from_unresolved_gaps() {
    let protected = ProtectedEvidenceRef {
        field_ref: "target-account".into(),
        exact_value_digest: "digest-target".into(),
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::SourceSpan {
            source_ref: "source-a".into(),
            source_version: 2,
            span_ref: "span-a".into(),
            content_digest: "content-a".into(),
        }]),
    };
    let unresolved_gaps = set(&["missing-current-balance"]);

    assert_eq!(protected.field_ref, "target-account");
    assert!(
        protected
            .proving_evidence
            .iter()
            .any(|evidence| matches!(evidence, ProtectedEvidenceLocator::SourceSpan { .. }))
    );
    assert!(unresolved_gaps.contains("missing-current-balance"));
    assert!(!unresolved_gaps.contains(&protected.field_ref));
}

#[test]
fn s04_goal_patch_preserves_independent_work_instead_of_implying_supersession() {
    let independent = GoalPatch {
        patch_id: "patch-independent".into(),
        base_goal_revision: versioned("goal-a", 3),
        relation: GoalPatchRelation::Independent,
        proposed_delta_ref: "delta-new-unrelated-work".into(),
        exact_source_refs: set(&["message-new"]),
        affected_work_refs: BTreeSet::new(),
        affected_plan_refs: BTreeSet::new(),
        affected_context_refs: BTreeSet::new(),
        acceptance_evidence_refs: set(&["user-message"]),
        resulting_goal_revision: None,
    };
    let correction = GoalPatch {
        relation: GoalPatchRelation::Correct,
        affected_work_refs: set(&["work-a"]),
        affected_plan_refs: set(&["plan-a"]),
        affected_context_refs: set(&["context-a"]),
        ..independent.clone()
    };

    assert_eq!(independent.relation, GoalPatchRelation::Independent);
    assert!(independent.affected_work_refs.is_empty());
    assert_eq!(correction.relation, GoalPatchRelation::Correct);
    assert!(correction.affected_work_refs.contains("work-a"));
}

#[test]
fn s04_task_time_semantics_do_not_collapse_civil_elapsed_and_event_time() {
    let civil = TimingConstraint {
        semantics: TimeSemantics::CivilTime,
        schedule_ref: Some("calendar-schedule".into()),
        timezone_ref: Some("user-timezone".into()),
        recurrence_revision_ref: Some("recurrence-v3".into()),
        tolerated_window_ref: Some("window-profile".into()),
        time_source_confidence_ref: Some("clock-confidence".into()),
    };
    let elapsed = TimingConstraint {
        semantics: TimeSemantics::ElapsedDuration,
        schedule_ref: Some("duration-budget".into()),
        timezone_ref: None,
        recurrence_revision_ref: None,
        tolerated_window_ref: None,
        time_source_confidence_ref: Some("monotonic-clock".into()),
    };
    let event = TimingConstraint {
        semantics: TimeSemantics::EventBased,
        schedule_ref: Some("provider-event".into()),
        timezone_ref: None,
        recurrence_revision_ref: None,
        tolerated_window_ref: None,
        time_source_confidence_ref: None,
    };

    assert_ne!(civil.semantics, elapsed.semantics);
    assert_ne!(elapsed.semantics, event.semantics);
}

#[test]
fn s04_scheduler_decision_records_policy_and_evidence_without_baking_priority_math_into_contract() {
    let candidate = SchedulerCandidate {
        task_ref: "task-a".into(),
        semantic_priority_evidence_refs: set(&["user-commitment-a"]),
        commitment_refs: set(&["commitment-a"]),
        deadline_refs: set(&["deadline-a"]),
        risk_refs: set(&["risk-profile-a"]),
        resource_pressure_refs: set(&["resource-state-a"]),
        preemption_cost_refs: set(&["preemption-evidence-a"]),
        fairness_evidence_refs: set(&["waiting-history-a"]),
    };
    let decision = SchedulerDecision {
        decision_id: "schedule-a".into(),
        ready_set_revision_ref: "ready-set@8".into(),
        admitted_task_refs: set(&["task-a"]),
        deferred_task_refs: set(&["task-b"]),
        preempted_task_refs: BTreeSet::new(),
        resource_reservation_refs: set(&["cpu-reservation-a"]),
        placement_reservation_refs: set(&["device-a"]),
        protected_conflict_evidence_refs: BTreeSet::new(),
        fairness_observation_refs: candidate.fairness_evidence_refs.clone(),
        policy: policy("scheduler-policy-a"),
        decision_evidence_refs: set(&["scheduler-receipt-evidence"]),
        reevaluation_trigger_refs: set(&["resource-change", "deadline-change"]),
    };

    assert!(decision.admitted_task_refs.contains(&candidate.task_ref));
    assert!(!decision.policy.qualification_evidence_refs.is_empty());
}

#[test]
fn s04_trajectory_checkpoint_distinguishes_progress_uncertainty_and_divergence() {
    let checkpoint = TrajectoryCheckpoint {
        checkpoint_id: "trajectory-a".into(),
        original_goal_revision: versioned("goal-a", 1),
        current_goal_revision: versioned("goal-a", 5),
        correction_refs: set(&["patch-2", "patch-4"]),
        policy_revision_refs: set(&["policy@7"]),
        authority_revision_refs: set(&["authority@3"]),
        planned_effect_refs: set(&["effect-a"]),
        attempted_effect_refs: set(&["effect-a"]),
        accepted_effect_refs: BTreeSet::new(),
        observed_effect_refs: BTreeSet::new(),
        obligation_refs: set(&["obligation-a"]),
        unresolved_assumption_refs: set(&["assumption-a"]),
        progress_evidence: vec![
            ProgressEvidence {
                evidence_ref: "artifact-a".into(),
                task_ref: "task-a".into(),
                kind: ProgressKind::ArtifactProduced,
                source_refs: set(&["artifact-source"]),
            },
            ProgressEvidence {
                evidence_ref: "unknown-a".into(),
                task_ref: "task-a".into(),
                kind: ProgressKind::Uncertainty,
                source_refs: set(&["provider-state"]),
            },
        ],
        divergence_evidence_refs: set(&["goal-drift-evidence"]),
        affected_scope_refs: set(&["work-a"]),
        verdict: TrajectoryVerdict::Replan,
        next_permitted_step_ref: Some("retrieve-current-state".into()),
        evaluator_policy: policy("trajectory-evaluator-a"),
    };

    assert_eq!(checkpoint.verdict, TrajectoryVerdict::Replan);
    assert!(
        checkpoint
            .progress_evidence
            .iter()
            .any(|item| item.kind == ProgressKind::Uncertainty)
    );
}

#[test]
fn s04_model_routing_receipt_preserves_multidimensional_eligibility_and_rejection_reasons() {
    let profile = ModelQualificationProfile {
        model_ref: "model-a".into(),
        provider_ref: "provider-a".into(),
        model_version: "2026-09".into(),
        adapter_version: "adapter-v4".into(),
        regime_evidence_refs: set(&["coding-heldout"]),
        domain_evidence_refs: set(&["rust-domain"]),
        heldout_distribution_refs: set(&["eval-distribution-v8"]),
        structured_output_evidence_refs: set(&["structured-eval"]),
        tool_reliability_evidence_refs: set(&["tool-eval"]),
        modality_refs: set(&["text"]),
        context_behavior_evidence_refs: set(&["long-context-eval"]),
        privacy_policy_refs: set(&["private-processing-policy"]),
        data_residency_refs: set(&["residency-a"]),
        retention_policy_refs: set(&["retention-a"]),
        provenance_ref: "qualification-provenance".into(),
        health_ref: "provider-health-current".into(),
        calibration_validity_ref: "calibration-window-current".into(),
    };
    let request = ModelRequest {
        request_id: "model-request-a".into(),
        regime_refs: set(&["coding"]),
        domain_refs: set(&["rust"]),
        quality_floor_ref: "quality-floor-a".into(),
        privacy_constraint_refs: set(&["private-only"]),
        data_constraint_refs: set(&["no-training"]),
        required_modalities: set(&["text"]),
        structured_output_requirement_ref: Some("json-contract".into()),
        tool_requirement_refs: set(&["compiler-tool"]),
        context_requirement_ref: "context-profile-a".into(),
        deadline_resource_envelope_ref: Some("resource-envelope-a".into()),
        verification_plan_ref: "verification-plan-a".into(),
    };
    let receipt = ModelRoutingReceipt {
        receipt_id: "route-a".into(),
        request_ref: request.request_id.clone(),
        eligible_candidate_refs: set(&["model-a@2026-09"]),
        rejected_candidates: vec![ModelRejection {
            candidate_ref: "model-b@old".into(),
            reason_refs: set(&["privacy-incompatible", "qualification-expired"]),
        }],
        selected_candidate_ref: Some("model-a@2026-09".into()),
        selected_model_version: Some(profile.model_version.clone()),
        qualification_profile_refs: set(&["qualification-profile-a"]),
        evaluation_version_refs: set(&["eval-v8"]),
        constraint_refs: request.privacy_constraint_refs.clone(),
        optimization_policy: policy("router-policy-a"),
        fallback_behavior_ref: "do-not-silently-lower-quality".into(),
    };

    assert_eq!(receipt.selected_model_version.as_deref(), Some("2026-09"));
    assert_eq!(receipt.rejected_candidates.len(), 1);
    assert!(
        receipt.rejected_candidates[0]
            .reason_refs
            .contains("privacy-incompatible")
    );
}

#[test]
fn s04_fidelity_verdict_keeps_material_findings_separate_from_success() {
    let finding = FidelityFinding {
        kind: FidelityFindingKind::Omission,
        subject_ref: "negated-constraint".into(),
        evidence_refs: set(&["source-comparison"]),
    };

    assert_eq!(finding.kind, FidelityFindingKind::Omission);
    assert!(!finding.evidence_refs.is_empty());
    assert_ne!(
        ContextFidelityVerdict::Block,
        ContextFidelityVerdict::Sufficient
    );
}
