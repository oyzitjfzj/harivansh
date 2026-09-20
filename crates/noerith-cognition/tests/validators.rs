use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn versioned(reference: &str, version: u64) -> VersionedRef {
    VersionedRef {
        reference: reference.to_owned(),
        version,
    }
}

fn task(name: &str, aggregates: &[&str]) -> TaskNode {
    TaskNode {
        task_ref: name.into(),
        goal: versioned("goal-a", 1),
        work: versioned("work-a", 1),
        semantic_operation_ref: format!("operation-{name}"),
        required_capability_refs: BTreeSet::new(),
        required_evidence_refs: BTreeSet::new(),
        state_class_ref: "S2".into(),
        protected_aggregate_refs: set(aggregates),
        resource_envelope: ResourceEnvelope {
            resource_refs: BTreeSet::new(),
            placement_constraints: BTreeSet::new(),
            externally_calibrated_budget_ref: None,
        },
        timing: None,
        waiting_condition_ref: None,
        wake_condition_ref: None,
        permission_requirement_ref: None,
        blocker_refs: BTreeSet::new(),
        completion_test_ref: "completion-evidence".into(),
        trajectory_checkpoint_ref: None,
        interrupt_scope_ref: None,
        cancellation_scope_ref: None,
    }
}

#[test]
fn s04_validator_detects_dependency_cycle_but_does_not_treat_conflict_edge_as_ordering() {
    let cyclic = TaskGraph {
        graph_id: "graph-cycle".into(),
        revision: 1,
        nodes: vec![task("a", &[]), task("b", &[])],
        edges: vec![
            TaskEdge {
                from_task_ref: "a".into(),
                to_task_ref: "b".into(),
                kind: TaskEdgeKind::Dependency,
                evidence_refs: set(&["dependency-proof"]),
            },
            TaskEdge {
                from_task_ref: "b".into(),
                to_task_ref: "a".into(),
                kind: TaskEdgeKind::Ordering,
                evidence_refs: set(&["ordering-proof"]),
            },
        ],
        promise_refs: BTreeSet::new(),
        recurrence_revision_refs: BTreeSet::new(),
    };
    assert_eq!(
        validate_task_graph(&cyclic),
        Err(CognitionContractError::DependencyCycle)
    );

    let conflict_only = TaskGraph {
        edges: vec![TaskEdge {
            from_task_ref: "a".into(),
            to_task_ref: "b".into(),
            kind: TaskEdgeKind::Conflict,
            evidence_refs: set(&["same-account-state"]),
        }],
        ..cyclic
    };
    assert_eq!(validate_task_graph(&conflict_only), Ok(()));
}

#[test]
fn s04_validator_reports_protected_aggregate_conflict_without_inventing_priority() {
    let graph = TaskGraph {
        graph_id: "graph-conflict".into(),
        revision: 1,
        nodes: vec![
            task("a", &["account-x"]),
            task("b", &["account-x"]),
            task("c", &["file-y"]),
        ],
        edges: Vec::new(),
        promise_refs: BTreeSet::new(),
        recurrence_revision_refs: BTreeSet::new(),
    };
    assert_eq!(
        protected_conflict_pairs(&graph),
        BTreeSet::from([("a".to_owned(), "b".to_owned())])
    );
}

fn profile() -> ModelQualificationProfile {
    ModelQualificationProfile {
        model_ref: "model-a".into(),
        provider_ref: "provider-a".into(),
        model_version: "m-7".into(),
        adapter_version: "a-4".into(),
        regime_evidence_refs: set(&["regime-eval"]),
        domain_evidence_refs: set(&["domain-eval"]),
        heldout_distribution_refs: set(&["heldout-v2"]),
        structured_output_evidence_refs: set(&["structured-eval"]),
        tool_reliability_evidence_refs: set(&["tool-eval"]),
        modality_refs: set(&["text"]),
        context_behavior_evidence_refs: set(&["context-eval"]),
        privacy_policy_refs: set(&["privacy-policy"]),
        data_residency_refs: set(&["residency"]),
        retention_policy_refs: set(&["retention"]),
        provenance_ref: "provenance".into(),
        health_ref: "health-current".into(),
        calibration_validity_ref: "calibration-current".into(),
    }
}

fn request() -> ModelRequest {
    ModelRequest {
        request_id: "request-a".into(),
        regime_refs: set(&["coding"]),
        domain_refs: set(&["rust"]),
        quality_floor_ref: "quality-floor-a".into(),
        privacy_constraint_refs: set(&["private-only"]),
        data_constraint_refs: set(&["no-training"]),
        required_modalities: set(&["text"]),
        structured_output_requirement_ref: Some("typed-json".into()),
        tool_requirement_refs: set(&["compiler"]),
        context_requirement_ref: "context-window-a".into(),
        deadline_resource_envelope_ref: None,
        verification_plan_ref: "verify-a".into(),
    }
}

fn proof() -> ModelEligibilityProof {
    ModelEligibilityProof {
        qualification_profile_ref: "profile-a".into(),
        current_model_version: "m-7".into(),
        current_adapter_version: "a-4".into(),
        quality_floor_ref: "quality-floor-a".into(),
        satisfied_privacy_constraint_refs: set(&["private-only"]),
        satisfied_data_constraint_refs: set(&["no-training"]),
        supported_modality_refs: set(&["text"]),
        supported_tool_requirement_refs: set(&["compiler"]),
        context_requirement_ref: "context-window-a".into(),
        structured_output_requirement_ref: Some("typed-json".into()),
        evidence_refs: set(&["eligibility-evidence"]),
    }
}

#[test]
fn s04_model_eligibility_rejects_version_drift_and_quality_or_privacy_shortfall() {
    let request = request();
    let profile = profile();
    assert_eq!(
        validate_model_eligibility(&request, &profile, &proof()),
        Ok(())
    );

    let mut stale = proof();
    stale.current_model_version = "m-8".into();
    assert_eq!(
        validate_model_eligibility(&request, &profile, &stale),
        Err(CognitionContractError::ModelVersionDrift)
    );

    let mut weaker = proof();
    weaker.quality_floor_ref = "lower-floor".into();
    assert_eq!(
        validate_model_eligibility(&request, &profile, &weaker),
        Err(CognitionContractError::QualityFloorUnproved)
    );

    let mut privacy_gap = proof();
    privacy_gap.satisfied_privacy_constraint_refs.clear();
    assert_eq!(
        validate_model_eligibility(&request, &profile, &privacy_gap),
        Err(CognitionContractError::PrivacyConstraintUnproved)
    );
}
