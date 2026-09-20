use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy() -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: "qualified-policy".into(),
        version: "2026-09".into(),
        qualification_evidence_refs: set(&["heldout-policy-evidence"]),
    }
}

fn labels() -> ContextBoundaryLabels {
    ContextBoundaryLabels {
        trust_label_ref: "trust-source".into(),
        data_use_label_ref: "use-private".into(),
        lifecycle_label_ref: "current@8".into(),
    }
}

fn exact(item_ref: &str, validity: &[&str]) -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Exact(ExactSourceProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: item_ref.into(),
            kind: ContextItemKind::ExactSourceSpan,
        },
        source_ref: format!("source-{item_ref}"),
        source_version: 8,
        span_ref: format!("span-{item_ref}"),
        content_digest: format!("digest-{item_ref}"),
        lineage_ref: format!("lineage-{item_ref}"),
        boundary: labels(),
        validity_dependency_refs: set(validity),
    })
}

fn derived(item_ref: &str, parents: &[&str], validity: &[&str]) -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Derived(DerivedContextProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: item_ref.into(),
            kind: ContextItemKind::DerivedView,
        },
        content_digest: format!("digest-{item_ref}"),
        parent_item_refs: set(parents),
        provenance_ref: format!("provenance-{item_ref}"),
        transform_policy: policy(),
        boundary: labels(),
        validity_dependency_refs: set(validity),
    })
}

#[test]
fn derived_context_cannot_launder_parent_invalidation_dependency() {
    let candidates = vec![
        exact("source-a", &["source@8", "correction@12"]),
        derived("summary-a", &["source-a"], &["source@8"]),
    ];
    assert_eq!(
        validate_context_candidate_set(&candidates, "tenant-a", "purpose-a"),
        Err(CognitionContractError::ContextDerivedValidityDependencyLost)
    );
}

#[test]
fn derived_context_may_add_dependencies_but_must_preserve_all_parent_dependencies() {
    let candidates = vec![
        exact("source-a", &["source@8", "correction@12"]),
        exact("source-b", &["source-b@2"]),
        derived(
            "summary-a",
            &["source-a", "source-b"],
            &["source@8", "correction@12", "source-b@2", "transform@3"],
        ),
    ];
    assert!(validate_context_candidate_set(&candidates, "tenant-a", "purpose-a").is_ok());
}

fn node(task_ref: &str) -> TaskNode {
    TaskNode {
        task_ref: task_ref.into(),
        goal: VersionedRef {
            reference: "goal-a".into(),
            version: 3,
        },
        work: VersionedRef {
            reference: "work-a".into(),
            version: 4,
        },
        semantic_operation_ref: format!("operation-{task_ref}"),
        required_capability_refs: BTreeSet::new(),
        required_evidence_refs: BTreeSet::new(),
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
        permission_requirement_ref: None,
        blocker_refs: BTreeSet::new(),
        completion_test_ref: "completion-proof".into(),
        trajectory_checkpoint_ref: None,
        interrupt_scope_ref: None,
        cancellation_scope_ref: None,
    }
}

fn graph(edges: Vec<TaskEdge>) -> TaskGraph {
    TaskGraph {
        graph_id: "graph-a".into(),
        revision: 7,
        nodes: vec![node("a"), node("b")],
        edges,
        promise_refs: BTreeSet::new(),
        recurrence_revision_refs: BTreeSet::new(),
    }
}

#[test]
fn task_graph_rejects_edge_without_evidence() {
    let value = graph(vec![TaskEdge {
        from_task_ref: "a".into(),
        to_task_ref: "b".into(),
        kind: TaskEdgeKind::Dependency,
        evidence_refs: BTreeSet::new(),
    }]);
    assert_eq!(
        validate_task_graph(&value),
        Err(CognitionContractError::TaskEdgeEvidenceMissing)
    );
}

#[test]
fn task_graph_rejects_duplicate_edge_identity_even_with_different_evidence_bags() {
    let value = graph(vec![
        TaskEdge {
            from_task_ref: "a".into(),
            to_task_ref: "b".into(),
            kind: TaskEdgeKind::Dependency,
            evidence_refs: set(&["dependency-proof-a"]),
        },
        TaskEdge {
            from_task_ref: "a".into(),
            to_task_ref: "b".into(),
            kind: TaskEdgeKind::Dependency,
            evidence_refs: set(&["dependency-proof-b"]),
        },
    ]);
    assert_eq!(
        validate_task_graph(&value),
        Err(CognitionContractError::DuplicateTaskEdge)
    );
}

#[test]
fn task_graph_rejects_empty_core_node_or_optional_reference() {
    let mut bad_core = graph(Vec::new());
    bad_core.nodes[0].completion_test_ref.clear();
    assert_eq!(
        validate_task_graph(&bad_core),
        Err(CognitionContractError::TaskNodeInvalid)
    );

    let mut bad_optional = graph(Vec::new());
    bad_optional.nodes[0].permission_requirement_ref = Some("  ".into());
    assert_eq!(
        validate_task_graph(&bad_optional),
        Err(CognitionContractError::TaskNodeInvalid)
    );
}

fn model_request() -> ModelRequest {
    ModelRequest {
        request_id: "request-a".into(),
        regime_refs: set(&["coding"]),
        domain_refs: set(&["rust"]),
        quality_floor_ref: "quality-high".into(),
        privacy_constraint_refs: set(&["private-only"]),
        data_constraint_refs: set(&["no-training"]),
        required_modalities: set(&["text"]),
        structured_output_requirement_ref: Some("typed-output".into()),
        tool_requirement_refs: set(&["compiler"]),
        context_requirement_ref: "context-profile-a".into(),
        deadline_resource_envelope_ref: None,
        verification_plan_ref: "verification-plan-a".into(),
    }
}

fn model_profile() -> ModelQualificationProfile {
    ModelQualificationProfile {
        model_ref: "model-a".into(),
        provider_ref: "provider-a".into(),
        model_version: "m7".into(),
        adapter_version: "a3".into(),
        regime_evidence_refs: set(&["regime-evidence"]),
        domain_evidence_refs: set(&["domain-evidence"]),
        heldout_distribution_refs: set(&["heldout-evidence"]),
        structured_output_evidence_refs: set(&["structured-evidence"]),
        tool_reliability_evidence_refs: set(&["tool-evidence"]),
        modality_refs: set(&["text"]),
        context_behavior_evidence_refs: set(&["context-evidence"]),
        privacy_policy_refs: set(&["privacy-evidence"]),
        data_residency_refs: set(&["residency-evidence"]),
        retention_policy_refs: set(&["retention-evidence"]),
        provenance_ref: "model-provenance".into(),
        health_ref: "health-current".into(),
        calibration_validity_ref: "calibration-current".into(),
    }
}

fn eligibility_proof() -> ModelEligibilityProof {
    ModelEligibilityProof {
        qualification_profile_ref: "qualification-profile-a".into(),
        current_model_version: "m7".into(),
        current_adapter_version: "a3".into(),
        quality_floor_ref: "quality-high".into(),
        satisfied_privacy_constraint_refs: set(&["private-only"]),
        satisfied_data_constraint_refs: set(&["no-training"]),
        supported_modality_refs: set(&["text"]),
        supported_tool_requirement_refs: set(&["compiler"]),
        context_requirement_ref: "context-profile-a".into(),
        structured_output_requirement_ref: Some("typed-output".into()),
        evidence_refs: set(&["eligibility-evidence"]),
    }
}

#[test]
fn model_proof_cannot_claim_modality_not_declared_by_profile() {
    let mut proof = eligibility_proof();
    proof.supported_modality_refs.insert("audio".into());
    assert_eq!(
        validate_model_eligibility(&model_request(), &model_profile(), &proof),
        Err(CognitionContractError::ModelProofExceedsProfile)
    );
}

#[test]
fn model_request_needing_tools_or_structured_output_requires_qualification_surfaces() {
    let mut profile = model_profile();
    profile.tool_reliability_evidence_refs.clear();
    assert_eq!(
        validate_model_eligibility(&model_request(), &profile, &eligibility_proof()),
        Err(CognitionContractError::ModelQualificationSurfaceMissing)
    );

    let mut profile = model_profile();
    profile.structured_output_evidence_refs.clear();
    assert_eq!(
        validate_model_eligibility(&model_request(), &profile, &eligibility_proof()),
        Err(CognitionContractError::ModelQualificationSurfaceMissing)
    );
}

#[test]
fn model_eligibility_requires_clean_evidence_not_nonempty_whitespace() {
    let mut proof = eligibility_proof();
    proof.evidence_refs = set(&["   "]);
    assert_eq!(
        validate_model_eligibility(&model_request(), &model_profile(), &proof),
        Err(CognitionContractError::QualificationEvidenceMissing)
    );
}

#[test]
fn fully_bound_model_eligibility_remains_accepted_without_ranking_formula() {
    assert!(
        validate_model_eligibility(&model_request(), &model_profile(), &eligibility_proof())
            .is_ok()
    );
}
