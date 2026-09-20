use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy(name: &str) -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: name.to_owned(),
        version: "qualified-1".into(),
        qualification_evidence_refs: set(&["heldout-evidence"]),
    }
}

fn identity(item_ref: &str, kind: ContextItemKind) -> ContextItemIdentity {
    ContextItemIdentity {
        tenant_ref: "tenant-a".into(),
        purpose_ref: "purpose-a".into(),
        item_ref: item_ref.into(),
        kind,
    }
}

fn exact_candidate() -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Exact(ExactSourceProjection {
        identity: identity("exact-a", ContextItemKind::ExactSourceSpan),
        source_ref: "source-a".into(),
        source_version: 7,
        span_ref: "span-a".into(),
        content_digest: "content-a".into(),
        lineage_ref: "lineage-a".into(),
        boundary: ContextBoundaryLabels {
            trust_label_ref: "trust-user-source".into(),
            data_use_label_ref: "use-private".into(),
            lifecycle_label_ref: "current".into(),
        },
        validity_dependency_refs: set(&["goal-a@3"]),
    })
}

fn derived_candidate() -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Derived(DerivedContextProjection {
        identity: identity("summary-a", ContextItemKind::DerivedView),
        content_digest: "summary-content-a".into(),
        parent_item_refs: set(&["exact-a"]),
        provenance_ref: "summary-provenance-a".into(),
        transform_policy: policy("summary-transform"),
        boundary: ContextBoundaryLabels {
            trust_label_ref: "trust-derived".into(),
            data_use_label_ref: "use-private".into(),
            lifecycle_label_ref: "current".into(),
        },
        validity_dependency_refs: set(&["goal-a@3"]),
    })
}

fn delivery(item_ref: &str, class: ContextInformationClass) -> ContextDeliveryBoundary {
    ContextDeliveryBoundary {
        item_ref: item_ref.into(),
        information_classes: BTreeSet::from([class]),
        taint_label_ref: "taint-reviewed".into(),
        sensitivity_label_ref: "sensitivity-private".into(),
        principal_scope_ref: Some("principal-a".into()),
        authority_context_evidence_ref: None,
        expiry_ref: Some("correction@5".into()),
        label_transition_evidence: Vec::new(),
    }
}

fn transition(
    parent: &ContextCandidateDescriptor,
    parent_boundary: &ContextDeliveryBoundary,
    child: &ContextCandidateDescriptor,
    child_boundary: &ContextDeliveryBoundary,
) -> ContextLabelTransitionEvidence {
    ContextLabelTransitionEvidence {
        parent_item_ref: parent.identity().item_ref.clone(),
        child_item_ref: child.identity().item_ref.clone(),
        parent_labels: ContextDeliveryLabelSnapshot::capture(parent, parent_boundary).unwrap(),
        child_labels: ContextDeliveryLabelSnapshot::capture(child, child_boundary).unwrap(),
        transition_policy: policy("delivery-label-transition"),
        evidence_refs: set(&["summary-label-flow-proof"]),
    }
}

fn protected_evidence() -> ProtectedEvidenceRef {
    ProtectedEvidenceRef {
        field_ref: "target-account".into(),
        exact_value_digest: "target-value-digest".into(),
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::SourceSpan {
            source_ref: "source-a".into(),
            source_version: 7,
            span_ref: "span-a".into(),
            content_digest: "content-a".into(),
        }]),
    }
}

fn input() -> ContextCompileInput {
    let exact = exact_candidate();
    let derived = derived_candidate();
    let exact_delivery = delivery("exact-a", ContextInformationClass::Evidence);
    let mut derived_delivery = delivery("summary-a", ContextInformationClass::ContentData);
    derived_delivery.label_transition_evidence = vec![transition(
        &exact,
        &exact_delivery,
        &derived,
        &derived_delivery,
    )];

    ContextCompileInput {
        compilation_id: "compilation-a".into(),
        version: 1,
        tenant_ref: "tenant-a".into(),
        principal_context_ref: "principal-a".into(),
        purpose_ref: "purpose-a".into(),
        candidate_set_revision_ref: "candidate-set@4".into(),
        candidates: vec![exact, derived],
        delivery_boundaries: vec![exact_delivery, derived_delivery],
        protected_evidence: vec![protected_evidence()],
        validity_frontier: ContextValidityFrontier {
            goal: VersionedRef {
                reference: "goal-a".into(),
                version: 3,
            },
            work: VersionedRef {
                reference: "work-a".into(),
                version: 8,
            },
            correction_frontier_ref: "correction@5".into(),
            policy_authority_epoch_ref: "authority@9".into(),
            dependency_refs: set(&["goal-a@3", "work-a@8"]),
        },
        receiver_profile: ReceiverContextProfileRef {
            receiver_ref: "model-a".into(),
            receiver_version: "model-v7".into(),
            context_profile_ref: "context-profile-a".into(),
            qualification_evidence_refs: set(&["position-eval", "length-eval"]),
        },
        unresolved_gaps: set(&["fresh-balance-needed"]),
        excluded_but_needed_evidence_refs: set(&["balance-source-not-loaded"]),
        effect_refs: set(&["effect-a"]),
        obligation_refs: set(&["obligation-a"]),
        token_budget_requested: Some(8_000),
        token_budget_used: Some(2_000),
        selector_policy: policy("context-selector"),
        resource_budget_ref: Some("resource-profile-a".into()),
    }
}

fn good_receipt(request: &ContextSelectionRequest) -> ContextSelectionReceipt {
    ContextSelectionReceipt {
        receipt_id: "selection-receipt-a".into(),
        candidate_set_revision_ref: request.candidate_set_revision_ref.clone(),
        selector_policy: request.selector_policy.clone(),
        dispositions: vec![
            ContextSelectionDisposition::Selected {
                item_ref: "exact-a".into(),
                policy_evidence_refs: set(&["protected-required"]),
            },
            ContextSelectionDisposition::Excluded {
                item_ref: "summary-a".into(),
                reason_refs: set(&["not-needed-for-current-purpose"]),
                policy_evidence_refs: set(&["selection-evidence"]),
            },
        ],
    }
}

fn bound(
    request: &ContextSelectionRequest,
    receipt: ContextSelectionReceipt,
) -> BoundContextSelectionReceipt {
    BoundContextSelectionReceipt {
        binding: request.binding(),
        receipt,
    }
}

struct GroundedSelector;

impl ContextSelector for GroundedSelector {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        assert_eq!(request.tenant_ref, "tenant-a");
        assert_eq!(request.principal_context_ref, "principal-a");
        assert_eq!(request.candidates.len(), 2);
        assert_eq!(request.delivery_boundaries.len(), 2);
        assert_eq!(request.protected_evidence.len(), 1);
        assert_eq!(request.validity_frontier.goal.version, 3);
        assert!(
            request
                .receiver_profile
                .qualification_evidence_refs
                .contains("position-eval")
        );
        Ok(bound(request, good_receipt(request)))
    }
}

#[test]
fn context_compiler_keeps_full_lineage_and_total_selection_receipt() {
    let compiled = ContextCompiler::new(GroundedSelector)
        .compile(input())
        .expect("context compilation");

    assert_eq!(compiled.candidates.len(), 2);
    assert_eq!(compiled.delivery_boundaries.len(), 2);
    assert_eq!(compiled.selected_item_refs(), BTreeSet::from(["exact-a"]));
    assert_eq!(compiled.excluded_item_refs(), BTreeSet::from(["summary-a"]));
    assert!(compiled.unresolved_gaps.contains("fresh-balance-needed"));
    assert!(
        compiled
            .excluded_but_needed_evidence_refs
            .contains("balance-source-not-loaded")
    );
    let derived = compiled
        .candidates
        .iter()
        .find_map(|candidate| match candidate {
            ContextCandidateDescriptor::Derived(item) => Some(item),
            _ => None,
        })
        .expect("derived candidate retained for reversible lineage");
    assert!(derived.parent_item_refs.contains("exact-a"));
}

struct ExcludesProtected;

impl ContextSelector for ExcludesProtected {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        Ok(bound(
            request,
            ContextSelectionReceipt {
                receipt_id: "bad-protected-drop".into(),
                candidate_set_revision_ref: request.candidate_set_revision_ref.clone(),
                selector_policy: request.selector_policy.clone(),
                dispositions: vec![
                    ContextSelectionDisposition::Excluded {
                        item_ref: "exact-a".into(),
                        reason_refs: set(&["save-budget"]),
                        policy_evidence_refs: set(&["budget-pressure"]),
                    },
                    ContextSelectionDisposition::Selected {
                        item_ref: "summary-a".into(),
                        policy_evidence_refs: set(&["smaller-view"]),
                    },
                ],
            },
        ))
    }
}

#[test]
fn context_compiler_rejects_budget_driven_protected_source_drop() {
    assert_eq!(
        ContextCompiler::new(ExcludesProtected).compile(input()),
        Err(ContextCompileError::ProtectedEvidenceExcluded {
            field_ref: "target-account".into(),
            item_ref: "exact-a".into(),
        })
    );
}

struct ReplayedBinding;

impl ContextSelector for ReplayedBinding {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        let mut result = bound(request, good_receipt(request));
        result.binding.principal_context_ref = "principal-stale".into();
        result.binding.receiver_profile.receiver_version = "model-v6".into();
        Ok(result)
    }
}

#[test]
fn context_compiler_rejects_receipt_replayed_across_principal_or_receiver() {
    assert_eq!(
        ContextCompiler::new(ReplayedBinding).compile(input()),
        Err(ContextCompileError::SelectionBindingMismatch)
    );
}

struct WrongCandidateRevision;

impl ContextSelector for WrongCandidateRevision {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        let mut receipt = good_receipt(request);
        receipt.candidate_set_revision_ref = "candidate-set@old".into();
        Ok(bound(request, receipt))
    }
}

#[test]
fn context_compiler_rejects_selector_receipt_revision_substitution() {
    assert_eq!(
        ContextCompiler::new(WrongCandidateRevision).compile(input()),
        Err(ContextCompileError::CandidateSetRevisionMismatch)
    );
}

struct WrongSelectorPolicy;

impl ContextSelector for WrongSelectorPolicy {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        let mut receipt = good_receipt(request);
        receipt.selector_policy = policy("different-selector");
        Ok(bound(request, receipt))
    }
}

#[test]
fn context_compiler_rejects_selector_policy_substitution() {
    assert_eq!(
        ContextCompiler::new(WrongSelectorPolicy).compile(input()),
        Err(ContextCompileError::SelectorPolicyMismatch)
    );
}

struct PartialReceipt;

impl ContextSelector for PartialReceipt {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        Ok(bound(
            request,
            ContextSelectionReceipt {
                receipt_id: "partial".into(),
                candidate_set_revision_ref: request.candidate_set_revision_ref.clone(),
                selector_policy: request.selector_policy.clone(),
                dispositions: vec![ContextSelectionDisposition::Selected {
                    item_ref: "exact-a".into(),
                    policy_evidence_refs: set(&["selected"]),
                }],
            },
        ))
    }
}

#[test]
fn context_compiler_rejects_partial_selection_receipt() {
    assert_eq!(
        ContextCompiler::new(PartialReceipt).compile(input()),
        Err(ContextCompileError::Contract(
            CognitionContractError::ContextSelectionIncomplete
        ))
    );
}

struct MustNotRun;

impl ContextSelector for MustNotRun {
    fn propose_selection(
        &self,
        _request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        panic!("selector must not run when deterministic validation fails")
    }
}

#[test]
fn context_compiler_rejects_broken_lineage_before_adaptive_selection() {
    let mut broken = input();
    let ContextCandidateDescriptor::Derived(derived) = &mut broken.candidates[1] else {
        panic!("expected derived candidate")
    };
    derived.parent_item_refs = set(&["missing-parent"]);

    assert_eq!(
        ContextCompiler::new(MustNotRun).compile(broken),
        Err(ContextCompileError::Contract(
            CognitionContractError::ContextDerivedParentMissing
        ))
    );
}

#[test]
fn independent_goal_patch_does_not_invalidate_existing_context_by_definition() {
    assert!(!patch_invalidates_existing_context(
        GoalPatchRelation::Independent
    ));
    assert!(patch_invalidates_existing_context(
        GoalPatchRelation::Correct
    ));
}
