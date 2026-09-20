use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy(name: &str) -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: name.into(),
        version: "qualified-1".into(),
        qualification_evidence_refs: set(&["heldout-evidence"]),
    }
}

fn structured_candidate() -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Structured(StructuredFactProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: "fact-item-a".into(),
            kind: ContextItemKind::StructuredFact,
        },
        fact_ref: "profile:target-account".into(),
        fact_version: 11,
        content_digest: "sha256:fact-v11".into(),
        provenance_refs: set(&["exact-source-v7:span-account"]),
        boundary: ContextBoundaryLabels {
            trust_label_ref: "trust:verified-user-fact".into(),
            data_use_label_ref: "use:private".into(),
            lifecycle_label_ref: "current:correction-12".into(),
        },
        validity_dependency_refs: set(&["profile@11", "correction@12"]),
    })
}

fn delivery() -> ContextDeliveryBoundary {
    ContextDeliveryBoundary {
        item_ref: "fact-item-a".into(),
        information_classes: BTreeSet::from([ContextInformationClass::Evidence]),
        taint_label_ref: "taint:verified-structured".into(),
        sensitivity_label_ref: "sensitivity:private".into(),
        principal_scope_ref: Some("principal-a".into()),
        authority_context_evidence_ref: None,
        expiry_ref: Some("correction@12".into()),
        label_transition_evidence: Vec::new(),
    }
}

fn protected() -> ProtectedEvidenceRef {
    ProtectedEvidenceRef {
        field_ref: "target-account".into(),
        exact_value_digest: "sha256:account-value".into(),
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::StructuredFact {
            fact_ref: "profile:target-account".into(),
            fact_version: 11,
            fact_digest: "sha256:fact-v11".into(),
        }]),
    }
}

fn input() -> ContextCompileInput {
    ContextCompileInput {
        compilation_id: "structured-compilation-a".into(),
        version: 1,
        tenant_ref: "tenant-a".into(),
        principal_context_ref: "principal-a".into(),
        purpose_ref: "purpose-a".into(),
        candidate_set_revision_ref: "candidate-set@13".into(),
        candidates: vec![structured_candidate()],
        delivery_boundaries: vec![delivery()],
        protected_evidence: vec![protected()],
        validity_frontier: ContextValidityFrontier {
            goal: VersionedRef {
                reference: "goal-a".into(),
                version: 4,
            },
            work: VersionedRef {
                reference: "work-a".into(),
                version: 9,
            },
            correction_frontier_ref: "correction@12".into(),
            policy_authority_epoch_ref: "authority@6".into(),
            dependency_refs: set(&["profile@11", "correction@12"]),
        },
        receiver_profile: ReceiverContextProfileRef {
            receiver_ref: "receiver-a".into(),
            receiver_version: "2026-09".into(),
            context_profile_ref: "context-profile@7".into(),
            qualification_evidence_refs: set(&["context-heldout@7"]),
        },
        unresolved_gaps: BTreeSet::new(),
        excluded_but_needed_evidence_refs: BTreeSet::new(),
        effect_refs: BTreeSet::new(),
        obligation_refs: BTreeSet::new(),
        token_budget_requested: Some(4_000),
        token_budget_used: Some(400),
        selector_policy: policy("selector-a"),
        resource_budget_ref: Some("resource-envelope@2".into()),
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

struct SelectProtectedFact;

impl ContextSelector for SelectProtectedFact {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        Ok(bound(
            request,
            ContextSelectionReceipt {
                receipt_id: "receipt-select".into(),
                candidate_set_revision_ref: request.candidate_set_revision_ref.clone(),
                selector_policy: request.selector_policy.clone(),
                dispositions: vec![ContextSelectionDisposition::Selected {
                    item_ref: "fact-item-a".into(),
                    policy_evidence_refs: set(&["protected-fact-required"]),
                }],
            },
        ))
    }
}

#[test]
fn protected_structured_fact_survives_compilation_with_exact_binding() {
    let compiled = ContextCompiler::new(SelectProtectedFact)
        .compile(input())
        .expect("protected structured fact compilation");
    assert_eq!(
        compiled.selected_item_refs(),
        BTreeSet::from(["fact-item-a"])
    );
    assert!(matches!(
        &compiled.candidates[0],
        ContextCandidateDescriptor::Structured(fact)
            if fact.fact_ref == "profile:target-account"
                && fact.fact_version == 11
                && fact.content_digest == "sha256:fact-v11"
    ));
}

struct DropProtectedFact;

impl ContextSelector for DropProtectedFact {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        Ok(bound(
            request,
            ContextSelectionReceipt {
                receipt_id: "receipt-drop".into(),
                candidate_set_revision_ref: request.candidate_set_revision_ref.clone(),
                selector_policy: request.selector_policy.clone(),
                dispositions: vec![ContextSelectionDisposition::Excluded {
                    item_ref: "fact-item-a".into(),
                    reason_refs: set(&["budget-pressure"]),
                    policy_evidence_refs: set(&["selector-output"]),
                }],
            },
        ))
    }
}

#[test]
fn selector_cannot_drop_protected_structured_fact_for_budget() {
    assert_eq!(
        ContextCompiler::new(DropProtectedFact).compile(input()),
        Err(ContextCompileError::ProtectedEvidenceExcluded {
            field_ref: "target-account".into(),
            item_ref: "fact-item-a".into(),
        })
    );
}

#[test]
fn stale_structured_fact_locator_fails_before_adaptive_selection() {
    let mut stale = input();
    stale.protected_evidence[0].proving_evidence =
        BTreeSet::from([ProtectedEvidenceLocator::StructuredFact {
            fact_ref: "profile:target-account".into(),
            fact_version: 10,
            fact_digest: "sha256:fact-v11".into(),
        }]);

    assert_eq!(
        ContextCompiler::new(SelectProtectedFact).compile(stale),
        Err(ContextCompileError::Contract(
            CognitionContractError::ProtectedEvidenceLocatorMismatch
        ))
    );
}
