use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy() -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: "context-selector-a".into(),
        version: "candidate-1".into(),
        qualification_evidence_refs: set(&["heldout-context-eval"]),
    }
}

fn boundary() -> ContextBoundaryLabels {
    ContextBoundaryLabels {
        trust_label_ref: "untrusted-external-data".into(),
        data_use_label_ref: "private-user-data".into(),
        lifecycle_label_ref: "current@frontier-7".into(),
    }
}

#[test]
fn exact_structured_and_derived_context_items_are_distinct_semantic_variants() {
    let exact = ContextCandidateDescriptor::Exact(ExactSourceProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: "item-source-a-2-span-4".into(),
            kind: ContextItemKind::ExactSourceSpan,
        },
        source_ref: "source-a".into(),
        source_version: 2,
        span_ref: "span-4".into(),
        content_digest: "sha256:exact-span".into(),
        lineage_ref: "lineage-a".into(),
        boundary: boundary(),
        validity_dependency_refs: set(&["source-a@2", "correction-frontier@7"]),
    });
    let structured = ContextCandidateDescriptor::Structured(StructuredFactProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: "decision-a".into(),
            kind: ContextItemKind::StructuredFact,
        },
        fact_ref: "decision:target-account".into(),
        fact_version: 3,
        content_digest: "sha256:structured-fact".into(),
        provenance_refs: set(&["item-source-a-2-span-4"]),
        boundary: boundary(),
        validity_dependency_refs: set(&["source-a@2", "correction-frontier@7"]),
    });
    let derived = ContextCandidateDescriptor::Derived(DerivedContextProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: "summary-a".into(),
            kind: ContextItemKind::DerivedView,
        },
        content_digest: "sha256:summary".into(),
        parent_item_refs: set(&["item-source-a-2-span-4", "decision-a"]),
        provenance_ref: "summary-provenance-a".into(),
        transform_policy: policy(),
        boundary: boundary(),
        validity_dependency_refs: set(&["source-a@2", "correction-frontier@7"]),
    });

    assert_ne!(exact.identity().kind, structured.identity().kind);
    assert_ne!(structured.identity().kind, derived.identity().kind);
    assert_ne!(exact.content_digest(), structured.content_digest());
    assert_ne!(structured.content_digest(), derived.content_digest());
}

#[test]
fn protected_evidence_can_bind_the_exact_source_span_not_only_the_source_name() {
    let pin = ProtectedEvidenceRef {
        field_ref: "target-account".into(),
        exact_value_digest: "sha256:account-42".into(),
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::SourceSpan {
            source_ref: "user-message-a".into(),
            source_version: 3,
            span_ref: "span-account".into(),
            content_digest: "sha256:span-account".into(),
        }]),
    };

    let unrelated = ProtectedEvidenceLocator::SourceSpan {
        source_ref: "user-message-a".into(),
        source_version: 3,
        span_ref: "span-unrelated".into(),
        content_digest: "sha256:span-unrelated".into(),
    };
    assert!(!pin.proving_evidence.contains(&unrelated));
}

#[test]
fn protected_structured_fact_evidence_binds_ref_version_and_digest() {
    let pin = ProtectedEvidenceRef {
        field_ref: "delivery-address".into(),
        exact_value_digest: "sha256:address-value".into(),
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::StructuredFact {
            fact_ref: "profile:delivery-address".into(),
            fact_version: 9,
            fact_digest: "sha256:fact-v9".into(),
        }]),
    };
    assert!(
        pin.proving_evidence
            .contains(&ProtectedEvidenceLocator::StructuredFact {
                fact_ref: "profile:delivery-address".into(),
                fact_version: 9,
                fact_digest: "sha256:fact-v9".into(),
            })
    );
    assert!(
        !pin.proving_evidence
            .contains(&ProtectedEvidenceLocator::StructuredFact {
                fact_ref: "profile:delivery-address".into(),
                fact_version: 8,
                fact_digest: "sha256:fact-v9".into(),
            })
    );
}

#[test]
fn context_validity_frontier_and_receiver_profile_are_explicit() {
    let frontier = ContextValidityFrontier {
        goal: VersionedRef {
            reference: "goal-a".into(),
            version: 8,
        },
        work: VersionedRef {
            reference: "work-a".into(),
            version: 13,
        },
        correction_frontier_ref: "correction-frontier@21".into(),
        policy_authority_epoch_ref: "authority-epoch@5".into(),
        dependency_refs: set(&["source-a@3", "memory-a@9"]),
    };
    let receiver = ReceiverContextProfileRef {
        receiver_ref: "model-a".into(),
        receiver_version: "2026-09-10".into(),
        context_profile_ref: "position-load-eval@4".into(),
        qualification_evidence_refs: set(&["long-context-heldout@4"]),
    };

    assert_eq!(frontier.goal.version, 8);
    assert_eq!(receiver.receiver_ref, "model-a");
    assert!(!receiver.qualification_evidence_refs.is_empty());
}

#[test]
fn selection_disposition_cannot_be_selected_and_excluded_at_the_same_time() {
    let selected = ContextSelectionDisposition::Selected {
        item_ref: "item-a".into(),
        policy_evidence_refs: set(&["selection-receipt-a"]),
    };
    let excluded = ContextSelectionDisposition::Excluded {
        item_ref: "item-b".into(),
        reason_refs: set(&["not-needed-for-current-purpose"]),
        policy_evidence_refs: set(&["selection-receipt-a"]),
    };
    let receipt = ContextSelectionReceipt {
        receipt_id: "receipt-a".into(),
        candidate_set_revision_ref: "candidate-set@7".into(),
        selector_policy: policy(),
        dispositions: vec![selected.clone(), excluded.clone()],
    };

    assert_eq!(selected.item_ref(), "item-a");
    assert_eq!(excluded.item_ref(), "item-b");
    assert_eq!(receipt.dispositions.len(), 2);
}
