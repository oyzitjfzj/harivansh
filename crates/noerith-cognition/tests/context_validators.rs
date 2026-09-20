use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy() -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: "selector-policy-a".into(),
        version: "candidate-1".into(),
        qualification_evidence_refs: set(&["selector-heldout-evidence"]),
    }
}

fn boundary() -> ContextBoundaryLabels {
    ContextBoundaryLabels {
        trust_label_ref: "opaque-trust-label".into(),
        data_use_label_ref: "opaque-data-use-label".into(),
        lifecycle_label_ref: "current-frontier-a".into(),
    }
}

fn exact(
    item_ref: &str,
    source_ref: &str,
    span_ref: &str,
    digest: &str,
) -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Exact(ExactSourceProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: item_ref.into(),
            kind: ContextItemKind::ExactSourceSpan,
        },
        source_ref: source_ref.into(),
        source_version: 3,
        span_ref: span_ref.into(),
        content_digest: digest.into(),
        lineage_ref: format!("lineage-{item_ref}"),
        boundary: boundary(),
        validity_dependency_refs: set(&["source-frontier@3"]),
    })
}

fn structured(
    item_ref: &str,
    fact_ref: &str,
    version: u64,
    digest: &str,
) -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Structured(StructuredFactProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: item_ref.into(),
            kind: ContextItemKind::StructuredFact,
        },
        fact_ref: fact_ref.into(),
        fact_version: version,
        content_digest: digest.into(),
        provenance_refs: set(&["source-item"]),
        boundary: boundary(),
        validity_dependency_refs: set(&["source-frontier@3"]),
    })
}

fn derived(item_ref: &str, parents: &[&str]) -> ContextCandidateDescriptor {
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
        boundary: boundary(),
        validity_dependency_refs: set(&["source-frontier@3"]),
    })
}

#[test]
fn candidate_validation_accepts_grounded_acyclic_lineage_independent_of_input_order() {
    let forward = vec![
        exact("source-item", "source-a", "span-a", "digest-span-a"),
        structured("decision-item", "decision-a", 4, "digest-decision-a"),
        derived("summary-a", &["source-item", "decision-item"]),
        derived("summary-b", &["summary-a"]),
    ];
    let reverse = vec![
        derived("summary-b", &["summary-a"]),
        derived("summary-a", &["source-item", "decision-item"]),
        structured("decision-item", "decision-a", 4, "digest-decision-a"),
        exact("source-item", "source-a", "span-a", "digest-span-a"),
    ];

    assert!(validate_context_candidate_set(&forward, "tenant-a", "purpose-a").is_ok());
    assert!(validate_context_candidate_set(&reverse, "tenant-a", "purpose-a").is_ok());
}

#[test]
fn candidate_validation_rejects_scope_kind_missing_parent_and_cycles() {
    let mut wrong_scope = exact("source-item", "source-a", "span-a", "digest-a");
    if let ContextCandidateDescriptor::Exact(item) = &mut wrong_scope {
        item.identity.tenant_ref = "tenant-b".into();
    }
    assert_eq!(
        validate_context_candidate_set(&[wrong_scope], "tenant-a", "purpose-a"),
        Err(CognitionContractError::ContextCandidateScopeMismatch)
    );

    let mut wrong_kind = exact("source-item", "source-a", "span-a", "digest-a");
    if let ContextCandidateDescriptor::Exact(item) = &mut wrong_kind {
        item.identity.kind = ContextItemKind::DerivedView;
    }
    assert_eq!(
        validate_context_candidate_set(&[wrong_kind], "tenant-a", "purpose-a"),
        Err(CognitionContractError::ContextCandidateInvalidKind)
    );

    assert_eq!(
        validate_context_candidate_set(
            &[derived("summary-a", &["missing-parent"])],
            "tenant-a",
            "purpose-a",
        ),
        Err(CognitionContractError::ContextDerivedParentMissing)
    );

    let cycle = vec![
        derived("summary-a", &["summary-b"]),
        derived("summary-b", &["summary-a"]),
    ];
    assert_eq!(
        validate_context_candidate_set(&cycle, "tenant-a", "purpose-a"),
        Err(CognitionContractError::ContextDerivationCycle)
    );
}

#[test]
fn structured_candidate_requires_provenance_and_correct_kind() {
    let mut no_provenance = structured("fact-item", "fact-a", 2, "digest-fact-a");
    if let ContextCandidateDescriptor::Structured(fact) = &mut no_provenance {
        fact.provenance_refs.clear();
    }
    assert_eq!(
        validate_context_candidate_set(&[no_provenance], "tenant-a", "purpose-a"),
        Err(CognitionContractError::ContextStructuredFactEvidenceMissing)
    );

    let mut wrong_kind = structured("fact-item", "fact-a", 2, "digest-fact-a");
    if let ContextCandidateDescriptor::Structured(fact) = &mut wrong_kind {
        fact.identity.kind = ContextItemKind::ExactSourceSpan;
    }
    assert_eq!(
        validate_context_candidate_set(&[wrong_kind], "tenant-a", "purpose-a"),
        Err(CognitionContractError::ContextCandidateInvalidKind)
    );
}

#[test]
fn candidate_validation_rejects_duplicate_identity_even_when_payload_differs() {
    let candidates = vec![
        exact("same-item", "source-a", "span-a", "digest-a"),
        structured("same-item", "fact-a", 1, "digest-b"),
    ];
    assert_eq!(
        validate_context_candidate_set(&candidates, "tenant-a", "purpose-a"),
        Err(CognitionContractError::ContextCandidateDuplicateIdentity)
    );
}

#[test]
fn selection_receipt_is_a_total_single_disposition_partition() {
    let candidates = vec![
        exact("source-item", "source-a", "span-a", "digest-a"),
        exact("source-extra", "source-b", "span-b", "digest-b"),
    ];
    let valid = ContextSelectionReceipt {
        receipt_id: "selection-a".into(),
        candidate_set_revision_ref: "candidate-set@9".into(),
        selector_policy: policy(),
        dispositions: vec![
            ContextSelectionDisposition::Selected {
                item_ref: "source-item".into(),
                policy_evidence_refs: set(&["selection-evidence-a"]),
            },
            ContextSelectionDisposition::Excluded {
                item_ref: "source-extra".into(),
                reason_refs: set(&["not-needed-for-this-purpose"]),
                policy_evidence_refs: set(&["selection-evidence-b"]),
            },
        ],
    };
    assert!(validate_context_selection_receipt(&candidates, &valid).is_ok());

    let mut incomplete = valid.clone();
    incomplete.dispositions.pop();
    assert_eq!(
        validate_context_selection_receipt(&candidates, &incomplete),
        Err(CognitionContractError::ContextSelectionIncomplete)
    );

    let mut duplicate = valid.clone();
    duplicate.dispositions[1] = ContextSelectionDisposition::Excluded {
        item_ref: "source-item".into(),
        reason_refs: set(&["duplicate-decision"]),
        policy_evidence_refs: set(&["selection-evidence-b"]),
    };
    assert_eq!(
        validate_context_selection_receipt(&candidates, &duplicate),
        Err(CognitionContractError::ContextSelectionDuplicateDisposition)
    );

    let mut no_reason = valid;
    no_reason.dispositions[1] = ContextSelectionDisposition::Excluded {
        item_ref: "source-extra".into(),
        reason_refs: BTreeSet::new(),
        policy_evidence_refs: set(&["selection-evidence-b"]),
    };
    assert_eq!(
        validate_context_selection_receipt(&candidates, &no_reason),
        Err(CognitionContractError::ContextSelectionEvidenceMissing)
    );
}

#[test]
fn protected_source_evidence_requires_exact_source_version_span_and_digest() {
    let candidates = vec![exact(
        "source-item",
        "user-message-a",
        "span-account",
        "digest-span-account",
    )];
    let exact_pin = ProtectedEvidenceRef {
        field_ref: "target-account".into(),
        exact_value_digest: "digest-account-value".into(),
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::SourceSpan {
            source_ref: "user-message-a".into(),
            source_version: 3,
            span_ref: "span-account".into(),
            content_digest: "digest-span-account".into(),
        }]),
    };
    assert!(validate_protected_evidence_against_candidates(&exact_pin, &candidates).is_ok());

    let wrong_span = ProtectedEvidenceRef {
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::SourceSpan {
            source_ref: "user-message-a".into(),
            source_version: 3,
            span_ref: "unrelated-span".into(),
            content_digest: "digest-span-account".into(),
        }]),
        ..exact_pin.clone()
    };
    assert_eq!(
        validate_protected_evidence_against_candidates(&wrong_span, &candidates),
        Err(CognitionContractError::ProtectedEvidenceLocatorMismatch)
    );

    let wrong_digest = ProtectedEvidenceRef {
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::SourceSpan {
            source_ref: "user-message-a".into(),
            source_version: 3,
            span_ref: "span-account".into(),
            content_digest: "wrong-digest".into(),
        }]),
        ..exact_pin
    };
    assert_eq!(
        validate_protected_evidence_against_candidates(&wrong_digest, &candidates),
        Err(CognitionContractError::ProtectedEvidenceLocatorMismatch)
    );
}

#[test]
fn protected_structured_evidence_requires_exact_fact_version_and_digest() {
    let candidates = vec![structured(
        "fact-item",
        "profile:account",
        7,
        "digest-fact-v7",
    )];
    let protected = ProtectedEvidenceRef {
        field_ref: "target-account".into(),
        exact_value_digest: "digest-account-value".into(),
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::StructuredFact {
            fact_ref: "profile:account".into(),
            fact_version: 7,
            fact_digest: "digest-fact-v7".into(),
        }]),
    };
    assert!(validate_protected_evidence_against_candidates(&protected, &candidates).is_ok());

    let wrong_version = ProtectedEvidenceRef {
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::StructuredFact {
            fact_ref: "profile:account".into(),
            fact_version: 6,
            fact_digest: "digest-fact-v7".into(),
        }]),
        ..protected.clone()
    };
    assert_eq!(
        validate_protected_evidence_against_candidates(&wrong_version, &candidates),
        Err(CognitionContractError::ProtectedEvidenceLocatorMismatch)
    );

    let wrong_digest = ProtectedEvidenceRef {
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::StructuredFact {
            fact_ref: "profile:account".into(),
            fact_version: 7,
            fact_digest: "wrong-digest".into(),
        }]),
        ..protected
    };
    assert_eq!(
        validate_protected_evidence_against_candidates(&wrong_digest, &candidates),
        Err(CognitionContractError::ProtectedEvidenceLocatorMismatch)
    );
}

#[test]
fn frontier_and_receiver_require_explicit_identity_and_qualification() {
    let frontier = ContextValidityFrontier {
        goal: VersionedRef {
            reference: "goal-a".into(),
            version: 8,
        },
        work: VersionedRef {
            reference: "work-a".into(),
            version: 13,
        },
        correction_frontier_ref: "correction@21".into(),
        policy_authority_epoch_ref: "authority@5".into(),
        dependency_refs: set(&["source-a@3"]),
    };
    assert!(validate_context_validity_frontier(&frontier).is_ok());

    let receiver = ReceiverContextProfileRef {
        receiver_ref: "model-a".into(),
        receiver_version: "2026-09".into(),
        context_profile_ref: "context-profile@4".into(),
        qualification_evidence_refs: set(&["position-load-heldout@4"]),
    };
    assert!(validate_receiver_context_profile(&receiver).is_ok());

    let mut unqualified = receiver;
    unqualified.qualification_evidence_refs.clear();
    assert_eq!(
        validate_receiver_context_profile(&unqualified),
        Err(CognitionContractError::ReceiverQualificationMissing)
    );
}

#[test]
fn long_derived_chain_is_validated_iteratively() {
    let mut candidates = vec![exact("source-root", "source-a", "span-root", "digest-root")];
    let mut parent = "source-root".to_owned();
    for index in 0..1024 {
        let item = format!("derived-{index}");
        candidates.push(derived(&item, &[parent.as_str()]));
        parent = item;
    }
    assert!(validate_context_candidate_set(&candidates, "tenant-a", "purpose-a").is_ok());
}
