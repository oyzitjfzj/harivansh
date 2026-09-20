use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy() -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: "selector-a".into(),
        version: "policy-4".into(),
        qualification_evidence_refs: set(&["selector-heldout@4"]),
    }
}

fn candidate() -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Exact(ExactSourceProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: "message-a:span-4".into(),
            kind: ContextItemKind::ExactSourceSpan,
        },
        source_ref: "message-a".into(),
        source_version: 7,
        span_ref: "span-4".into(),
        content_digest: "sha256:message-a-span-4".into(),
        lineage_ref: "lineage-message-a".into(),
        boundary: ContextBoundaryLabels {
            trust_label_ref: "trust:user-source".into(),
            data_use_label_ref: "use:private".into(),
            lifecycle_label_ref: "current:correction-9".into(),
        },
        validity_dependency_refs: set(&["message-a@7", "correction@9"]),
    })
}

fn delivery() -> ContextDeliveryBoundary {
    ContextDeliveryBoundary {
        item_ref: "message-a:span-4".into(),
        information_classes: BTreeSet::from([
            ContextInformationClass::ContentData,
            ContextInformationClass::Evidence,
        ]),
        taint_label_ref: "taint:user-supplied".into(),
        sensitivity_label_ref: "sensitivity:private".into(),
        principal_scope_ref: Some("principal-a@3".into()),
        authority_context_evidence_ref: None,
        expiry_ref: Some("current:correction-9".into()),
        label_transition_evidence: Vec::new(),
    }
}

fn request() -> ContextSelectionRequest {
    ContextSelectionRequest {
        tenant_ref: "tenant-a".into(),
        principal_context_ref: "principal-a@3".into(),
        purpose_ref: "purpose-a".into(),
        candidate_set_revision_ref: "candidate-set@12".into(),
        candidates: vec![candidate()],
        delivery_boundaries: vec![delivery()],
        protected_evidence: vec![ProtectedEvidenceRef {
            field_ref: "target-account".into(),
            exact_value_digest: "sha256:account-42".into(),
            proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::SourceSpan {
                source_ref: "message-a".into(),
                source_version: 7,
                span_ref: "span-4".into(),
                content_digest: "sha256:message-a-span-4".into(),
            }]),
        }],
        validity_frontier: ContextValidityFrontier {
            goal: VersionedRef {
                reference: "goal-a".into(),
                version: 8,
            },
            work: VersionedRef {
                reference: "work-a".into(),
                version: 13,
            },
            correction_frontier_ref: "correction@9".into(),
            policy_authority_epoch_ref: "authority@5".into(),
            dependency_refs: set(&["message-a@7"]),
        },
        receiver_profile: ReceiverContextProfileRef {
            receiver_ref: "receiver-a".into(),
            receiver_version: "2026-09".into(),
            context_profile_ref: "context-profile@6".into(),
            qualification_evidence_refs: set(&["position-load-heldout@6"]),
        },
        unresolved_gap_refs: set(&["fresh-provider-state-needed"]),
        selector_policy: policy(),
        resource_budget_ref: Some("resource-envelope@2".into()),
    }
}

struct Selector;

impl ContextSelector for Selector {
    fn propose_selection(
        &self,
        request: &ContextSelectionRequest,
    ) -> Result<BoundContextSelectionReceipt, AdaptivePolicyError> {
        assert_eq!(request.candidates[0].identity().tenant_ref, "tenant-a");
        assert_eq!(
            request.candidates[0].boundary().trust_label_ref,
            "trust:user-source"
        );
        assert_eq!(
            request.delivery_boundaries[0].sensitivity_label_ref,
            "sensitivity:private"
        );
        assert!(
            request.delivery_boundaries[0]
                .information_classes
                .contains(&ContextInformationClass::Evidence)
        );
        assert_eq!(
            request.receiver_profile.context_profile_ref,
            "context-profile@6"
        );
        assert_eq!(
            request.validity_frontier.correction_frontier_ref,
            "correction@9"
        );
        assert_eq!(request.protected_evidence.len(), 1);
        Ok(BoundContextSelectionReceipt {
            binding: request.binding(),
            receipt: ContextSelectionReceipt {
                receipt_id: "selection-receipt-a".into(),
                candidate_set_revision_ref: request.candidate_set_revision_ref.clone(),
                selector_policy: request.selector_policy.clone(),
                dispositions: request
                    .candidates
                    .iter()
                    .map(|candidate| ContextSelectionDisposition::Selected {
                        item_ref: candidate.identity().item_ref.clone(),
                        policy_evidence_refs: set(&["selection-decision-evidence"]),
                    })
                    .collect(),
            },
        })
    }
}

#[test]
fn selector_receives_metadata_and_binds_its_exact_request() {
    let request = request();
    let result = Selector.propose_selection(&request).unwrap();
    assert_eq!(result.binding, request.binding());
    assert_eq!(
        result.receipt.candidate_set_revision_ref,
        request.candidate_set_revision_ref
    );
    assert_eq!(result.receipt.selector_policy, request.selector_policy);
    assert_eq!(result.receipt.dispositions.len(), 1);
}

#[test]
fn selection_request_is_proposal_data_not_effect_authority() {
    let request = request();
    assert_eq!(request.candidates[0].identity().purpose_ref, "purpose-a");
    assert!(request.resource_budget_ref.is_some());
    assert_eq!(request.protected_evidence[0].field_ref, "target-account");
    assert_eq!(
        request.delivery_boundaries[0].authority_context_evidence_ref,
        None
    );
}
