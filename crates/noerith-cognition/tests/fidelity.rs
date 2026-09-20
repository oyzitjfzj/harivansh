use noerith_cognition::*;
use std::collections::{BTreeSet, VecDeque};

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy(name: &str) -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: name.into(),
        version: "qualified-1".into(),
        qualification_evidence_refs: set(&["heldout-qualification"]),
    }
}

fn candidate() -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Exact(ExactSourceProjection {
        identity: ContextItemIdentity {
            tenant_ref: "tenant-a".into(),
            purpose_ref: "purpose-a".into(),
            item_ref: "exact-a".into(),
            kind: ContextItemKind::ExactSourceSpan,
        },
        source_ref: "source-a".into(),
        source_version: 7,
        span_ref: "span-a".into(),
        content_digest: "source-digest-a".into(),
        lineage_ref: "lineage-a".into(),
        boundary: ContextBoundaryLabels {
            trust_label_ref: "trust-user-source".into(),
            data_use_label_ref: "use-private".into(),
            lifecycle_label_ref: "current@9".into(),
        },
        validity_dependency_refs: set(&["source-a@7", "correction@9"]),
    })
}

fn delivery() -> ContextDeliveryBoundary {
    ContextDeliveryBoundary {
        item_ref: "exact-a".into(),
        information_classes: BTreeSet::from([
            ContextInformationClass::ContentData,
            ContextInformationClass::Evidence,
        ]),
        taint_label_ref: "taint-user-supplied".into(),
        sensitivity_label_ref: "sensitivity-private".into(),
        principal_scope_ref: Some("principal-a".into()),
        authority_context_evidence_ref: None,
        expiry_ref: Some("correction@9".into()),
        label_transition_evidence: Vec::new(),
    }
}

fn protected() -> ProtectedEvidenceRef {
    ProtectedEvidenceRef {
        field_ref: "target-account".into(),
        exact_value_digest: "target-digest-a".into(),
        proving_evidence: BTreeSet::from([ProtectedEvidenceLocator::SourceSpan {
            source_ref: "source-a".into(),
            source_version: 7,
            span_ref: "span-a".into(),
            content_digest: "source-digest-a".into(),
        }]),
    }
}

fn frontier() -> ContextValidityFrontier {
    ContextValidityFrontier {
        goal: VersionedRef {
            reference: "goal-a".into(),
            version: 4,
        },
        work: VersionedRef {
            reference: "work-a".into(),
            version: 12,
        },
        correction_frontier_ref: "correction@9".into(),
        policy_authority_epoch_ref: "authority@6".into(),
        dependency_refs: set(&["source-a@7", "correction@9"]),
    }
}

fn receiver() -> ReceiverContextProfileRef {
    ReceiverContextProfileRef {
        receiver_ref: "model-a".into(),
        receiver_version: "model@7".into(),
        context_profile_ref: "context-profile@3".into(),
        qualification_evidence_refs: set(&["position-load-eval@3"]),
    }
}

fn compilation() -> ContextCompilation {
    ContextCompilation {
        compilation_id: "compilation-a".into(),
        version: 3,
        tenant_ref: "tenant-a".into(),
        principal_context_ref: "principal-a".into(),
        purpose_ref: "purpose-a".into(),
        candidate_set_revision_ref: "candidate-set@5".into(),
        candidates: vec![candidate()],
        delivery_boundaries: vec![delivery()],
        protected_evidence: vec![protected()],
        validity_frontier: frontier(),
        receiver_profile: receiver(),
        unresolved_gaps: BTreeSet::new(),
        excluded_but_needed_evidence_refs: BTreeSet::new(),
        effect_refs: BTreeSet::new(),
        obligation_refs: BTreeSet::new(),
        token_budget_requested: Some(4_000),
        token_budget_used: Some(800),
        selection_receipt: ContextSelectionReceipt {
            receipt_id: "selection-a".into(),
            candidate_set_revision_ref: "candidate-set@5".into(),
            selector_policy: policy("selector-a"),
            dispositions: vec![ContextSelectionDisposition::Selected {
                item_ref: "exact-a".into(),
                policy_evidence_refs: set(&["selection-evidence"]),
            }],
        },
    }
}

fn good_report(request: &ContextFidelityRequest<'_>) -> ContextFidelityReport {
    ContextFidelityReport {
        report_id: "fidelity-a".into(),
        binding: request.binding.clone(),
        checked_item_refs: set(&["exact-a"]),
        protected_checks: vec![ProtectedFidelityCheck {
            field_ref: "target-account".into(),
            expected_digest: "target-digest-a".into(),
            observed_digest: Some("target-digest-a".into()),
            evidence_refs: set(&["exact-value-check"]),
        }],
        findings: Vec::new(),
        verdict: ContextFidelityVerdict::Sufficient,
        verifier_policy: policy("independent-fidelity-verifier"),
        verifier_evidence_refs: set(&["fidelity-eval-output"]),
        independence_evidence_refs: set(&["independence-qualification"]),
    }
}

struct GoodVerifier;

impl IndependentFidelityVerifier for GoodVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        Ok(good_report(request))
    }
}

struct SequenceAuthority {
    frontiers: VecDeque<ContextValidityFrontier>,
}

impl SequenceAuthority {
    fn stable(value: ContextValidityFrontier) -> Self {
        Self {
            frontiers: VecDeque::from([value.clone(), value]),
        }
    }
}

impl ContextFrontierAuthority for SequenceAuthority {
    fn current_frontier(
        &mut self,
        _binding: &ContextFidelityBinding,
    ) -> Result<ContextValidityFrontier, ContextFrontierError> {
        self.frontiers
            .pop_front()
            .ok_or(ContextFrontierError::Unavailable)
    }
}

#[test]
fn s04_fidelity_guard_binds_exact_compilation_and_protected_value() {
    let packet = compilation();
    let mut authority = SequenceAuthority::stable(packet.validity_frontier.clone());
    let verified = ContextFidelityGuard::new(GoodVerifier)
        .verify(&packet, &mut authority)
        .unwrap();
    assert_eq!(verified.verdict(), ContextFidelityVerdict::Sufficient);
    assert_eq!(verified.binding().receiver_profile, packet.receiver_profile);
    assert_eq!(verified.validated_frontier(), &packet.validity_frontier);
    assert!(verified_fidelity_has_no_effect_commit_authority(&verified));
    assert_eq!(protected_evidence_for_fidelity(&packet).len(), 1);
}

struct NeverVerifier;

impl IndependentFidelityVerifier for NeverVerifier {
    fn evaluate(
        &self,
        _request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        panic!("stale context must fail before adaptive verifier runs")
    }
}

#[test]
fn s04_fidelity_guard_rejects_stale_frontier_before_verifier() {
    let packet = compilation();
    let mut stale = packet.validity_frontier.clone();
    stale.correction_frontier_ref = "correction@10".into();
    let mut authority = SequenceAuthority {
        frontiers: VecDeque::from([stale]),
    };
    assert_eq!(
        ContextFidelityGuard::new(NeverVerifier).verify(&packet, &mut authority),
        Err(FidelityGuardError::ContextStale)
    );
}

#[test]
fn s04_fidelity_guard_rejects_frontier_change_during_verification() {
    let packet = compilation();
    let mut changed = packet.validity_frontier.clone();
    changed.policy_authority_epoch_ref = "authority@7".into();
    let mut authority = SequenceAuthority {
        frontiers: VecDeque::from([packet.validity_frontier.clone(), changed]),
    };
    assert_eq!(
        ContextFidelityGuard::new(GoodVerifier).verify(&packet, &mut authority),
        Err(FidelityGuardError::ContextStale)
    );
}

struct ReplayVerifier;

impl IndependentFidelityVerifier for ReplayVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        let mut report = good_report(request);
        report.binding.principal_context_ref = "principal-other".into();
        report.binding.receiver_profile.receiver_version = "model@old".into();
        Ok(report)
    }
}

#[test]
fn s04_fidelity_report_cannot_replay_across_principal_or_receiver() {
    let packet = compilation();
    let mut authority = SequenceAuthority::stable(packet.validity_frontier.clone());
    assert_eq!(
        ContextFidelityGuard::new(ReplayVerifier).verify(&packet, &mut authority),
        Err(FidelityGuardError::BindingMismatch)
    );
}

struct MissingCoverageVerifier;

impl IndependentFidelityVerifier for MissingCoverageVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        let mut report = good_report(request);
        report.checked_item_refs.clear();
        Ok(report)
    }
}

#[test]
fn s04_fidelity_cannot_claim_complete_without_checking_selected_item() {
    let packet = compilation();
    let mut authority = SequenceAuthority::stable(packet.validity_frontier.clone());
    assert_eq!(
        ContextFidelityGuard::new(MissingCoverageVerifier).verify(&packet, &mut authority),
        Err(FidelityGuardError::SelectedCoverageMissing)
    );
}

struct WrongProtectedDigestVerifier;

impl IndependentFidelityVerifier for WrongProtectedDigestVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        let mut report = good_report(request);
        report.protected_checks[0].expected_digest = "different-expected".into();
        Ok(report)
    }
}

#[test]
fn s04_fidelity_cannot_relabel_the_expected_protected_value() {
    let packet = compilation();
    let mut authority = SequenceAuthority::stable(packet.validity_frontier.clone());
    assert_eq!(
        ContextFidelityGuard::new(WrongProtectedDigestVerifier).verify(&packet, &mut authority),
        Err(FidelityGuardError::ProtectedExpectedDigestMismatch)
    );
}

struct WrongObservedDigestVerifier;

impl IndependentFidelityVerifier for WrongObservedDigestVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        let mut report = good_report(request);
        report.protected_checks[0].observed_digest = Some("changed-value".into());
        Ok(report)
    }
}

#[test]
fn s04_sufficient_requires_exact_protected_value_match() {
    let packet = compilation();
    let mut authority = SequenceAuthority::stable(packet.validity_frontier.clone());
    assert_eq!(
        ContextFidelityGuard::new(WrongObservedDigestVerifier).verify(&packet, &mut authority),
        Err(FidelityGuardError::SufficientProtectedValueMismatch)
    );
}

struct OmissionButSufficientVerifier;

impl IndependentFidelityVerifier for OmissionButSufficientVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        let mut report = good_report(request);
        report.findings.push(FidelityFinding {
            kind: FidelityFindingKind::Omission,
            subject_ref: "important-negation".into(),
            evidence_refs: set(&["source-comparison"]),
        });
        Ok(report)
    }
}

#[test]
fn s04_sufficient_cannot_coexist_with_material_fidelity_finding() {
    let packet = compilation();
    let mut authority = SequenceAuthority::stable(packet.validity_frontier.clone());
    assert_eq!(
        ContextFidelityGuard::new(OmissionButSufficientVerifier).verify(&packet, &mut authority),
        Err(FidelityGuardError::SufficientWithFinding)
    );
}

struct RetrieveExactVerifier;

impl IndependentFidelityVerifier for RetrieveExactVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        let mut report = good_report(request);
        report.verdict = ContextFidelityVerdict::RetrieveExactSource;
        report.protected_checks[0].observed_digest = None;
        report.findings.push(FidelityFinding {
            kind: FidelityFindingKind::Distortion,
            subject_ref: "derived-brief".into(),
            evidence_refs: set(&["comparison-needs-exact-source"]),
        });
        Ok(report)
    }
}

#[test]
fn s04_fidelity_can_request_exact_source_without_inventing_success() {
    let packet = compilation();
    let mut authority = SequenceAuthority::stable(packet.validity_frontier.clone());
    let verified = ContextFidelityGuard::new(RetrieveExactVerifier)
        .verify(&packet, &mut authority)
        .unwrap();
    assert_eq!(
        verified.verdict(),
        ContextFidelityVerdict::RetrieveExactSource
    );
}

#[test]
fn s04_duplicate_protected_field_is_rejected_before_verification() {
    let mut packet = compilation();
    let mut conflicting = protected();
    conflicting.exact_value_digest = "conflicting-value".into();
    packet.protected_evidence.push(conflicting);
    let mut authority = SequenceAuthority::stable(packet.validity_frontier.clone());
    assert_eq!(
        ContextFidelityGuard::new(NeverVerifier).verify(&packet, &mut authority),
        Err(FidelityGuardError::DuplicateProtectedField)
    );
}
