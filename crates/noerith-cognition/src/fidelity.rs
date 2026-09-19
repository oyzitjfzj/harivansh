use crate::{
    AdaptivePolicyError, AdaptivePolicyRef, CognitionContractError, ContextCandidateDescriptor,
    ContextCompilation, ContextDeliveryBoundary, ContextDeliveryError,
    ContextDeliveryLabelSnapshot, ContextInformationClass, ContextItemKind,
    ContextLabelTransitionEvidence, ContextSelectionDisposition, ContextValidityFrontier,
    ProtectedEvidenceLocator, ProtectedEvidenceRef, ReceiverContextProfileRef,
    validate_context_candidate_set, validate_context_delivery_boundaries,
    validate_context_selection_receipt, validate_context_validity_frontier,
    validate_protected_evidence_against_candidates, validate_receiver_context_profile,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextItemOriginBinding {
    Exact {
        source_ref: String,
        source_version: u64,
        span_ref: String,
        lineage_ref: String,
    },
    Structured {
        fact_ref: String,
        fact_version: u64,
        provenance_refs: BTreeSet<String>,
    },
    Derived {
        parent_item_refs: BTreeSet<String>,
        provenance_ref: String,
        transform_policy: AdaptivePolicyRef,
    },
}

/// Canonical structural projection of one context item for fidelity binding.
/// It binds source/lineage, digest, validity and the complete delivery edge
/// evidence so a report cannot be replayed after a relabel policy/evidence
/// transition changes while visible labels happen to remain identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextItemFidelityBinding {
    pub kind: ContextItemKind,
    pub content_digest: String,
    pub validity_dependency_refs: BTreeSet<String>,
    pub delivery_labels: ContextDeliveryLabelSnapshot,
    pub information_classes: BTreeSet<ContextInformationClass>,
    pub authority_context_evidence_ref: Option<String>,
    pub label_transition_evidence: Vec<ContextLabelTransitionEvidence>,
    pub origin: ContextItemOriginBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedClaimFidelityBinding {
    pub exact_value_digest: String,
    pub proving_evidence: BTreeSet<ProtectedEvidenceLocator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextSelectionDispositionBinding {
    Selected {
        policy_evidence_refs: BTreeSet<String>,
    },
    Excluded {
        reason_refs: BTreeSet<String>,
        policy_evidence_refs: BTreeSet<String>,
    },
}

/// Exact compilation state covered by one fidelity evaluation.
///
/// This is evidence scope, not authority. Every semantic field in the
/// compilation that can change downstream interpretation is represented here;
/// a caller cannot safely replay a report by reusing only a friendly-looking
/// compilation/candidate-set identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFidelityBinding {
    pub compilation_id: String,
    pub compilation_version: u64,
    pub tenant_ref: String,
    pub principal_context_ref: String,
    pub purpose_ref: String,
    pub candidate_set_revision_ref: String,
    pub validity_frontier: ContextValidityFrontier,
    pub receiver_profile: ReceiverContextProfileRef,
    pub selection_receipt_ref: String,
    pub selector_policy: AdaptivePolicyRef,
    pub selected_item_refs: BTreeSet<String>,
    pub excluded_item_refs: BTreeSet<String>,
    pub selection_dispositions: BTreeMap<String, ContextSelectionDispositionBinding>,
    pub item_bindings: BTreeMap<String, ContextItemFidelityBinding>,
    pub protected_claims: BTreeMap<String, ProtectedClaimFidelityBinding>,
    pub unresolved_gap_refs: BTreeSet<String>,
    pub excluded_but_needed_evidence_refs: BTreeSet<String>,
    pub effect_refs: BTreeSet<String>,
    pub obligation_refs: BTreeSet<String>,
    pub token_budget_requested: Option<u64>,
    pub token_budget_used: Option<u64>,
}

impl ContextFidelityBinding {
    pub fn from_compilation(compilation: &ContextCompilation) -> Result<Self, FidelityGuardError> {
        let boundary_by_ref: BTreeMap<&str, &ContextDeliveryBoundary> = compilation
            .delivery_boundaries
            .iter()
            .map(|boundary| (boundary.item_ref.as_str(), boundary))
            .collect();
        if boundary_by_ref.len() != compilation.delivery_boundaries.len() {
            return Err(FidelityGuardError::BindingBoundaryMismatch);
        }

        let mut item_bindings = BTreeMap::new();
        for candidate in &compilation.candidates {
            let item_ref = candidate.identity().item_ref.as_str();
            let Some(boundary) = boundary_by_ref.get(item_ref) else {
                return Err(FidelityGuardError::BindingBoundaryMismatch);
            };
            let delivery_labels = ContextDeliveryLabelSnapshot::capture(candidate, boundary)
                .map_err(FidelityGuardError::Delivery)?;
            let (validity_dependency_refs, origin) = match candidate {
                ContextCandidateDescriptor::Exact(exact) => (
                    exact.validity_dependency_refs.clone(),
                    ContextItemOriginBinding::Exact {
                        source_ref: exact.source_ref.clone(),
                        source_version: exact.source_version,
                        span_ref: exact.span_ref.clone(),
                        lineage_ref: exact.lineage_ref.clone(),
                    },
                ),
                ContextCandidateDescriptor::Structured(fact) => (
                    fact.validity_dependency_refs.clone(),
                    ContextItemOriginBinding::Structured {
                        fact_ref: fact.fact_ref.clone(),
                        fact_version: fact.fact_version,
                        provenance_refs: fact.provenance_refs.clone(),
                    },
                ),
                ContextCandidateDescriptor::Derived(derived) => (
                    derived.validity_dependency_refs.clone(),
                    ContextItemOriginBinding::Derived {
                        parent_item_refs: derived.parent_item_refs.clone(),
                        provenance_ref: derived.provenance_ref.clone(),
                        transform_policy: derived.transform_policy.clone(),
                    },
                ),
            };
            let binding = ContextItemFidelityBinding {
                kind: candidate.identity().kind,
                content_digest: candidate.content_digest().to_owned(),
                validity_dependency_refs,
                delivery_labels,
                information_classes: boundary.information_classes.clone(),
                authority_context_evidence_ref: boundary.authority_context_evidence_ref.clone(),
                label_transition_evidence: boundary.label_transition_evidence.clone(),
                origin,
            };
            if item_bindings.insert(item_ref.to_owned(), binding).is_some() {
                return Err(FidelityGuardError::DuplicateContextItem);
            }
        }

        let mut protected_claims = BTreeMap::new();
        for protected in &compilation.protected_evidence {
            if protected_claims
                .insert(
                    protected.field_ref.clone(),
                    ProtectedClaimFidelityBinding {
                        exact_value_digest: protected.exact_value_digest.clone(),
                        proving_evidence: protected.proving_evidence.clone(),
                    },
                )
                .is_some()
            {
                return Err(FidelityGuardError::DuplicateProtectedField);
            }
        }

        let mut selected_item_refs = BTreeSet::new();
        let mut excluded_item_refs = BTreeSet::new();
        let mut selection_dispositions = BTreeMap::new();
        for disposition in &compilation.selection_receipt.dispositions {
            let (item_ref, bound) = match disposition {
                ContextSelectionDisposition::Selected {
                    item_ref,
                    policy_evidence_refs,
                } => {
                    selected_item_refs.insert(item_ref.clone());
                    (
                        item_ref,
                        ContextSelectionDispositionBinding::Selected {
                            policy_evidence_refs: policy_evidence_refs.clone(),
                        },
                    )
                }
                ContextSelectionDisposition::Excluded {
                    item_ref,
                    reason_refs,
                    policy_evidence_refs,
                } => {
                    excluded_item_refs.insert(item_ref.clone());
                    (
                        item_ref,
                        ContextSelectionDispositionBinding::Excluded {
                            reason_refs: reason_refs.clone(),
                            policy_evidence_refs: policy_evidence_refs.clone(),
                        },
                    )
                }
            };
            if selection_dispositions
                .insert(item_ref.clone(), bound)
                .is_some()
            {
                return Err(FidelityGuardError::DuplicateSelectionDisposition);
            }
        }

        Ok(Self {
            compilation_id: compilation.compilation_id.clone(),
            compilation_version: compilation.version,
            tenant_ref: compilation.tenant_ref.clone(),
            principal_context_ref: compilation.principal_context_ref.clone(),
            purpose_ref: compilation.purpose_ref.clone(),
            candidate_set_revision_ref: compilation.candidate_set_revision_ref.clone(),
            validity_frontier: compilation.validity_frontier.clone(),
            receiver_profile: compilation.receiver_profile.clone(),
            selection_receipt_ref: compilation.selection_receipt.receipt_id.clone(),
            selector_policy: compilation.selection_receipt.selector_policy.clone(),
            selected_item_refs,
            excluded_item_refs,
            selection_dispositions,
            item_bindings,
            protected_claims,
            unresolved_gap_refs: compilation.unresolved_gaps.clone(),
            excluded_but_needed_evidence_refs: compilation
                .excluded_but_needed_evidence_refs
                .clone(),
            effect_refs: compilation.effect_refs.clone(),
            obligation_refs: compilation.obligation_refs.clone(),
            token_budget_requested: compilation.token_budget_requested,
            token_budget_used: compilation.token_budget_used,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FidelityFindingKind {
    Omission,
    Contradiction,
    Distortion,
    StaleOrSupersededEvidence,
    ProvenanceGap,
    BoundaryLoss,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidelityFinding {
    pub kind: FidelityFindingKind,
    pub subject_ref: String,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedFidelityCheck {
    pub field_ref: String,
    pub expected_digest: String,
    pub observed_digest: Option<String>,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextFidelityVerdict {
    Sufficient,
    RetrieveExactSource,
    Recompile,
    IndependentReview,
    Escalate,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFidelityReport {
    pub report_id: String,
    pub binding: ContextFidelityBinding,
    pub checked_item_refs: BTreeSet<String>,
    pub protected_checks: Vec<ProtectedFidelityCheck>,
    pub findings: Vec<FidelityFinding>,
    pub verdict: ContextFidelityVerdict,
    pub verifier_policy: AdaptivePolicyRef,
    pub verifier_evidence_refs: BTreeSet<String>,
    pub independence_evidence_refs: BTreeSet<String>,
}

/// Guard-issued evidence wrapper. Fields are private so downstream code cannot
/// construct a value that looks guard-approved without passing the complete
/// structural, exact-value and pre/post-frontier checks in `ContextFidelityGuard`.
/// It is still evidence only: final protected use must revalidate current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContextFidelity {
    report: ContextFidelityReport,
    validated_frontier: ContextValidityFrontier,
}

impl VerifiedContextFidelity {
    pub fn report(&self) -> &ContextFidelityReport {
        &self.report
    }

    pub fn report_id(&self) -> &str {
        &self.report.report_id
    }

    pub fn binding(&self) -> &ContextFidelityBinding {
        &self.report.binding
    }

    pub const fn verdict(&self) -> ContextFidelityVerdict {
        self.report.verdict
    }

    pub fn validated_frontier(&self) -> &ContextValidityFrontier {
        &self.validated_frontier
    }

    pub fn verifier_evidence_refs(&self) -> &BTreeSet<String> {
        &self.report.verifier_evidence_refs
    }

    pub fn independence_evidence_refs(&self) -> &BTreeSet<String> {
        &self.report.independence_evidence_refs
    }
}

pub struct ContextFidelityRequest<'a> {
    pub compilation: &'a ContextCompilation,
    pub binding: &'a ContextFidelityBinding,
}

/// Adaptive semantic checker. It proposes findings/verdict plus evidence; the
/// deterministic guard below independently validates protected structure.
pub trait IndependentFidelityVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextFrontierError {
    Unavailable,
    InvalidEvidence,
}

/// Narrow read-only owner boundary for currentness. It deliberately exposes no
/// mutation or effect authority.
pub trait ContextFrontierAuthority {
    fn current_frontier(
        &mut self,
        binding: &ContextFidelityBinding,
    ) -> Result<ContextValidityFrontier, ContextFrontierError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FidelityGuardError {
    Adaptive(AdaptivePolicyError),
    Contract(CognitionContractError),
    Delivery(ContextDeliveryError),
    Frontier(ContextFrontierError),
    ContextStale,
    CompilationReceiptMismatch,
    BindingMismatch,
    BindingBoundaryMismatch,
    DuplicateContextItem,
    DuplicateSelectionDisposition,
    DuplicateProtectedField,
    ProtectedEvidenceExcluded { field_ref: String, item_ref: String },
    DuplicateProtectedCheck,
    ProtectedCheckSetMismatch,
    ProtectedExpectedDigestMismatch,
    SelectedCoverageMissing,
    UnknownCheckedItem,
    MissingVerifierEvidence,
    InvalidFinding,
    SufficientWithFinding,
    SufficientProtectedValueMismatch,
}

pub struct ContextFidelityGuard<V> {
    verifier: V,
}

impl<V> ContextFidelityGuard<V>
where
    V: IndependentFidelityVerifier,
{
    pub const fn new(verifier: V) -> Self {
        Self { verifier }
    }

    /// Evaluate fidelity against an exact compiled frontier and issue an
    /// unforgeable-by-public-constructor wrapper only after every guard check.
    pub fn verify<A>(
        &self,
        compilation: &ContextCompilation,
        authority: &mut A,
    ) -> Result<VerifiedContextFidelity, FidelityGuardError>
    where
        A: ContextFrontierAuthority,
    {
        validate_compilation(compilation)?;
        let binding = ContextFidelityBinding::from_compilation(compilation)?;

        let before = authority
            .current_frontier(&binding)
            .map_err(FidelityGuardError::Frontier)?;
        if before != compilation.validity_frontier {
            return Err(FidelityGuardError::ContextStale);
        }

        let request = ContextFidelityRequest {
            compilation,
            binding: &binding,
        };
        let report = self
            .verifier
            .evaluate(&request)
            .map_err(FidelityGuardError::Adaptive)?;

        let after = authority
            .current_frontier(&binding)
            .map_err(FidelityGuardError::Frontier)?;
        if after != compilation.validity_frontier {
            return Err(FidelityGuardError::ContextStale);
        }

        validate_report(compilation, &binding, &report)?;
        Ok(VerifiedContextFidelity {
            report,
            validated_frontier: after,
        })
    }
}

fn validate_compilation(compilation: &ContextCompilation) -> Result<(), FidelityGuardError> {
    if compilation.compilation_id.trim().is_empty()
        || compilation.principal_context_ref.trim().is_empty()
        || compilation.candidate_set_revision_ref.trim().is_empty()
    {
        return Err(FidelityGuardError::Contract(
            CognitionContractError::ContextSelectionReceiptInvalid,
        ));
    }

    validate_context_candidate_set(
        &compilation.candidates,
        &compilation.tenant_ref,
        &compilation.purpose_ref,
    )
    .map_err(FidelityGuardError::Contract)?;
    validate_context_delivery_boundaries(&compilation.candidates, &compilation.delivery_boundaries)
        .map_err(FidelityGuardError::Delivery)?;
    validate_context_validity_frontier(&compilation.validity_frontier)
        .map_err(FidelityGuardError::Contract)?;
    validate_receiver_context_profile(&compilation.receiver_profile)
        .map_err(FidelityGuardError::Contract)?;
    validate_context_selection_receipt(&compilation.candidates, &compilation.selection_receipt)
        .map_err(FidelityGuardError::Contract)?;

    if compilation.selection_receipt.candidate_set_revision_ref
        != compilation.candidate_set_revision_ref
    {
        return Err(FidelityGuardError::CompilationReceiptMismatch);
    }

    let selected: BTreeSet<&str> = compilation
        .selection_receipt
        .dispositions
        .iter()
        .filter_map(|disposition| match disposition {
            ContextSelectionDisposition::Selected { item_ref, .. } => Some(item_ref.as_str()),
            ContextSelectionDisposition::Excluded { .. } => None,
        })
        .collect();

    for protected in &compilation.protected_evidence {
        validate_protected_evidence_against_candidates(protected, &compilation.candidates)
            .map_err(FidelityGuardError::Contract)?;
        for locator in &protected.proving_evidence {
            let Some(item_ref) = protected_locator_item_ref(locator, &compilation.candidates)
            else {
                return Err(FidelityGuardError::Contract(
                    CognitionContractError::ProtectedEvidenceLocatorMismatch,
                ));
            };
            if !selected.contains(item_ref) {
                return Err(FidelityGuardError::ProtectedEvidenceExcluded {
                    field_ref: protected.field_ref.clone(),
                    item_ref: item_ref.to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn protected_locator_item_ref<'a>(
    locator: &ProtectedEvidenceLocator,
    candidates: &'a [ContextCandidateDescriptor],
) -> Option<&'a str> {
    candidates
        .iter()
        .find_map(|candidate| match (locator, candidate) {
            (
                ProtectedEvidenceLocator::SourceSpan {
                    source_ref,
                    source_version,
                    span_ref,
                    content_digest,
                },
                ContextCandidateDescriptor::Exact(exact),
            ) if exact.source_ref == *source_ref
                && exact.source_version == *source_version
                && exact.span_ref == *span_ref
                && exact.content_digest == *content_digest =>
            {
                Some(exact.identity.item_ref.as_str())
            }
            (
                ProtectedEvidenceLocator::StructuredFact {
                    fact_ref,
                    fact_version,
                    fact_digest,
                },
                ContextCandidateDescriptor::Structured(fact),
            ) if fact.fact_ref == *fact_ref
                && fact.fact_version == *fact_version
                && fact.content_digest == *fact_digest =>
            {
                Some(fact.identity.item_ref.as_str())
            }
            _ => None,
        })
}

fn validate_report(
    compilation: &ContextCompilation,
    expected: &ContextFidelityBinding,
    report: &ContextFidelityReport,
) -> Result<(), FidelityGuardError> {
    if report.binding != *expected {
        return Err(FidelityGuardError::BindingMismatch);
    }
    if report.report_id.trim().is_empty()
        || !qualified_policy(&report.verifier_policy)
        || !clean_nonempty_set(&report.verifier_evidence_refs)
        || !clean_nonempty_set(&report.independence_evidence_refs)
    {
        return Err(FidelityGuardError::MissingVerifierEvidence);
    }

    let all_candidate_refs: BTreeSet<&str> = compilation
        .candidates
        .iter()
        .map(|candidate| candidate.identity().item_ref.as_str())
        .collect();
    if report
        .checked_item_refs
        .iter()
        .any(|item| !all_candidate_refs.contains(item.as_str()))
    {
        return Err(FidelityGuardError::UnknownCheckedItem);
    }
    if !expected
        .selected_item_refs
        .is_subset(&report.checked_item_refs)
    {
        return Err(FidelityGuardError::SelectedCoverageMissing);
    }

    for finding in &report.findings {
        if finding.subject_ref.trim().is_empty() || !clean_nonempty_set(&finding.evidence_refs) {
            return Err(FidelityGuardError::InvalidFinding);
        }
    }

    let mut checks = BTreeMap::<&str, &ProtectedFidelityCheck>::new();
    for check in &report.protected_checks {
        if check.field_ref.trim().is_empty()
            || check.expected_digest.trim().is_empty()
            || !clean_nonempty_set(&check.evidence_refs)
        {
            return Err(FidelityGuardError::ProtectedCheckSetMismatch);
        }
        if checks.insert(check.field_ref.as_str(), check).is_some() {
            return Err(FidelityGuardError::DuplicateProtectedCheck);
        }
    }
    let expected_fields: BTreeSet<&str> = expected
        .protected_claims
        .keys()
        .map(String::as_str)
        .collect();
    let checked_fields: BTreeSet<&str> = checks.keys().copied().collect();
    if checked_fields != expected_fields {
        return Err(FidelityGuardError::ProtectedCheckSetMismatch);
    }
    for (field_ref, claim) in &expected.protected_claims {
        let check = checks
            .get(field_ref.as_str())
            .expect("protected field sets already proven equal");
        if check.expected_digest != claim.exact_value_digest {
            return Err(FidelityGuardError::ProtectedExpectedDigestMismatch);
        }
    }

    if report.verdict == ContextFidelityVerdict::Sufficient {
        if !report.findings.is_empty() {
            return Err(FidelityGuardError::SufficientWithFinding);
        }
        if expected.protected_claims.iter().any(|(field, claim)| {
            checks
                .get(field.as_str())
                .and_then(|check| check.observed_digest.as_deref())
                != Some(claim.exact_value_digest.as_str())
        }) {
            return Err(FidelityGuardError::SufficientProtectedValueMismatch);
        }
    }
    Ok(())
}

fn qualified_policy(policy: &AdaptivePolicyRef) -> bool {
    !policy.policy_ref.trim().is_empty()
        && !policy.version.trim().is_empty()
        && clean_nonempty_set(&policy.qualification_evidence_refs)
}

fn clean_nonempty_set(values: &BTreeSet<String>) -> bool {
    !values.is_empty() && values.iter().all(|value| !value.trim().is_empty())
}

/// A guard-issued fidelity wrapper is evidence about context quality only. It
/// has no credential, grant, DecisionSnapshot or controlled-release capability.
pub const fn verified_fidelity_has_no_effect_commit_authority(
    _verified: &VerifiedContextFidelity,
) -> bool {
    true
}

/// Expose protected evidence only as immutable context for independent
/// evaluators; this helper does not convert evidence into authority.
pub fn protected_evidence_for_fidelity(
    compilation: &ContextCompilation,
) -> &[ProtectedEvidenceRef] {
    &compilation.protected_evidence
}
