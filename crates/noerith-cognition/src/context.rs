use crate::{
    AdaptivePolicyError, AdaptivePolicyRef, CognitionContractError, ContextCandidateDescriptor,
    ContextDeliveryBoundary, ContextDeliveryError, ContextSelectionDisposition,
    ContextSelectionReceipt, ContextSelectionRequest, ContextSelector, ContextValidityFrontier,
    GoalPatchRelation, ProtectedEvidenceLocator, ProtectedEvidenceRef, ReceiverContextProfileRef,
    validate_context_candidate_set, validate_context_delivery_boundaries,
    validate_context_selection_receipt, validate_context_validity_frontier,
    validate_protected_evidence_against_candidates, validate_receiver_context_profile,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextCompileError {
    Adaptive(AdaptivePolicyError),
    Contract(CognitionContractError),
    Delivery(ContextDeliveryError),
    EmptyField(&'static str),
    TokenBudgetExceeded,
    SelectionBindingMismatch,
    CandidateSetRevisionMismatch,
    SelectorPolicyMismatch,
    ProtectedEvidenceExcluded { field_ref: String, item_ref: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextCompileInput {
    pub compilation_id: String,
    pub version: u64,
    pub tenant_ref: String,
    pub principal_context_ref: String,
    pub purpose_ref: String,
    pub candidate_set_revision_ref: String,
    pub candidates: Vec<ContextCandidateDescriptor>,
    pub delivery_boundaries: Vec<ContextDeliveryBoundary>,
    pub protected_evidence: Vec<ProtectedEvidenceRef>,
    pub validity_frontier: ContextValidityFrontier,
    pub receiver_profile: ReceiverContextProfileRef,
    pub unresolved_gaps: BTreeSet<String>,
    pub excluded_but_needed_evidence_refs: BTreeSet<String>,
    pub effect_refs: BTreeSet<String>,
    pub obligation_refs: BTreeSet<String>,
    pub token_budget_requested: Option<u64>,
    pub token_budget_used: Option<u64>,
    pub selector_policy: AdaptivePolicyRef,
    pub resource_budget_ref: Option<String>,
}

/// One canonical evidence-bearing, reversible context compilation record.
/// Selection records inclusion/exclusion without replacing exact source or
/// granting executable authority. Final protected use still needs current
/// frontier validation and independent fidelity evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextCompilation {
    pub compilation_id: String,
    pub version: u64,
    pub tenant_ref: String,
    pub principal_context_ref: String,
    pub purpose_ref: String,
    pub candidate_set_revision_ref: String,
    pub candidates: Vec<ContextCandidateDescriptor>,
    pub delivery_boundaries: Vec<ContextDeliveryBoundary>,
    pub protected_evidence: Vec<ProtectedEvidenceRef>,
    pub validity_frontier: ContextValidityFrontier,
    pub receiver_profile: ReceiverContextProfileRef,
    pub unresolved_gaps: BTreeSet<String>,
    pub excluded_but_needed_evidence_refs: BTreeSet<String>,
    pub effect_refs: BTreeSet<String>,
    pub obligation_refs: BTreeSet<String>,
    pub token_budget_requested: Option<u64>,
    pub token_budget_used: Option<u64>,
    pub selection_receipt: ContextSelectionReceipt,
}

impl ContextCompilation {
    pub fn selected_item_refs(&self) -> BTreeSet<&str> {
        self.selection_receipt
            .dispositions
            .iter()
            .filter_map(|disposition| match disposition {
                ContextSelectionDisposition::Selected { item_ref, .. } => Some(item_ref.as_str()),
                ContextSelectionDisposition::Excluded { .. } => None,
            })
            .collect()
    }

    pub fn excluded_item_refs(&self) -> BTreeSet<&str> {
        self.selection_receipt
            .dispositions
            .iter()
            .filter_map(|disposition| match disposition {
                ContextSelectionDisposition::Excluded { item_ref, .. } => Some(item_ref.as_str()),
                ContextSelectionDisposition::Selected { .. } => None,
            })
            .collect()
    }
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

pub struct ContextCompiler<S> {
    selector: S,
}

impl<S> ContextCompiler<S>
where
    S: ContextSelector,
{
    pub const fn new(selector: S) -> Self {
        Self { selector }
    }

    pub fn compile(
        &self,
        input: ContextCompileInput,
    ) -> Result<ContextCompilation, ContextCompileError> {
        for (name, value) in [
            ("compilation_id", input.compilation_id.as_str()),
            ("tenant_ref", input.tenant_ref.as_str()),
            (
                "principal_context_ref",
                input.principal_context_ref.as_str(),
            ),
            ("purpose_ref", input.purpose_ref.as_str()),
            (
                "candidate_set_revision_ref",
                input.candidate_set_revision_ref.as_str(),
            ),
            (
                "selector_policy.policy_ref",
                input.selector_policy.policy_ref.as_str(),
            ),
            (
                "selector_policy.version",
                input.selector_policy.version.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ContextCompileError::EmptyField(name));
            }
        }
        if input.selector_policy.qualification_evidence_refs.is_empty()
            || input
                .selector_policy
                .qualification_evidence_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(ContextCompileError::EmptyField(
                "selector_policy.qualification_evidence_refs",
            ));
        }
        if let (Some(requested), Some(used)) =
            (input.token_budget_requested, input.token_budget_used)
            && used > requested
        {
            return Err(ContextCompileError::TokenBudgetExceeded);
        }

        validate_context_candidate_set(&input.candidates, &input.tenant_ref, &input.purpose_ref)
            .map_err(ContextCompileError::Contract)?;
        validate_context_delivery_boundaries(&input.candidates, &input.delivery_boundaries)
            .map_err(ContextCompileError::Delivery)?;
        validate_context_validity_frontier(&input.validity_frontier)
            .map_err(ContextCompileError::Contract)?;
        validate_receiver_context_profile(&input.receiver_profile)
            .map_err(ContextCompileError::Contract)?;
        for protected in &input.protected_evidence {
            validate_protected_evidence_against_candidates(protected, &input.candidates)
                .map_err(ContextCompileError::Contract)?;
        }

        let request = ContextSelectionRequest {
            tenant_ref: input.tenant_ref.clone(),
            principal_context_ref: input.principal_context_ref.clone(),
            purpose_ref: input.purpose_ref.clone(),
            candidate_set_revision_ref: input.candidate_set_revision_ref.clone(),
            candidates: input.candidates.clone(),
            delivery_boundaries: input.delivery_boundaries.clone(),
            protected_evidence: input.protected_evidence.clone(),
            validity_frontier: input.validity_frontier.clone(),
            receiver_profile: input.receiver_profile.clone(),
            unresolved_gap_refs: input.unresolved_gaps.clone(),
            selector_policy: input.selector_policy.clone(),
            resource_budget_ref: input.resource_budget_ref.clone(),
        };
        let expected_binding = request.binding();

        let bound_receipt = self
            .selector
            .propose_selection(&request)
            .map_err(ContextCompileError::Adaptive)?;
        if bound_receipt.binding != expected_binding {
            return Err(ContextCompileError::SelectionBindingMismatch);
        }
        let receipt = bound_receipt.receipt;

        validate_context_selection_receipt(&input.candidates, &receipt)
            .map_err(ContextCompileError::Contract)?;
        if receipt.candidate_set_revision_ref != input.candidate_set_revision_ref {
            return Err(ContextCompileError::CandidateSetRevisionMismatch);
        }
        if receipt.selector_policy != input.selector_policy {
            return Err(ContextCompileError::SelectorPolicyMismatch);
        }

        let selected: BTreeSet<&str> = receipt
            .dispositions
            .iter()
            .filter_map(|disposition| match disposition {
                ContextSelectionDisposition::Selected { item_ref, .. } => Some(item_ref.as_str()),
                ContextSelectionDisposition::Excluded { .. } => None,
            })
            .collect();

        for protected in &input.protected_evidence {
            for locator in &protected.proving_evidence {
                let Some(item_ref) = protected_locator_item_ref(locator, &input.candidates) else {
                    return Err(ContextCompileError::Contract(
                        CognitionContractError::ProtectedEvidenceLocatorMismatch,
                    ));
                };
                if !selected.contains(item_ref) {
                    return Err(ContextCompileError::ProtectedEvidenceExcluded {
                        field_ref: protected.field_ref.clone(),
                        item_ref: item_ref.to_owned(),
                    });
                }
            }
        }

        Ok(ContextCompilation {
            compilation_id: input.compilation_id,
            version: input.version,
            tenant_ref: input.tenant_ref,
            principal_context_ref: input.principal_context_ref,
            purpose_ref: input.purpose_ref,
            candidate_set_revision_ref: input.candidate_set_revision_ref,
            candidates: input.candidates,
            delivery_boundaries: input.delivery_boundaries,
            protected_evidence: input.protected_evidence,
            validity_frontier: input.validity_frontier,
            receiver_profile: input.receiver_profile,
            unresolved_gaps: input.unresolved_gaps,
            excluded_but_needed_evidence_refs: input.excluded_but_needed_evidence_refs,
            effect_refs: input.effect_refs,
            obligation_refs: input.obligation_refs,
            token_budget_requested: input.token_budget_requested,
            token_budget_used: input.token_budget_used,
            selection_receipt: receipt,
        })
    }
}

pub const fn patch_invalidates_existing_context(relation: GoalPatchRelation) -> bool {
    matches!(
        relation,
        GoalPatchRelation::Add
            | GoalPatchRelation::Clarify
            | GoalPatchRelation::Correct
            | GoalPatchRelation::Supersede
    )
}
