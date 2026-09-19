use crate::{
    AdaptivePolicyError, AdaptivePolicyRef, ContextFidelityBinding, ContextFidelityVerdict,
    VerifiedContextFidelity, VersionedRef,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguityClaim {
    pub ambiguity_ref: String,
    pub affected_field_refs: BTreeSet<String>,
    pub candidate_interpretation_refs: BTreeSet<String>,
    pub missing_information_refs: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResolutionRequirement {
    pub requirement_ref: String,
    pub ambiguity_refs: BTreeSet<String>,
    pub blocked_scope_refs: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguityBinding {
    pub affected_field_refs: BTreeSet<String>,
    pub candidate_interpretation_refs: BTreeSet<String>,
    pub missing_information_refs: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionRequirementBinding {
    pub ambiguity_refs: BTreeSet<String>,
    pub blocked_scope_refs: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
}

/// Exact state on which one grounding decision is based. This is proposal
/// scope/evidence, never an authority token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundingBinding {
    pub request_ref: String,
    pub goal: VersionedRef,
    pub work: VersionedRef,
    pub fidelity_report_ref: String,
    pub fidelity_binding: ContextFidelityBinding,
    pub fidelity_verdict: ContextFidelityVerdict,
    pub fidelity_evidence_refs: BTreeSet<String>,
    pub foresight_evidence_refs: BTreeSet<String>,
    pub authority_evidence_refs: BTreeSet<String>,
    pub ambiguities: BTreeMap<String, AmbiguityBinding>,
    pub protected_requirements: BTreeMap<String, ResolutionRequirementBinding>,
    pub interaction_profile_ref: String,
    pub prior_question_refs: BTreeSet<String>,
    pub grounding_policy: AdaptivePolicyRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundingRequest {
    pub request_ref: String,
    pub goal: VersionedRef,
    pub work: VersionedRef,
    pub fidelity_report_ref: String,
    pub fidelity_binding: ContextFidelityBinding,
    pub fidelity_verdict: ContextFidelityVerdict,
    pub fidelity_evidence_refs: BTreeSet<String>,
    pub foresight_evidence_refs: BTreeSet<String>,
    pub authority_evidence_refs: BTreeSet<String>,
    pub ambiguities: Vec<AmbiguityClaim>,
    pub protected_requirements: Vec<ProtectedResolutionRequirement>,
    pub interaction_profile_ref: String,
    pub prior_question_refs: BTreeSet<String>,
    pub grounding_policy: AdaptivePolicyRef,
}

impl GroundingRequest {
    pub fn binding(&self) -> Result<GroundingBinding, ClarificationError> {
        validate_request(self)?;

        let mut ambiguities = BTreeMap::new();
        for claim in &self.ambiguities {
            if ambiguities
                .insert(
                    claim.ambiguity_ref.clone(),
                    AmbiguityBinding {
                        affected_field_refs: claim.affected_field_refs.clone(),
                        candidate_interpretation_refs: claim.candidate_interpretation_refs.clone(),
                        missing_information_refs: claim.missing_information_refs.clone(),
                        evidence_refs: claim.evidence_refs.clone(),
                    },
                )
                .is_some()
            {
                return Err(ClarificationError::DuplicateAmbiguity);
            }
        }

        let mut protected_requirements = BTreeMap::new();
        for requirement in &self.protected_requirements {
            if protected_requirements
                .insert(
                    requirement.requirement_ref.clone(),
                    ResolutionRequirementBinding {
                        ambiguity_refs: requirement.ambiguity_refs.clone(),
                        blocked_scope_refs: requirement.blocked_scope_refs.clone(),
                        evidence_refs: requirement.evidence_refs.clone(),
                    },
                )
                .is_some()
            {
                return Err(ClarificationError::DuplicateProtectedRequirement);
            }
        }

        Ok(GroundingBinding {
            request_ref: self.request_ref.clone(),
            goal: self.goal.clone(),
            work: self.work.clone(),
            fidelity_report_ref: self.fidelity_report_ref.clone(),
            fidelity_binding: self.fidelity_binding.clone(),
            fidelity_verdict: self.fidelity_verdict,
            fidelity_evidence_refs: self.fidelity_evidence_refs.clone(),
            foresight_evidence_refs: self.foresight_evidence_refs.clone(),
            authority_evidence_refs: self.authority_evidence_refs.clone(),
            ambiguities,
            protected_requirements,
            interaction_profile_ref: self.interaction_profile_ref.clone(),
            prior_question_refs: self.prior_question_refs.clone(),
            grounding_policy: self.grounding_policy.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClarificationQuestion {
    pub question_ref: String,
    pub ambiguity_refs: BTreeSet<String>,
    pub prompt_ref: String,
    pub answer_schema_ref: String,
    pub interaction_profile_ref: String,
    pub prior_question_refs: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundingAssumption {
    pub assumption_ref: String,
    pub ambiguity_refs: BTreeSet<String>,
    pub assumed_interpretation_refs: BTreeSet<String>,
    pub bounded_scope_refs: BTreeSet<String>,
    pub expiry_or_revalidation_ref: String,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroundingDisposition {
    Ask {
        question: ClarificationQuestion,
    },
    Retrieve {
        evidence_need_refs: BTreeSet<String>,
    },
    ProceedWithAssumptions {
        assumptions: Vec<GroundingAssumption>,
        allowed_scope_refs: BTreeSet<String>,
    },
    ProceedReversible {
        allowed_scope_refs: BTreeSet<String>,
        reversibility_evidence_refs: BTreeSet<String>,
    },
    Defer {
        dependency_refs: BTreeSet<String>,
    },
    Escalate {
        reason_evidence_refs: BTreeSet<String>,
    },
    Block {
        reason_evidence_refs: BTreeSet<String>,
    },
}

/// Raw adaptive proposal. Downstream code should consume only the private-field
/// `VerifiedGroundingProposal` returned by `ClarificationGate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundingProposal {
    pub proposal_ref: String,
    pub binding: GroundingBinding,
    pub disposition: GroundingDisposition,
    pub policy: AdaptivePolicyRef,
    pub decision_evidence_refs: BTreeSet<String>,
}

pub trait GroundingPolicy {
    fn propose(&self, request: &GroundingRequest)
    -> Result<GroundingProposal, AdaptivePolicyError>;
}

/// Gate-issued proposal wrapper. It proves only that the adaptive proposal was
/// checked against the exact request and guard-issued fidelity evidence; it is
/// not permission to cross an external-effect boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGroundingProposal {
    proposal: GroundingProposal,
}

impl VerifiedGroundingProposal {
    pub fn proposal_ref(&self) -> &str {
        &self.proposal.proposal_ref
    }

    pub fn binding(&self) -> &GroundingBinding {
        &self.proposal.binding
    }

    pub fn disposition(&self) -> &GroundingDisposition {
        &self.proposal.disposition
    }

    pub fn question(&self) -> Option<&ClarificationQuestion> {
        match &self.proposal.disposition {
            GroundingDisposition::Ask { question } => Some(question),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClarificationAnswerEvidence {
    pub answer_ref: String,
    pub question_ref: String,
    pub binding: GroundingBinding,
    pub source_event_ref: String,
    pub resolved_ambiguity_refs: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClarificationError {
    Adaptive(AdaptivePolicyError),
    EmptyField(&'static str),
    InvalidPolicy,
    MissingFidelityEvidence,
    MissingForesightEvidence,
    MissingAuthorityEvidence,
    FidelityEvidenceMismatch,
    FidelityGoalWorkMismatch,
    DuplicateAmbiguity,
    InvalidAmbiguity,
    DuplicateProtectedRequirement,
    InvalidProtectedRequirement,
    ProtectedRequirementUnknownAmbiguity,
    BindingMismatch,
    PolicyMismatch,
    MissingDecisionEvidence,
    QuestionUnknownAmbiguity,
    QuestionReplay,
    QuestionAccessibilityMismatch,
    InvalidQuestion,
    InvalidAssumption,
    AssumptionUnknownAmbiguity,
    AssumptionUnknownInterpretation,
    DuplicateAssumption,
    ProceedCrossesProtectedRequirement,
    InvalidProceedScope,
    InvalidRetrieve,
    InvalidDefer,
    InvalidEscalation,
    AnswerBindingMismatch,
    AnswerQuestionMismatch,
    AnswerUnknownAmbiguity,
    InvalidAnswerEvidence,
}

pub struct ClarificationGate<P> {
    policy: P,
}

impl<P> ClarificationGate<P>
where
    P: GroundingPolicy,
{
    pub const fn new(policy: P) -> Self {
        Self { policy }
    }

    pub fn propose(
        &self,
        request: &GroundingRequest,
        verified_fidelity: &VerifiedContextFidelity,
    ) -> Result<VerifiedGroundingProposal, ClarificationError> {
        validate_verified_fidelity(request, verified_fidelity)?;
        let expected_binding = request.binding()?;
        let proposal = self
            .policy
            .propose(request)
            .map_err(ClarificationError::Adaptive)?;

        if proposal.binding != expected_binding {
            return Err(ClarificationError::BindingMismatch);
        }
        if proposal.policy != request.grounding_policy {
            return Err(ClarificationError::PolicyMismatch);
        }
        if proposal.proposal_ref.trim().is_empty()
            || !clean_nonempty_set(&proposal.decision_evidence_refs)
        {
            return Err(ClarificationError::MissingDecisionEvidence);
        }

        validate_disposition(request, &proposal.disposition)?;
        Ok(VerifiedGroundingProposal { proposal })
    }
}

pub fn validate_clarification_answer(
    current_request: &GroundingRequest,
    verified_fidelity: &VerifiedContextFidelity,
    question_proposal: &VerifiedGroundingProposal,
    answer: &ClarificationAnswerEvidence,
) -> Result<(), ClarificationError> {
    validate_verified_fidelity(current_request, verified_fidelity)?;
    let current_binding = current_request.binding()?;
    if question_proposal.binding() != &current_binding || answer.binding != current_binding {
        return Err(ClarificationError::AnswerBindingMismatch);
    }
    let Some(question) = question_proposal.question() else {
        return Err(ClarificationError::AnswerQuestionMismatch);
    };
    if answer.question_ref != question.question_ref {
        return Err(ClarificationError::AnswerQuestionMismatch);
    }
    if answer.answer_ref.trim().is_empty()
        || answer.source_event_ref.trim().is_empty()
        || !clean_nonempty_set(&answer.evidence_refs)
        || answer.resolved_ambiguity_refs.is_empty()
    {
        return Err(ClarificationError::InvalidAnswerEvidence);
    }
    if !answer
        .resolved_ambiguity_refs
        .is_subset(&question.ambiguity_refs)
    {
        return Err(ClarificationError::AnswerUnknownAmbiguity);
    }
    Ok(())
}

fn validate_verified_fidelity(
    request: &GroundingRequest,
    verified: &VerifiedContextFidelity,
) -> Result<(), ClarificationError> {
    if request.fidelity_report_ref != verified.report_id()
        || request.fidelity_binding != *verified.binding()
        || request.fidelity_verdict != verified.verdict()
        || request.fidelity_evidence_refs != *verified.verifier_evidence_refs()
    {
        return Err(ClarificationError::FidelityEvidenceMismatch);
    }
    if request.goal != verified.binding().validity_frontier.goal
        || request.work != verified.binding().validity_frontier.work
        || verified.validated_frontier() != &request.fidelity_binding.validity_frontier
    {
        return Err(ClarificationError::FidelityGoalWorkMismatch);
    }
    Ok(())
}

fn validate_request(request: &GroundingRequest) -> Result<(), ClarificationError> {
    for (name, value) in [
        ("grounding.request_ref", request.request_ref.as_str()),
        ("grounding.goal.reference", request.goal.reference.as_str()),
        ("grounding.work.reference", request.work.reference.as_str()),
        (
            "grounding.fidelity_report_ref",
            request.fidelity_report_ref.as_str(),
        ),
        (
            "grounding.interaction_profile_ref",
            request.interaction_profile_ref.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(ClarificationError::EmptyField(name));
        }
    }
    if !qualified_policy(&request.grounding_policy) {
        return Err(ClarificationError::InvalidPolicy);
    }
    if !clean_nonempty_set(&request.fidelity_evidence_refs) {
        return Err(ClarificationError::MissingFidelityEvidence);
    }
    if !clean_nonempty_set(&request.foresight_evidence_refs) {
        return Err(ClarificationError::MissingForesightEvidence);
    }
    if !clean_nonempty_set(&request.authority_evidence_refs) {
        return Err(ClarificationError::MissingAuthorityEvidence);
    }
    if request
        .prior_question_refs
        .iter()
        .any(|reference| reference.trim().is_empty())
    {
        return Err(ClarificationError::InvalidQuestion);
    }

    let mut ambiguity_refs = BTreeSet::new();
    for claim in &request.ambiguities {
        if claim.ambiguity_ref.trim().is_empty()
            || claim.affected_field_refs.is_empty()
            || claim
                .affected_field_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
            || (claim.candidate_interpretation_refs.is_empty()
                && claim.missing_information_refs.is_empty())
            || claim
                .candidate_interpretation_refs
                .iter()
                .chain(claim.missing_information_refs.iter())
                .any(|reference| reference.trim().is_empty())
            || !clean_nonempty_set(&claim.evidence_refs)
        {
            return Err(ClarificationError::InvalidAmbiguity);
        }
        if !ambiguity_refs.insert(claim.ambiguity_ref.as_str()) {
            return Err(ClarificationError::DuplicateAmbiguity);
        }
    }

    let mut requirement_refs = BTreeSet::new();
    for requirement in &request.protected_requirements {
        if requirement.requirement_ref.trim().is_empty()
            || requirement.ambiguity_refs.is_empty()
            || requirement.blocked_scope_refs.is_empty()
            || requirement
                .ambiguity_refs
                .iter()
                .chain(requirement.blocked_scope_refs.iter())
                .any(|reference| reference.trim().is_empty())
            || !clean_nonempty_set(&requirement.evidence_refs)
        {
            return Err(ClarificationError::InvalidProtectedRequirement);
        }
        if !requirement_refs.insert(requirement.requirement_ref.as_str()) {
            return Err(ClarificationError::DuplicateProtectedRequirement);
        }
        if requirement
            .ambiguity_refs
            .iter()
            .any(|reference| !ambiguity_refs.contains(reference.as_str()))
        {
            return Err(ClarificationError::ProtectedRequirementUnknownAmbiguity);
        }
    }
    Ok(())
}

fn validate_disposition(
    request: &GroundingRequest,
    disposition: &GroundingDisposition,
) -> Result<(), ClarificationError> {
    let ambiguity_by_ref: BTreeMap<&str, &AmbiguityClaim> = request
        .ambiguities
        .iter()
        .map(|claim| (claim.ambiguity_ref.as_str(), claim))
        .collect();
    let blocked_scopes: BTreeSet<&str> = request
        .protected_requirements
        .iter()
        .flat_map(|requirement| requirement.blocked_scope_refs.iter().map(String::as_str))
        .collect();

    match disposition {
        GroundingDisposition::Ask { question } => {
            if question.question_ref.trim().is_empty()
                || question.ambiguity_refs.is_empty()
                || question.prompt_ref.trim().is_empty()
                || question.answer_schema_ref.trim().is_empty()
                || question.prior_question_refs != request.prior_question_refs
                || !clean_nonempty_set(&question.evidence_refs)
            {
                return Err(ClarificationError::InvalidQuestion);
            }
            if question.interaction_profile_ref != request.interaction_profile_ref {
                return Err(ClarificationError::QuestionAccessibilityMismatch);
            }
            if question
                .ambiguity_refs
                .iter()
                .any(|reference| !ambiguity_by_ref.contains_key(reference.as_str()))
            {
                return Err(ClarificationError::QuestionUnknownAmbiguity);
            }
            if request.prior_question_refs.contains(&question.question_ref) {
                return Err(ClarificationError::QuestionReplay);
            }
        }
        GroundingDisposition::Retrieve { evidence_need_refs } => {
            if !clean_nonempty_set(evidence_need_refs) {
                return Err(ClarificationError::InvalidRetrieve);
            }
        }
        GroundingDisposition::ProceedWithAssumptions {
            assumptions,
            allowed_scope_refs,
        } => {
            validate_proceed_scope(allowed_scope_refs, &blocked_scopes)?;
            if assumptions.is_empty() {
                return Err(ClarificationError::InvalidAssumption);
            }
            let mut assumption_refs = BTreeSet::new();
            for assumption in assumptions {
                if assumption.assumption_ref.trim().is_empty()
                    || assumption.ambiguity_refs.is_empty()
                    || assumption.assumed_interpretation_refs.is_empty()
                    || assumption.bounded_scope_refs.is_empty()
                    || assumption.expiry_or_revalidation_ref.trim().is_empty()
                    || !clean_nonempty_set(&assumption.evidence_refs)
                    || !assumption.bounded_scope_refs.is_subset(allowed_scope_refs)
                {
                    return Err(ClarificationError::InvalidAssumption);
                }
                if !assumption_refs.insert(assumption.assumption_ref.as_str()) {
                    return Err(ClarificationError::DuplicateAssumption);
                }
                for ambiguity_ref in &assumption.ambiguity_refs {
                    let Some(claim) = ambiguity_by_ref.get(ambiguity_ref.as_str()) else {
                        return Err(ClarificationError::AssumptionUnknownAmbiguity);
                    };
                    if !claim.candidate_interpretation_refs.is_empty()
                        && !assumption
                            .assumed_interpretation_refs
                            .is_subset(&claim.candidate_interpretation_refs)
                    {
                        return Err(ClarificationError::AssumptionUnknownInterpretation);
                    }
                }
            }
        }
        GroundingDisposition::ProceedReversible {
            allowed_scope_refs,
            reversibility_evidence_refs,
        } => {
            validate_proceed_scope(allowed_scope_refs, &blocked_scopes)?;
            if !clean_nonempty_set(reversibility_evidence_refs) {
                return Err(ClarificationError::InvalidProceedScope);
            }
        }
        GroundingDisposition::Defer { dependency_refs } => {
            if !clean_nonempty_set(dependency_refs) {
                return Err(ClarificationError::InvalidDefer);
            }
        }
        GroundingDisposition::Escalate {
            reason_evidence_refs,
        }
        | GroundingDisposition::Block {
            reason_evidence_refs,
        } => {
            if !clean_nonempty_set(reason_evidence_refs) {
                return Err(ClarificationError::InvalidEscalation);
            }
        }
    }
    Ok(())
}

fn validate_proceed_scope(
    allowed_scope_refs: &BTreeSet<String>,
    blocked_scopes: &BTreeSet<&str>,
) -> Result<(), ClarificationError> {
    if !clean_nonempty_set(allowed_scope_refs) {
        return Err(ClarificationError::InvalidProceedScope);
    }
    if allowed_scope_refs
        .iter()
        .any(|scope| blocked_scopes.contains(scope.as_str()))
    {
        return Err(ClarificationError::ProceedCrossesProtectedRequirement);
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

/// Gate-issued grounding proposals are descriptive next-step evidence. They
/// contain no credential, grant, DecisionSnapshot or controlled-release token.
pub const fn verified_grounding_has_no_effect_commit_authority(
    _proposal: &VerifiedGroundingProposal,
) -> bool {
    true
}
