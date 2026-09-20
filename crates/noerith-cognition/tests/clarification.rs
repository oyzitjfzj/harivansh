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
        protected_evidence: Vec::new(),
        validity_frontier: frontier(),
        receiver_profile: ReceiverContextProfileRef {
            receiver_ref: "model-a".into(),
            receiver_version: "model@7".into(),
            context_profile_ref: "context-profile@3".into(),
            qualification_evidence_refs: set(&["position-load-eval@3"]),
        },
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

struct FidelityVerifier;

impl IndependentFidelityVerifier for FidelityVerifier {
    fn evaluate(
        &self,
        request: &ContextFidelityRequest<'_>,
    ) -> Result<ContextFidelityReport, AdaptivePolicyError> {
        Ok(ContextFidelityReport {
            report_id: "fidelity-a".into(),
            binding: request.binding.clone(),
            checked_item_refs: set(&["exact-a"]),
            protected_checks: Vec::new(),
            findings: Vec::new(),
            verdict: ContextFidelityVerdict::Sufficient,
            verifier_policy: policy("fidelity-verifier"),
            verifier_evidence_refs: set(&["fidelity-evidence"]),
            independence_evidence_refs: set(&["independence-evidence"]),
        })
    }
}

struct FrontierAuthority {
    frontiers: VecDeque<ContextValidityFrontier>,
}

impl ContextFrontierAuthority for FrontierAuthority {
    fn current_frontier(
        &mut self,
        _binding: &ContextFidelityBinding,
    ) -> Result<ContextValidityFrontier, ContextFrontierError> {
        self.frontiers
            .pop_front()
            .ok_or(ContextFrontierError::Unavailable)
    }
}

fn verified_fidelity() -> VerifiedContextFidelity {
    let packet = compilation();
    let mut authority = FrontierAuthority {
        frontiers: VecDeque::from([frontier(), frontier()]),
    };
    ContextFidelityGuard::new(FidelityVerifier)
        .verify(&packet, &mut authority)
        .unwrap()
}

fn ambiguity() -> AmbiguityClaim {
    AmbiguityClaim {
        ambiguity_ref: "recipient-ambiguity".into(),
        affected_field_refs: set(&["target-principal"]),
        candidate_interpretation_refs: set(&["recipient-alice", "recipient-alicia"]),
        missing_information_refs: BTreeSet::new(),
        evidence_refs: set(&["two-matching-contacts"]),
    }
}

fn request(verified: &VerifiedContextFidelity) -> GroundingRequest {
    GroundingRequest {
        request_ref: "grounding-a".into(),
        goal: verified.binding().validity_frontier.goal.clone(),
        work: verified.binding().validity_frontier.work.clone(),
        fidelity_report_ref: verified.report_id().into(),
        fidelity_binding: verified.binding().clone(),
        fidelity_verdict: verified.verdict(),
        fidelity_evidence_refs: verified.verifier_evidence_refs().clone(),
        foresight_evidence_refs: set(&["consequence-analysis-a"]),
        authority_evidence_refs: set(&["authority-view-a"]),
        ambiguities: vec![ambiguity()],
        protected_requirements: Vec::new(),
        interaction_profile_ref: "voice-short-choice@2".into(),
        prior_question_refs: BTreeSet::new(),
        grounding_policy: policy("grounding-policy"),
    }
}

fn base_proposal(
    request: &GroundingRequest,
    disposition: GroundingDisposition,
) -> GroundingProposal {
    GroundingProposal {
        proposal_ref: "grounding-proposal-a".into(),
        binding: request.binding().unwrap(),
        disposition,
        policy: request.grounding_policy.clone(),
        decision_evidence_refs: set(&["grounding-decision-evidence"]),
    }
}

struct AskPolicy;

impl GroundingPolicy for AskPolicy {
    fn propose(
        &self,
        request: &GroundingRequest,
    ) -> Result<GroundingProposal, AdaptivePolicyError> {
        Ok(base_proposal(
            request,
            GroundingDisposition::Ask {
                question: ClarificationQuestion {
                    question_ref: "question-a".into(),
                    ambiguity_refs: set(&["recipient-ambiguity"]),
                    prompt_ref: "which-recipient".into(),
                    answer_schema_ref: "recipient-choice-schema@1".into(),
                    interaction_profile_ref: request.interaction_profile_ref.clone(),
                    prior_question_refs: request.prior_question_refs.clone(),
                    evidence_refs: set(&["question-targeting-evidence"]),
                },
            },
        ))
    }
}

#[test]
fn s04_clarification_ask_is_bound_to_guard_verified_fidelity() {
    let verified = verified_fidelity();
    let request = request(&verified);
    let proposal = ClarificationGate::new(AskPolicy)
        .propose(&request, &verified)
        .unwrap();
    assert!(proposal.question().is_some());
    assert!(verified_grounding_has_no_effect_commit_authority(&proposal));
}

#[test]
fn s04_clarification_rejects_forged_fidelity_snapshot_before_policy() {
    let verified = verified_fidelity();
    let mut request = request(&verified);
    request.fidelity_report_ref = "forged-report".into();
    assert_eq!(
        ClarificationGate::new(AskPolicy).propose(&request, &verified),
        Err(ClarificationError::FidelityEvidenceMismatch)
    );
}

struct ProtectedProceedPolicy;

impl GroundingPolicy for ProtectedProceedPolicy {
    fn propose(
        &self,
        request: &GroundingRequest,
    ) -> Result<GroundingProposal, AdaptivePolicyError> {
        Ok(base_proposal(
            request,
            GroundingDisposition::ProceedReversible {
                allowed_scope_refs: set(&["send-message-effect"]),
                reversibility_evidence_refs: set(&["claimed-reversible"]),
            },
        ))
    }
}

#[test]
fn s04_protected_ambiguity_cannot_be_guessed_across_blocked_scope() {
    let verified = verified_fidelity();
    let mut request = request(&verified);
    request
        .protected_requirements
        .push(ProtectedResolutionRequirement {
            requirement_ref: "must-resolve-recipient".into(),
            ambiguity_refs: set(&["recipient-ambiguity"]),
            blocked_scope_refs: set(&["send-message-effect"]),
            evidence_refs: set(&["effect-target-is-protected"]),
        });
    assert_eq!(
        ClarificationGate::new(ProtectedProceedPolicy).propose(&request, &verified),
        Err(ClarificationError::ProceedCrossesProtectedRequirement)
    );
}

struct ReversiblePolicy;

impl GroundingPolicy for ReversiblePolicy {
    fn propose(
        &self,
        request: &GroundingRequest,
    ) -> Result<GroundingProposal, AdaptivePolicyError> {
        Ok(base_proposal(
            request,
            GroundingDisposition::ProceedReversible {
                allowed_scope_refs: set(&["draft-only"]),
                reversibility_evidence_refs: set(&["local-unpublished-draft"]),
            },
        ))
    }
}

#[test]
fn s04_nonblocked_reversible_work_can_continue_without_overquestioning() {
    let verified = verified_fidelity();
    let mut request = request(&verified);
    request
        .protected_requirements
        .push(ProtectedResolutionRequirement {
            requirement_ref: "must-resolve-before-send".into(),
            ambiguity_refs: set(&["recipient-ambiguity"]),
            blocked_scope_refs: set(&["send-message-effect"]),
            evidence_refs: set(&["effect-target-is-protected"]),
        });
    assert!(
        ClarificationGate::new(ReversiblePolicy)
            .propose(&request, &verified)
            .is_ok()
    );
}

struct AssumptionPolicy;

impl GroundingPolicy for AssumptionPolicy {
    fn propose(
        &self,
        request: &GroundingRequest,
    ) -> Result<GroundingProposal, AdaptivePolicyError> {
        Ok(base_proposal(
            request,
            GroundingDisposition::ProceedWithAssumptions {
                assumptions: vec![GroundingAssumption {
                    assumption_ref: "assumption-a".into(),
                    ambiguity_refs: set(&["recipient-ambiguity"]),
                    assumed_interpretation_refs: set(&["recipient-alice"]),
                    bounded_scope_refs: set(&["draft-only"]),
                    expiry_or_revalidation_ref: "before-send-or-correction".into(),
                    evidence_refs: set(&["assumption-visible"]),
                }],
                allowed_scope_refs: set(&["draft-only"]),
            },
        ))
    }
}

#[test]
fn s04_safe_assumption_stays_explicit_bounded_and_expiring() {
    let verified = verified_fidelity();
    let request = request(&verified);
    let proposal = ClarificationGate::new(AssumptionPolicy)
        .propose(&request, &verified)
        .unwrap();
    let GroundingDisposition::ProceedWithAssumptions { assumptions, .. } = proposal.disposition()
    else {
        panic!("expected bounded assumption")
    };
    assert_eq!(
        assumptions[0].expiry_or_revalidation_ref,
        "before-send-or-correction"
    );
}

struct UnknownAssumptionPolicy;

impl GroundingPolicy for UnknownAssumptionPolicy {
    fn propose(
        &self,
        request: &GroundingRequest,
    ) -> Result<GroundingProposal, AdaptivePolicyError> {
        let mut proposal = AssumptionPolicy.propose(request)?;
        let GroundingDisposition::ProceedWithAssumptions { assumptions, .. } =
            &mut proposal.disposition
        else {
            unreachable!()
        };
        assumptions[0].assumed_interpretation_refs = set(&["invented-recipient"]);
        Ok(proposal)
    }
}

#[test]
fn s04_assumption_cannot_invent_unregistered_interpretation() {
    let verified = verified_fidelity();
    let request = request(&verified);
    assert_eq!(
        ClarificationGate::new(UnknownAssumptionPolicy).propose(&request, &verified),
        Err(ClarificationError::AssumptionUnknownInterpretation)
    );
}

struct WrongChannelQuestionPolicy;

impl GroundingPolicy for WrongChannelQuestionPolicy {
    fn propose(
        &self,
        request: &GroundingRequest,
    ) -> Result<GroundingProposal, AdaptivePolicyError> {
        let mut proposal = AskPolicy.propose(request)?;
        let GroundingDisposition::Ask { question } = &mut proposal.disposition else {
            unreachable!()
        };
        question.interaction_profile_ref = "visual-grid-only".into();
        Ok(proposal)
    }
}

#[test]
fn s04_question_must_match_qualified_accessibility_profile() {
    let verified = verified_fidelity();
    let request = request(&verified);
    assert_eq!(
        ClarificationGate::new(WrongChannelQuestionPolicy).propose(&request, &verified),
        Err(ClarificationError::QuestionAccessibilityMismatch)
    );
}

struct ReplayedQuestionPolicy;

impl GroundingPolicy for ReplayedQuestionPolicy {
    fn propose(
        &self,
        request: &GroundingRequest,
    ) -> Result<GroundingProposal, AdaptivePolicyError> {
        AskPolicy.propose(request)
    }
}

#[test]
fn s04_exact_question_id_cannot_loop_as_if_new() {
    let verified = verified_fidelity();
    let mut request = request(&verified);
    request.prior_question_refs.insert("question-a".into());
    assert_eq!(
        ClarificationGate::new(ReplayedQuestionPolicy).propose(&request, &verified),
        Err(ClarificationError::QuestionReplay)
    );
}

#[test]
fn s04_answer_is_bound_to_current_question_and_resolves_only_named_ambiguities() {
    let verified = verified_fidelity();
    let request = request(&verified);
    let proposal = ClarificationGate::new(AskPolicy)
        .propose(&request, &verified)
        .unwrap();
    let answer = ClarificationAnswerEvidence {
        answer_ref: "answer-a".into(),
        question_ref: "question-a".into(),
        binding: request.binding().unwrap(),
        source_event_ref: "authenticated-user-turn@44".into(),
        resolved_ambiguity_refs: set(&["recipient-ambiguity"]),
        evidence_refs: set(&["exact-user-answer-span"]),
    };
    assert!(validate_clarification_answer(&request, &verified, &proposal, &answer).is_ok());

    let mut forged = answer;
    forged
        .resolved_ambiguity_refs
        .insert("other-ambiguity".into());
    assert_eq!(
        validate_clarification_answer(&request, &verified, &proposal, &forged),
        Err(ClarificationError::AnswerUnknownAmbiguity)
    );
}

#[test]
fn s04_old_answer_cannot_apply_after_goal_revision_changes() {
    let verified = verified_fidelity();
    let request = request(&verified);
    let proposal = ClarificationGate::new(AskPolicy)
        .propose(&request, &verified)
        .unwrap();
    let answer = ClarificationAnswerEvidence {
        answer_ref: "answer-a".into(),
        question_ref: "question-a".into(),
        binding: request.binding().unwrap(),
        source_event_ref: "authenticated-user-turn@44".into(),
        resolved_ambiguity_refs: set(&["recipient-ambiguity"]),
        evidence_refs: set(&["exact-user-answer-span"]),
    };
    let mut changed_request = request;
    changed_request.goal.version += 1;
    assert_eq!(
        validate_clarification_answer(&changed_request, &verified, &proposal, &answer),
        Err(ClarificationError::FidelityGoalWorkMismatch)
    );
}
