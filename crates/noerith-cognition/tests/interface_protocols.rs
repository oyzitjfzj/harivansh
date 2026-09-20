use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn versioned(reference: &str, version: u64) -> VersionedRef {
    VersionedRef {
        reference: reference.into(),
        version,
    }
}

fn policy(name: &str) -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: name.into(),
        version: "qualified-2026-09".into(),
        qualification_evidence_refs: set(&["heldout-policy-evidence"]),
    }
}

fn selection_binding() -> ContextSelectionBinding {
    ContextSelectionBinding {
        tenant_ref: "tenant-a".into(),
        principal_context_ref: "principal-a@4".into(),
        purpose_ref: "purpose-a".into(),
        candidate_set_revision_ref: "candidate-set@9".into(),
        validity_frontier: ContextValidityFrontier {
            goal: versioned("goal-a", 3),
            work: versioned("work-a", 5),
            correction_frontier_ref: "correction@7".into(),
            policy_authority_epoch_ref: "authority@4".into(),
            dependency_refs: set(&["source@8"]),
        },
        receiver_profile: ReceiverContextProfileRef {
            receiver_ref: "model-a".into(),
            receiver_version: "m7".into(),
            context_profile_ref: "context-profile@6".into(),
            qualification_evidence_refs: set(&["receiver-heldout"]),
        },
        selector_policy: policy("selector-policy"),
    }
}

#[test]
fn s04_rerank_is_only_a_bound_permutation_of_the_selected_set() {
    let request = ContextRerankRequest {
        selection_binding: selection_binding(),
        selected_candidate_refs: set(&["item-a", "item-b"]),
        protected_candidate_refs: set(&["item-a"]),
        reranker_policy: policy("reranker-policy"),
    };
    let result = BoundContextRerankProposal {
        binding: request.binding(),
        proposal: ContextRerankProposal {
            ordered_candidate_refs: vec!["item-b".into(), "item-a".into()],
            decision_evidence_refs: set(&["ordering-evidence"]),
        },
    };
    assert_eq!(result.validate_for(&request), Ok(()));
}

#[test]
fn s04_rerank_cannot_drop_duplicate_or_replay_across_receiver_frontier() {
    let request = ContextRerankRequest {
        selection_binding: selection_binding(),
        selected_candidate_refs: set(&["item-a", "item-b"]),
        protected_candidate_refs: set(&["item-a"]),
        reranker_policy: policy("reranker-policy"),
    };
    let duplicate = BoundContextRerankProposal {
        binding: request.binding(),
        proposal: ContextRerankProposal {
            ordered_candidate_refs: vec!["item-a".into(), "item-a".into()],
            decision_evidence_refs: set(&["ordering-evidence"]),
        },
    };
    assert_eq!(
        duplicate.validate_for(&request),
        Err(AdaptiveProposalProtocolError::RerankCandidateSetMismatch)
    );

    let valid = BoundContextRerankProposal {
        binding: request.binding(),
        proposal: ContextRerankProposal {
            ordered_candidate_refs: vec!["item-a".into(), "item-b".into()],
            decision_evidence_refs: set(&["ordering-evidence"]),
        },
    };
    let mut changed_receiver = request.clone();
    changed_receiver
        .selection_binding
        .receiver_profile
        .receiver_version = "m8".into();
    assert_eq!(
        valid.validate_for(&changed_receiver),
        Err(AdaptiveProposalProtocolError::BindingMismatch)
    );
}

fn progress() -> ProgressEvidence {
    ProgressEvidence {
        evidence_ref: "progress-evidence-a".into(),
        task_ref: "task-a".into(),
        kind: ProgressKind::MilestoneVerified,
        source_refs: set(&["verification-run-a"]),
    }
}

fn trajectory_request() -> TrajectoryEvaluationRequest {
    TrajectoryEvaluationRequest {
        previous_checkpoint_ref: Some("checkpoint-previous".into()),
        original_goal: versioned("goal-a", 1),
        current_goal: versioned("goal-a", 3),
        current_work: versioned("work-a", 5),
        accepted_correction_refs: set(&["correction@7"]),
        current_policy_refs: set(&["policy@9"]),
        current_authority_refs: set(&["authority@4"]),
        effect_refs: set(&["effect-a"]),
        progress_evidence: vec![progress()],
        unresolved_assumption_refs: set(&["assumption-a"]),
        evaluator_policy: policy("trajectory-policy"),
    }
}

fn trajectory_result(request: &TrajectoryEvaluationRequest) -> BoundTrajectoryCheckpoint {
    BoundTrajectoryCheckpoint {
        binding: request.binding(),
        checkpoint: TrajectoryCheckpoint {
            checkpoint_id: "checkpoint-current".into(),
            original_goal_revision: request.original_goal.clone(),
            current_goal_revision: request.current_goal.clone(),
            correction_refs: request.accepted_correction_refs.clone(),
            policy_revision_refs: request.current_policy_refs.clone(),
            authority_revision_refs: request.current_authority_refs.clone(),
            planned_effect_refs: set(&["effect-a"]),
            attempted_effect_refs: set(&["effect-a"]),
            accepted_effect_refs: set(&["effect-a"]),
            observed_effect_refs: BTreeSet::new(),
            obligation_refs: set(&["obligation-a"]),
            unresolved_assumption_refs: request.unresolved_assumption_refs.clone(),
            progress_evidence: request.progress_evidence.clone(),
            divergence_evidence_refs: BTreeSet::new(),
            affected_scope_refs: set(&["work-a"]),
            verdict: TrajectoryVerdict::Continue,
            next_permitted_step_ref: Some("task-next".into()),
            evaluator_policy: request.evaluator_policy.clone(),
        },
        decision_evidence_refs: set(&["trajectory-decision-evidence"]),
    }
}

#[test]
fn s04_trajectory_output_is_bound_to_exact_goal_work_policy_authority_frontier() {
    let request = trajectory_request();
    let result = trajectory_result(&request);
    assert_eq!(result.validate_for(&request), Ok(()));

    let mut corrected = request.clone();
    corrected.current_goal.version += 1;
    assert_eq!(
        result.validate_for(&corrected),
        Err(AdaptiveProposalProtocolError::BindingMismatch)
    );
}

#[test]
fn s04_trajectory_cannot_invent_impossible_effect_causality() {
    let request = trajectory_request();
    let mut result = trajectory_result(&request);
    result.checkpoint.attempted_effect_refs.clear();
    assert_eq!(
        result.validate_for(&request),
        Err(AdaptiveProposalProtocolError::TrajectoryEffectMismatch)
    );
}

fn goal_patch(relation: GoalPatchRelation) -> GoalPatch {
    GoalPatch {
        patch_id: "patch-a".into(),
        base_goal_revision: versioned("goal-a", 3),
        relation,
        proposed_delta_ref: "delta-a".into(),
        exact_source_refs: set(&["message-user-a"]),
        affected_work_refs: set(&["work-a"]),
        affected_plan_refs: set(&["plan-a"]),
        affected_context_refs: set(&["context-a"]),
        acceptance_evidence_refs: set(&["accepted-user-evidence"]),
        resulting_goal_revision: None,
    }
}

fn patch_request(relation: GoalPatchRelation) -> GoalPatchEvaluationRequest {
    GoalPatchEvaluationRequest {
        patch: goal_patch(relation),
        current_goal: versioned("goal-a", 3),
        current_constitution_fingerprint_ref: "constitution:fp3".into(),
        exact_source_refs: set(&["message-user-a"]),
        evaluator_policy: policy("goal-patch-policy"),
    }
}

#[test]
fn s04_goal_patch_disposition_is_exact_constitution_bound_proposal_only() {
    let request = patch_request(GoalPatchRelation::Correct);
    let result = BoundGoalPatchProposalDisposition {
        binding: request.binding(),
        disposition: GoalPatchProposalDisposition::AcceptCandidate,
        decision_evidence_refs: set(&["classification-evidence"]),
    };
    assert_eq!(result.validate_for(&request), Ok(()));

    let mut changed_head = request.clone();
    changed_head.current_constitution_fingerprint_ref = "constitution:fp4".into();
    assert_eq!(
        result.validate_for(&changed_head),
        Err(AdaptiveProposalProtocolError::BindingMismatch)
    );
}

#[test]
fn s04_goal_patch_semantic_disposition_cannot_confuse_independent_with_mutation() {
    let independent = patch_request(GoalPatchRelation::Independent);
    let wrong = BoundGoalPatchProposalDisposition {
        binding: independent.binding(),
        disposition: GoalPatchProposalDisposition::AcceptCandidate,
        decision_evidence_refs: set(&["classification-evidence"]),
    };
    assert_eq!(
        wrong.validate_for(&independent),
        Err(AdaptiveProposalProtocolError::GoalPatchDispositionMismatch)
    );

    let correct = BoundGoalPatchProposalDisposition {
        binding: independent.binding(),
        disposition: GoalPatchProposalDisposition::KeepIndependent,
        decision_evidence_refs: set(&["classification-evidence"]),
    };
    assert_eq!(correct.validate_for(&independent), Ok(()));
}
