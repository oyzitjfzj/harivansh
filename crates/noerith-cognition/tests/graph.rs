use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn rev(version: u64) -> VersionedRef {
    VersionedRef {
        reference: "goal-a".into(),
        version,
    }
}

fn policy() -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: "scheduler-policy".into(),
        version: "qualified".into(),
        qualification_evidence_refs: set(&["scheduler-heldout"]),
    }
}

fn node(name: &str, protected: &[&str]) -> TaskNode {
    TaskNode {
        task_ref: name.into(),
        goal: rev(1),
        work: VersionedRef {
            reference: "work-a".into(),
            version: 1,
        },
        semantic_operation_ref: format!("operation-{name}"),
        required_capability_refs: BTreeSet::new(),
        required_evidence_refs: BTreeSet::new(),
        state_class_ref: "S2".into(),
        protected_aggregate_refs: set(protected),
        resource_envelope: ResourceEnvelope {
            resource_refs: BTreeSet::new(),
            placement_constraints: BTreeSet::new(),
            externally_calibrated_budget_ref: None,
        },
        timing: None,
        waiting_condition_ref: None,
        wake_condition_ref: None,
        permission_requirement_ref: None,
        blocker_refs: BTreeSet::new(),
        completion_test_ref: "completion-evidence".into(),
        trajectory_checkpoint_ref: None,
        interrupt_scope_ref: None,
        cancellation_scope_ref: None,
    }
}

fn graph(id: &str, nodes: Vec<TaskNode>, edges: Vec<TaskEdge>) -> TaskGraph {
    TaskGraph {
        graph_id: id.into(),
        revision: 1,
        nodes,
        edges,
        promise_refs: BTreeSet::new(),
        recurrence_revision_refs: BTreeSet::new(),
    }
}

fn scheduler_decision(ready_ref: &str, admitted: &[&str]) -> SchedulerDecision {
    SchedulerDecision {
        decision_id: "schedule-a".into(),
        ready_set_revision_ref: ready_ref.into(),
        admitted_task_refs: set(admitted),
        deferred_task_refs: BTreeSet::new(),
        preempted_task_refs: BTreeSet::new(),
        resource_reservation_refs: BTreeSet::new(),
        placement_reservation_refs: BTreeSet::new(),
        protected_conflict_evidence_refs: BTreeSet::new(),
        fairness_observation_refs: BTreeSet::new(),
        policy: policy(),
        decision_evidence_refs: set(&["scheduler-decision-evidence"]),
        reevaluation_trigger_refs: set(&["work-state-change"]),
    }
}

fn admit(execution: &mut ExecutionGraph, task_refs: &[&str]) {
    let snapshot = execution.ready_set_snapshot(&[]).unwrap();
    let decision = scheduler_decision(snapshot.snapshot_ref(), task_refs);
    execution
        .apply_scheduler_decision(&snapshot, &decision)
        .unwrap();
}

fn transition(
    execution: &mut ExecutionGraph,
    id: &str,
    task_ref: &str,
    from_state: TaskRuntimeState,
    to_state: TaskRuntimeState,
) -> Result<bool, ExecutionGraphError> {
    execution.apply_transition(TaskTransitionEvidence {
        transition_ref: id.into(),
        task_ref: task_ref.into(),
        graph_revision: execution.graph().revision,
        base_runtime_revision: execution.runtime_revision(),
        from_state,
        to_state,
        evidence_refs: set(&["state-transition-evidence"]),
    })
}

fn complete(execution: &mut ExecutionGraph, task_ref: &str) -> Result<bool, ExecutionGraphError> {
    execution.complete_task(CompletionWitness {
        witness_ref: format!("completion-witness-{task_ref}"),
        task_ref: task_ref.into(),
        completion_test_ref: "completion-evidence".into(),
        graph_revision: execution.graph().revision,
        base_runtime_revision: execution.runtime_revision(),
        evidence_refs: set(&["completion-test-passed"]),
    })
}

fn effect(
    execution: &mut ExecutionGraph,
    task_ref: &str,
    effect_ref: &str,
    milestone: EffectMilestone,
    suffix: &str,
) -> Result<bool, ExecutionGraphError> {
    execution.record_effect_milestone(EffectMilestoneWitness {
        witness_ref: format!("effect-witness-{effect_ref}-{suffix}"),
        task_ref: task_ref.into(),
        effect_ref: effect_ref.into(),
        milestone,
        graph_revision: execution.graph().revision,
        base_runtime_revision: execution.runtime_revision(),
        evidence_refs: set(&["effect-ledger-evidence"]),
    })
}

#[test]
fn s04_dependency_readiness_requires_evidenced_completion_not_naked_status() {
    let task_graph = graph(
        "graph-a",
        vec![node("research", &[]), node("build", &[])],
        vec![TaskEdge {
            from_task_ref: "research".into(),
            to_task_ref: "build".into(),
            kind: TaskEdgeKind::Dependency,
            evidence_refs: set(&["build-needs-research"]),
        }],
    );
    let mut execution = ExecutionGraph::new(task_graph).unwrap();
    assert_eq!(execution.dependency_ready_set(), set(&["research"]));
    admit(&mut execution, &["research"]);
    transition(
        &mut execution,
        "research-start",
        "research",
        TaskRuntimeState::Ready,
        TaskRuntimeState::Running,
    )
    .unwrap();
    assert_eq!(
        transition(
            &mut execution,
            "fake-complete",
            "research",
            TaskRuntimeState::Running,
            TaskRuntimeState::Completed,
        ),
        Err(ExecutionGraphError::CompletionRequiresWitness)
    );
    assert_eq!(execution.dependency_ready_set(), BTreeSet::new());
    complete(&mut execution, "research").unwrap();
    assert_eq!(execution.dependency_ready_set(), set(&["build"]));
}

#[test]
fn s04_direct_ready_transition_cannot_bypass_dependency_checks() {
    let task_graph = graph(
        "graph-bypass",
        vec![node("parent", &[]), node("child", &[])],
        vec![TaskEdge {
            from_task_ref: "parent".into(),
            to_task_ref: "child".into(),
            kind: TaskEdgeKind::Dependency,
            evidence_refs: set(&["child-needs-parent"]),
        }],
    );
    let mut execution = ExecutionGraph::new(task_graph).unwrap();
    assert_eq!(
        transition(
            &mut execution,
            "fake-ready",
            "child",
            TaskRuntimeState::Planned,
            TaskRuntimeState::Ready,
        ),
        Err(ExecutionGraphError::ReadyTransitionRequiresSnapshot)
    );
    let snapshot = execution.ready_set_snapshot(&[]).unwrap();
    assert!(!snapshot.ready_task_refs().contains("child"));
}

#[test]
fn s04_transition_evidence_is_exact_frontier_bound_and_replay_safe() {
    let mut execution =
        ExecutionGraph::new(graph("graph-transition", vec![node("a", &[])], Vec::new())).unwrap();
    admit(&mut execution, &["a"]);
    let evidence = TaskTransitionEvidence {
        transition_ref: "start-a".into(),
        task_ref: "a".into(),
        graph_revision: 1,
        base_runtime_revision: execution.runtime_revision(),
        from_state: TaskRuntimeState::Ready,
        to_state: TaskRuntimeState::Running,
        evidence_refs: set(&["worker-started"]),
    };
    assert_eq!(execution.apply_transition(evidence.clone()), Ok(true));
    assert_eq!(execution.apply_transition(evidence.clone()), Ok(false));

    let mut conflicting = evidence;
    conflicting.evidence_refs = set(&["different-proof"]);
    assert_eq!(
        execution.apply_transition(conflicting),
        Err(ExecutionGraphError::TransitionIdentityConflict)
    );

    let stale = TaskTransitionEvidence {
        transition_ref: "stale-a".into(),
        task_ref: "a".into(),
        graph_revision: 1,
        base_runtime_revision: 0,
        from_state: TaskRuntimeState::Running,
        to_state: TaskRuntimeState::Paused,
        evidence_refs: set(&["pause-request"]),
    };
    assert_eq!(
        execution.apply_transition(stale),
        Err(ExecutionGraphError::TransitionBindingMismatch)
    );
}

#[test]
fn s04_new_independent_work_does_not_pause_existing_running_work() {
    let task_graph = graph(
        "graph-independent",
        vec![node("background-build", &[]), node("new-conversation", &[])],
        Vec::new(),
    );
    let mut execution = ExecutionGraph::new(task_graph).unwrap();
    admit(&mut execution, &["background-build"]);
    transition(
        &mut execution,
        "start-background",
        "background-build",
        TaskRuntimeState::Ready,
        TaskRuntimeState::Running,
    )
    .unwrap();

    let snapshot = execution.ready_set_snapshot(&[]).unwrap();
    let decision = scheduler_decision(snapshot.snapshot_ref(), &["new-conversation"]);
    execution
        .apply_scheduler_decision(&snapshot, &decision)
        .unwrap();
    assert_eq!(
        execution.state("background-build").unwrap(),
        TaskRuntimeState::Running
    );
    assert_eq!(
        execution.state("new-conversation").unwrap(),
        TaskRuntimeState::Ready
    );
}

#[test]
fn s04_scheduler_cannot_admit_two_tasks_that_touch_same_protected_aggregate() {
    let task_graph = graph(
        "graph-conflict",
        vec![
            node("writer-a", &["account-state"]),
            node("writer-b", &["account-state"]),
        ],
        Vec::new(),
    );
    let mut execution = ExecutionGraph::new(task_graph).unwrap();
    let snapshot = execution.ready_set_snapshot(&[]).unwrap();
    assert_eq!(
        execution.apply_scheduler_decision(
            &snapshot,
            &scheduler_decision(snapshot.snapshot_ref(), &["writer-a", "writer-b"])
        ),
        Err(ExecutionGraphError::SchedulerCreatesProtectedConflict)
    );
}

#[test]
fn s04_waiting_task_requires_exact_current_wake_witness() {
    let mut task = node("await-reply", &[]);
    task.waiting_condition_ref = Some("waiting:user-reply".into());
    task.wake_condition_ref = Some("event:user-reply".into());
    let mut execution = ExecutionGraph::new(graph("graph-wake", vec![task], Vec::new())).unwrap();

    admit(&mut execution, &["await-reply"]);
    transition(
        &mut execution,
        "start-wait",
        "await-reply",
        TaskRuntimeState::Ready,
        TaskRuntimeState::Running,
    )
    .unwrap();
    transition(
        &mut execution,
        "wait-1",
        "await-reply",
        TaskRuntimeState::Running,
        TaskRuntimeState::Waiting,
    )
    .unwrap();
    assert_eq!(execution.wait_epoch("await-reply").unwrap(), 1);
    assert!(
        execution
            .ready_set_snapshot(&[])
            .unwrap()
            .ready_task_refs()
            .is_empty()
    );

    let witness = WakeWitness {
        witness_ref: "wake-evidence@1".into(),
        task_ref: "await-reply".into(),
        wake_condition_ref: "event:user-reply".into(),
        graph_revision: 1,
        wait_epoch: 1,
        evidence_refs: set(&["observed-user-reply"]),
    };
    let wake_snapshot = execution
        .ready_set_snapshot(std::slice::from_ref(&witness))
        .unwrap();
    assert!(wake_snapshot.ready_task_refs().contains("await-reply"));
    let wake_decision = scheduler_decision(wake_snapshot.snapshot_ref(), &["await-reply"]);
    execution
        .apply_scheduler_decision(&wake_snapshot, &wake_decision)
        .unwrap();
    transition(
        &mut execution,
        "resume-1",
        "await-reply",
        TaskRuntimeState::Ready,
        TaskRuntimeState::Running,
    )
    .unwrap();
    transition(
        &mut execution,
        "wait-2",
        "await-reply",
        TaskRuntimeState::Running,
        TaskRuntimeState::Waiting,
    )
    .unwrap();
    assert_eq!(execution.wait_epoch("await-reply").unwrap(), 2);
    assert_eq!(
        execution.ready_set_snapshot(&[witness]),
        Err(ExecutionGraphError::WakeWitnessMismatch)
    );
}

#[test]
fn s04_wake_witness_for_another_condition_or_nonwaiting_task_fails_closed() {
    let mut waiting = node("waiting", &[]);
    waiting.wake_condition_ref = Some("event:a".into());
    let other = node("other", &[]);
    let mut execution = ExecutionGraph::new(graph(
        "graph-wake-adversary",
        vec![waiting, other],
        Vec::new(),
    ))
    .unwrap();
    admit(&mut execution, &["waiting"]);
    transition(
        &mut execution,
        "start-waiting",
        "waiting",
        TaskRuntimeState::Ready,
        TaskRuntimeState::Running,
    )
    .unwrap();
    transition(
        &mut execution,
        "wait-waiting",
        "waiting",
        TaskRuntimeState::Running,
        TaskRuntimeState::Waiting,
    )
    .unwrap();

    let wrong_condition = WakeWitness {
        witness_ref: "wrong".into(),
        task_ref: "waiting".into(),
        wake_condition_ref: "event:b".into(),
        graph_revision: 1,
        wait_epoch: 1,
        evidence_refs: set(&["event-b-observed"]),
    };
    assert_eq!(
        execution.ready_set_snapshot(&[wrong_condition]),
        Err(ExecutionGraphError::WakeWitnessMismatch)
    );

    let nonwaiting = WakeWitness {
        witness_ref: "other".into(),
        task_ref: "other".into(),
        wake_condition_ref: "event:a".into(),
        graph_revision: 1,
        wait_epoch: 0,
        evidence_refs: set(&["event-a-observed"]),
    };
    assert_eq!(
        execution.ready_set_snapshot(&[nonwaiting]),
        Err(ExecutionGraphError::WakeWitnessForNonWaitingTask)
    );
}

#[test]
fn s04_ready_snapshot_becomes_stale_after_any_projected_truth_change() {
    let mut execution = ExecutionGraph::new(graph(
        "graph-stale-ready",
        vec![node("a", &[]), node("b", &[])],
        Vec::new(),
    ))
    .unwrap();
    let snapshot = execution.ready_set_snapshot(&[]).unwrap();
    effect(
        &mut execution,
        "a",
        "effect-a",
        EffectMilestone::Planned,
        "planned",
    )
    .unwrap();
    assert_eq!(
        execution.apply_scheduler_decision(
            &snapshot,
            &scheduler_decision(snapshot.snapshot_ref(), &["b"]),
        ),
        Err(ExecutionGraphError::ReadySnapshotStale)
    );
}

#[test]
fn s04_effect_truth_is_separate_causal_and_replay_safe() {
    let mut execution =
        ExecutionGraph::new(graph("graph-effects", vec![node("a", &[])], Vec::new())).unwrap();
    assert_eq!(
        effect(
            &mut execution,
            "a",
            "effect-a",
            EffectMilestone::Accepted,
            "accepted-too-early",
        ),
        Err(ExecutionGraphError::EffectMilestoneOutOfOrder)
    );
    effect(
        &mut execution,
        "a",
        "effect-a",
        EffectMilestone::Planned,
        "planned",
    )
    .unwrap();
    effect(
        &mut execution,
        "a",
        "effect-a",
        EffectMilestone::Attempted,
        "attempted",
    )
    .unwrap();
    effect(
        &mut execution,
        "a",
        "effect-a",
        EffectMilestone::Accepted,
        "accepted",
    )
    .unwrap();
    effect(
        &mut execution,
        "a",
        "effect-a",
        EffectMilestone::Observed,
        "observed",
    )
    .unwrap();
    let truth = execution.consequence("a").unwrap();
    assert_eq!(truth.planned_effect_refs, set(&["effect-a"]));
    assert_eq!(truth.attempted_effect_refs, set(&["effect-a"]));
    assert_eq!(truth.accepted_effect_refs, set(&["effect-a"]));
    assert_eq!(truth.observed_effect_refs, set(&["effect-a"]));
}

#[test]
fn s04_running_cancellation_is_explicit_and_ambiguous_effect_requires_reconciliation() {
    let mut cancel_node = node("send", &[]);
    cancel_node.cancellation_scope_ref = Some("cancel-scope-send".into());
    let mut execution =
        ExecutionGraph::new(graph("graph-cancel", vec![cancel_node], Vec::new())).unwrap();
    admit(&mut execution, &["send"]);
    transition(
        &mut execution,
        "start-send",
        "send",
        TaskRuntimeState::Ready,
        TaskRuntimeState::Running,
    )
    .unwrap();
    effect(
        &mut execution,
        "send",
        "effect-send",
        EffectMilestone::Planned,
        "planned",
    )
    .unwrap();
    effect(
        &mut execution,
        "send",
        "effect-send",
        EffectMilestone::Attempted,
        "attempted",
    )
    .unwrap();
    transition(
        &mut execution,
        "cancel-request",
        "send",
        TaskRuntimeState::Running,
        TaskRuntimeState::CancelRequested,
    )
    .unwrap();

    let unresolved = CancellationWitness {
        witness_ref: "cancel-final".into(),
        task_ref: "send".into(),
        cancellation_scope_ref: Some("cancel-scope-send".into()),
        graph_revision: 1,
        base_runtime_revision: execution.runtime_revision(),
        resolved_effect_refs: BTreeSet::new(),
        evidence_refs: set(&["cancel-control-evidence"]),
    };
    assert_eq!(
        execution.finalize_cancellation(unresolved),
        Err(ExecutionGraphError::CancellationRequiresReconciliation)
    );
    transition(
        &mut execution,
        "enter-reconcile",
        "send",
        TaskRuntimeState::CancelRequested,
        TaskRuntimeState::Reconciling,
    )
    .unwrap();
    assert_eq!(
        execution.state("send").unwrap(),
        TaskRuntimeState::Reconciling
    );
}

#[test]
fn s04_final_cancellation_preserves_effect_history_instead_of_claiming_nothing_happened() {
    let mut cancel_node = node("send", &[]);
    cancel_node.cancellation_scope_ref = Some("cancel-scope-send".into());
    let mut execution =
        ExecutionGraph::new(graph("graph-cancel-effects", vec![cancel_node], Vec::new())).unwrap();
    admit(&mut execution, &["send"]);
    transition(
        &mut execution,
        "start-send",
        "send",
        TaskRuntimeState::Ready,
        TaskRuntimeState::Running,
    )
    .unwrap();
    for (milestone, suffix) in [
        (EffectMilestone::Planned, "planned"),
        (EffectMilestone::Attempted, "attempted"),
        (EffectMilestone::Accepted, "accepted"),
        (EffectMilestone::Observed, "observed"),
    ] {
        effect(&mut execution, "send", "effect-send", milestone, suffix).unwrap();
    }
    transition(
        &mut execution,
        "cancel-request",
        "send",
        TaskRuntimeState::Running,
        TaskRuntimeState::CancelRequested,
    )
    .unwrap();
    execution
        .finalize_cancellation(CancellationWitness {
            witness_ref: "cancel-resolved".into(),
            task_ref: "send".into(),
            cancellation_scope_ref: Some("cancel-scope-send".into()),
            graph_revision: 1,
            base_runtime_revision: execution.runtime_revision(),
            resolved_effect_refs: set(&["effect-send"]),
            evidence_refs: set(&["effect-outcome-and-cancellation-resolved"]),
        })
        .unwrap();
    assert_eq!(
        execution.state("send").unwrap(),
        TaskRuntimeState::Cancelled
    );
    let truth = execution.consequence("send").unwrap();
    assert!(truth.accepted_effect_refs.contains("effect-send"));
    assert!(truth.observed_effect_refs.contains("effect-send"));
}

#[test]
fn s04_wrong_completion_witness_does_not_mutate_state() {
    let mut execution =
        ExecutionGraph::new(graph("graph-completion", vec![node("a", &[])], Vec::new())).unwrap();
    admit(&mut execution, &["a"]);
    transition(
        &mut execution,
        "start-a",
        "a",
        TaskRuntimeState::Ready,
        TaskRuntimeState::Running,
    )
    .unwrap();
    let before_revision = execution.runtime_revision();
    assert_eq!(
        execution.complete_task(CompletionWitness {
            witness_ref: "bad-completion".into(),
            task_ref: "a".into(),
            completion_test_ref: "different-test".into(),
            graph_revision: 1,
            base_runtime_revision: before_revision,
            evidence_refs: set(&["some-evidence"]),
        }),
        Err(ExecutionGraphError::CompletionWitnessBindingMismatch)
    );
    assert_eq!(execution.state("a").unwrap(), TaskRuntimeState::Running);
    assert_eq!(execution.runtime_revision(), before_revision);
}

fn checkpoint(id: &str, goal_version: u64, verdict: TrajectoryVerdict) -> TrajectoryCheckpoint {
    TrajectoryCheckpoint {
        checkpoint_id: id.into(),
        original_goal_revision: rev(1),
        current_goal_revision: rev(goal_version),
        correction_refs: BTreeSet::new(),
        policy_revision_refs: set(&["policy@1"]),
        authority_revision_refs: set(&["authority@1"]),
        planned_effect_refs: set(&["effect-a"]),
        attempted_effect_refs: BTreeSet::new(),
        accepted_effect_refs: BTreeSet::new(),
        observed_effect_refs: BTreeSet::new(),
        obligation_refs: BTreeSet::new(),
        unresolved_assumption_refs: BTreeSet::new(),
        progress_evidence: Vec::new(),
        divergence_evidence_refs: BTreeSet::new(),
        affected_scope_refs: set(&["work-a"]),
        verdict,
        next_permitted_step_ref: Some("next-step".into()),
        evaluator_policy: AdaptivePolicyRef {
            policy_ref: "trajectory-policy".into(),
            version: "qualified".into(),
            qualification_evidence_refs: set(&["trajectory-eval"]),
        },
    }
}

#[test]
fn s04_trajectory_is_append_only_and_stale_goal_checkpoint_is_rejected() {
    let mut ledger = TrajectoryLedger::new(rev(2));
    ledger
        .append(checkpoint("checkpoint-1", 2, TrajectoryVerdict::Continue))
        .unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(
        ledger.append(checkpoint("checkpoint-1", 2, TrajectoryVerdict::Replan)),
        Err(TrajectoryLedgerError::DuplicateCheckpoint)
    );
    assert_eq!(
        ledger.append(checkpoint("checkpoint-2", 1, TrajectoryVerdict::Continue)),
        Err(TrajectoryLedgerError::StaleGoalRevision)
    );
    assert_eq!(ledger.len(), 1);
}

#[test]
fn s04_goal_correction_requires_new_trajectory_checkpoint_revision() {
    let mut ledger = TrajectoryLedger::new(rev(2));
    ledger
        .append(checkpoint("checkpoint-old", 2, TrajectoryVerdict::Continue))
        .unwrap();
    ledger.update_current_goal(rev(3)).unwrap();
    assert_eq!(
        ledger.append(checkpoint(
            "checkpoint-stale",
            2,
            TrajectoryVerdict::Continue
        )),
        Err(TrajectoryLedgerError::StaleGoalRevision)
    );
    ledger
        .append(checkpoint(
            "checkpoint-current",
            3,
            TrajectoryVerdict::Replan,
        ))
        .unwrap();
    assert_eq!(ledger.latest().unwrap().current_goal_revision, rev(3));
    assert_eq!(ledger.len(), 2);
}

#[test]
fn s04_trajectory_original_goal_cannot_silently_change() {
    let mut ledger = TrajectoryLedger::new(rev(2));
    ledger
        .append(checkpoint("checkpoint-1", 2, TrajectoryVerdict::Continue))
        .unwrap();
    let mut changed = checkpoint("checkpoint-2", 2, TrajectoryVerdict::Replan);
    changed.original_goal_revision = rev(0);
    assert_eq!(
        ledger.append(changed),
        Err(TrajectoryLedgerError::OriginalGoalChanged)
    );
    assert_eq!(ledger.len(), 1);
}

#[test]
fn s04_trajectory_effect_milestones_are_causal_and_cumulative() {
    let mut ledger = TrajectoryLedger::new(rev(2));
    let mut first = checkpoint("checkpoint-1", 2, TrajectoryVerdict::Continue);
    first.attempted_effect_refs = set(&["effect-a"]);
    first.accepted_effect_refs = set(&["effect-a"]);
    first.observed_effect_refs = set(&["effect-a"]);
    ledger.append(first).unwrap();

    let mut regressed = checkpoint("checkpoint-2", 2, TrajectoryVerdict::Replan);
    regressed.planned_effect_refs.clear();
    assert_eq!(
        ledger.append(regressed),
        Err(TrajectoryLedgerError::CumulativeEffectHistoryRegressed)
    );
    assert_eq!(ledger.len(), 1);

    let mut impossible = checkpoint("checkpoint-3", 2, TrajectoryVerdict::Replan);
    impossible.attempted_effect_refs = set(&["effect-a", "effect-never-planned"]);
    assert_eq!(
        ledger.append(impossible),
        Err(TrajectoryLedgerError::InvalidEffectCausality)
    );
    assert_eq!(ledger.len(), 1);
}

#[test]
fn s04_trajectory_goal_identity_and_revision_cannot_move_backwards() {
    let mut ledger = TrajectoryLedger::new(rev(4));
    assert_eq!(
        ledger.update_current_goal(VersionedRef {
            reference: "goal-b".into(),
            version: 5,
        }),
        Err(TrajectoryLedgerError::GoalIdentityChanged)
    );
    assert_eq!(
        ledger.update_current_goal(rev(3)),
        Err(TrajectoryLedgerError::GoalRevisionRegressed)
    );
    ledger.update_current_goal(rev(5)).unwrap();
}
