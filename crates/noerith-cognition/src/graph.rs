use crate::{
    SchedulerDecision, TaskEdgeKind, TaskGraph, TrajectoryCheckpoint, TrajectoryVerdict,
    VersionedRef, protected_conflict_pairs, validate_task_graph,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRuntimeState {
    Planned,
    Ready,
    Running,
    Waiting,
    Paused,
    CancelRequested,
    Reconciling,
    Completed,
    Failed,
    Cancelled,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTransitionEvidence {
    pub transition_ref: String,
    pub task_ref: String,
    pub graph_revision: u64,
    pub base_runtime_revision: u64,
    pub from_state: TaskRuntimeState,
    pub to_state: TaskRuntimeState,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectMilestone {
    Planned,
    Attempted,
    Accepted,
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectMilestoneWitness {
    pub witness_ref: String,
    pub task_ref: String,
    pub effect_ref: String,
    pub milestone: EffectMilestone,
    pub graph_revision: u64,
    pub base_runtime_revision: u64,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaskConsequenceProjection {
    pub planned_effect_refs: BTreeSet<String>,
    pub attempted_effect_refs: BTreeSet<String>,
    pub accepted_effect_refs: BTreeSet<String>,
    pub observed_effect_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionWitness {
    pub witness_ref: String,
    pub task_ref: String,
    pub completion_test_ref: String,
    pub graph_revision: u64,
    pub base_runtime_revision: u64,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationWitness {
    pub witness_ref: String,
    pub task_ref: String,
    pub cancellation_scope_ref: Option<String>,
    pub graph_revision: u64,
    pub base_runtime_revision: u64,
    /// Every attempted effect whose cancellation/outcome ambiguity has been
    /// resolved by the referenced authoritative evidence. This is resolution
    /// bookkeeping, not a claim that the effect did not happen.
    pub resolved_effect_refs: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeWitness {
    pub witness_ref: String,
    pub task_ref: String,
    pub wake_condition_ref: String,
    pub graph_revision: u64,
    pub wait_epoch: u64,
    pub evidence_refs: BTreeSet<String>,
}

/// Graph-produced readiness snapshot. Its fields are private so callers cannot
/// manufacture a ready set and then ask the scheduler to legitimize it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadySetSnapshot {
    snapshot_ref: String,
    graph_id: String,
    graph_revision: u64,
    runtime_revision: u64,
    ready_task_refs: BTreeSet<String>,
}

impl ReadySetSnapshot {
    pub fn snapshot_ref(&self) -> &str {
        &self.snapshot_ref
    }

    pub fn ready_task_refs(&self) -> &BTreeSet<String> {
        &self.ready_task_refs
    }

    pub fn graph_revision(&self) -> u64 {
        self.graph_revision
    }

    pub fn runtime_revision(&self) -> u64 {
        self.runtime_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionGraphError {
    InvalidGraph,
    UnknownTask,
    InvalidTransition,
    InvalidTransitionEvidence,
    TransitionBindingMismatch,
    TransitionIdentityConflict,
    ReadyTransitionRequiresSnapshot,
    CompletionRequiresWitness,
    CancellationRequiresWitness,
    RuntimeRevisionOverflow,
    WaitEpochOverflow,
    InvalidWakeWitness,
    DuplicateWakeWitness,
    WakeWitnessForUnknownTask,
    WakeWitnessForNonWaitingTask,
    WakeWitnessMismatch,
    ReadySnapshotStale,
    ReadySnapshotGraphMismatch,
    SchedulerReadySetMismatch,
    SchedulerAdmitsUnknownOrNotReadyTask,
    SchedulerCreatesProtectedConflict,
    SchedulerEvidenceMissing,
    InvalidEffectWitness,
    EffectWitnessBindingMismatch,
    EffectWitnessIdentityConflict,
    EffectMilestoneOutOfOrder,
    InvalidCompletionWitness,
    CompletionWitnessBindingMismatch,
    CompletionWitnessIdentityConflict,
    InvalidCancellationWitness,
    CancellationWitnessBindingMismatch,
    CancellationWitnessIdentityConflict,
    CancellationRequiresReconciliation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionGraph {
    graph: TaskGraph,
    states: BTreeMap<String, TaskRuntimeState>,
    wait_epochs: BTreeMap<String, u64>,
    consequence: BTreeMap<String, TaskConsequenceProjection>,
    transition_evidence: BTreeMap<String, TaskTransitionEvidence>,
    effect_witnesses: BTreeMap<String, EffectMilestoneWitness>,
    completion_witnesses: BTreeMap<String, CompletionWitness>,
    cancellation_witnesses: BTreeMap<String, CancellationWitness>,
    runtime_revision: u64,
}

impl ExecutionGraph {
    pub fn new(graph: TaskGraph) -> Result<Self, ExecutionGraphError> {
        validate_task_graph(&graph).map_err(|_| ExecutionGraphError::InvalidGraph)?;
        let states = graph
            .nodes
            .iter()
            .map(|node| (node.task_ref.clone(), TaskRuntimeState::Planned))
            .collect();
        let wait_epochs = graph
            .nodes
            .iter()
            .map(|node| (node.task_ref.clone(), 0_u64))
            .collect();
        let consequence = graph
            .nodes
            .iter()
            .map(|node| (node.task_ref.clone(), TaskConsequenceProjection::default()))
            .collect();
        Ok(Self {
            graph,
            states,
            wait_epochs,
            consequence,
            transition_evidence: BTreeMap::new(),
            effect_witnesses: BTreeMap::new(),
            completion_witnesses: BTreeMap::new(),
            cancellation_witnesses: BTreeMap::new(),
            runtime_revision: 0,
        })
    }

    pub fn graph(&self) -> &TaskGraph {
        &self.graph
    }

    pub fn runtime_revision(&self) -> u64 {
        self.runtime_revision
    }

    pub fn state(&self, task_ref: &str) -> Result<TaskRuntimeState, ExecutionGraphError> {
        self.states
            .get(task_ref)
            .copied()
            .ok_or(ExecutionGraphError::UnknownTask)
    }

    pub fn wait_epoch(&self, task_ref: &str) -> Result<u64, ExecutionGraphError> {
        self.wait_epochs
            .get(task_ref)
            .copied()
            .ok_or(ExecutionGraphError::UnknownTask)
    }

    pub fn consequence(
        &self,
        task_ref: &str,
    ) -> Result<&TaskConsequenceProjection, ExecutionGraphError> {
        self.consequence
            .get(task_ref)
            .ok_or(ExecutionGraphError::UnknownTask)
    }

    /// Apply a non-readiness lifecycle transition that is bound to the exact
    /// graph/runtime frontier. The adaptive caller proposes the transition;
    /// this function only checks state-machine/evidence invariants.
    ///
    /// Returns `Ok(false)` for an exact idempotent replay of a previously
    /// accepted transition witness and fails if the witness ID is reused for a
    /// different binding.
    pub fn apply_transition(
        &mut self,
        evidence: TaskTransitionEvidence,
    ) -> Result<bool, ExecutionGraphError> {
        validate_transition_evidence_shape(&evidence)?;
        if let Some(existing) = self.transition_evidence.get(&evidence.transition_ref) {
            return if existing == &evidence {
                Ok(false)
            } else {
                Err(ExecutionGraphError::TransitionIdentityConflict)
            };
        }

        let current = self.state(&evidence.task_ref)?;
        if evidence.graph_revision != self.graph.revision
            || evidence.base_runtime_revision != self.runtime_revision
            || evidence.from_state != current
        {
            return Err(ExecutionGraphError::TransitionBindingMismatch);
        }
        if evidence.to_state == TaskRuntimeState::Ready {
            return Err(ExecutionGraphError::ReadyTransitionRequiresSnapshot);
        }
        if evidence.to_state == TaskRuntimeState::Completed {
            return Err(ExecutionGraphError::CompletionRequiresWitness);
        }
        if evidence.to_state == TaskRuntimeState::Cancelled {
            return Err(ExecutionGraphError::CancellationRequiresWitness);
        }
        if !generic_transition_allowed(current, evidence.to_state) {
            return Err(ExecutionGraphError::InvalidTransition);
        }

        let next_runtime_revision = self.next_runtime_revision()?;
        let next_wait_epoch = if evidence.to_state == TaskRuntimeState::Waiting {
            Some(
                self.wait_epoch(&evidence.task_ref)?
                    .checked_add(1)
                    .ok_or(ExecutionGraphError::WaitEpochOverflow)?,
            )
        } else {
            None
        };

        if let Some(epoch) = next_wait_epoch {
            self.wait_epochs.insert(evidence.task_ref.clone(), epoch);
        }
        self.states
            .insert(evidence.task_ref.clone(), evidence.to_state);
        self.runtime_revision = next_runtime_revision;
        self.transition_evidence
            .insert(evidence.transition_ref.clone(), evidence);
        Ok(true)
    }

    /// Record a consequence milestone observed from an owning effect/outcome
    /// subsystem. The graph stores only typed evidence references and never
    /// manufactures provider success or authorization.
    pub fn record_effect_milestone(
        &mut self,
        witness: EffectMilestoneWitness,
    ) -> Result<bool, ExecutionGraphError> {
        validate_effect_witness_shape(&witness)?;
        if let Some(existing) = self.effect_witnesses.get(&witness.witness_ref) {
            return if existing == &witness {
                Ok(false)
            } else {
                Err(ExecutionGraphError::EffectWitnessIdentityConflict)
            };
        }
        if witness.graph_revision != self.graph.revision
            || witness.base_runtime_revision != self.runtime_revision
        {
            return Err(ExecutionGraphError::EffectWitnessBindingMismatch);
        }
        let current = self
            .consequence
            .get(&witness.task_ref)
            .ok_or(ExecutionGraphError::UnknownTask)?;
        validate_effect_milestone_order(current, &witness)?;
        let next_runtime_revision = self.next_runtime_revision()?;

        let projection = self
            .consequence
            .get_mut(&witness.task_ref)
            .expect("task consequence projection created with graph");
        match witness.milestone {
            EffectMilestone::Planned => {
                projection
                    .planned_effect_refs
                    .insert(witness.effect_ref.clone());
            }
            EffectMilestone::Attempted => {
                projection
                    .attempted_effect_refs
                    .insert(witness.effect_ref.clone());
            }
            EffectMilestone::Accepted => {
                projection
                    .accepted_effect_refs
                    .insert(witness.effect_ref.clone());
            }
            EffectMilestone::Observed => {
                projection
                    .observed_effect_refs
                    .insert(witness.effect_ref.clone());
            }
        }
        self.runtime_revision = next_runtime_revision;
        self.effect_witnesses
            .insert(witness.witness_ref.clone(), witness);
        Ok(true)
    }

    /// Finish a task only through the exact completion test declared by its
    /// TaskNode. The evidence provider owns semantic verification; graph.rs
    /// merely prevents a naked status assignment from becoming “done”.
    pub fn complete_task(
        &mut self,
        witness: CompletionWitness,
    ) -> Result<bool, ExecutionGraphError> {
        validate_completion_witness_shape(&witness)?;
        if let Some(existing) = self.completion_witnesses.get(&witness.task_ref) {
            return if existing == &witness {
                Ok(false)
            } else {
                Err(ExecutionGraphError::CompletionWitnessIdentityConflict)
            };
        }
        let current = self.state(&witness.task_ref)?;
        if witness.graph_revision != self.graph.revision
            || witness.base_runtime_revision != self.runtime_revision
            || !matches!(
                current,
                TaskRuntimeState::Running
                    | TaskRuntimeState::Waiting
                    | TaskRuntimeState::Reconciling
            )
        {
            return Err(ExecutionGraphError::CompletionWitnessBindingMismatch);
        }
        let node = self
            .node(&witness.task_ref)
            .ok_or(ExecutionGraphError::UnknownTask)?;
        if witness.completion_test_ref != node.completion_test_ref {
            return Err(ExecutionGraphError::CompletionWitnessBindingMismatch);
        }
        let next_runtime_revision = self.next_runtime_revision()?;
        self.states
            .insert(witness.task_ref.clone(), TaskRuntimeState::Completed);
        self.runtime_revision = next_runtime_revision;
        self.completion_witnesses
            .insert(witness.task_ref.clone(), witness);
        Ok(true)
    }

    /// Finalize an already-requested cancellation without deleting historical
    /// consequence milestones. Every attempted effect must have explicit
    /// resolution evidence before the graph can leave `CancelRequested` or
    /// `Reconciling` as `Cancelled`.
    pub fn finalize_cancellation(
        &mut self,
        witness: CancellationWitness,
    ) -> Result<bool, ExecutionGraphError> {
        validate_cancellation_witness_shape(&witness)?;
        if let Some(existing) = self.cancellation_witnesses.get(&witness.task_ref) {
            return if existing == &witness {
                Ok(false)
            } else {
                Err(ExecutionGraphError::CancellationWitnessIdentityConflict)
            };
        }
        let current = self.state(&witness.task_ref)?;
        if witness.graph_revision != self.graph.revision
            || witness.base_runtime_revision != self.runtime_revision
            || !matches!(
                current,
                TaskRuntimeState::CancelRequested | TaskRuntimeState::Reconciling
            )
        {
            return Err(ExecutionGraphError::CancellationWitnessBindingMismatch);
        }
        let node = self
            .node(&witness.task_ref)
            .ok_or(ExecutionGraphError::UnknownTask)?;
        if witness.cancellation_scope_ref != node.cancellation_scope_ref {
            return Err(ExecutionGraphError::CancellationWitnessBindingMismatch);
        }
        let consequence = self.consequence(&witness.task_ref)?;
        if witness.resolved_effect_refs != consequence.attempted_effect_refs {
            return Err(ExecutionGraphError::CancellationRequiresReconciliation);
        }
        let next_runtime_revision = self.next_runtime_revision()?;
        self.states
            .insert(witness.task_ref.clone(), TaskRuntimeState::Cancelled);
        self.runtime_revision = next_runtime_revision;
        self.cancellation_witnesses
            .insert(witness.task_ref.clone(), witness);
        Ok(true)
    }

    /// Convenience projection for tasks whose graph dependencies are complete
    /// and that are not waiting for an external wake event. Scheduler admission
    /// uses `ready_set_snapshot`, not this unversioned view.
    pub fn dependency_ready_set(&self) -> BTreeSet<String> {
        self.dependency_blockers()
            .into_iter()
            .filter_map(|(task_ref, blocked)| {
                let state = self.states.get(task_ref)?;
                (blocked == 0
                    && matches!(state, TaskRuntimeState::Planned | TaskRuntimeState::Ready))
                .then_some(task_ref.to_owned())
            })
            .collect()
    }

    pub fn ready_set_snapshot(
        &self,
        wake_witnesses: &[WakeWitness],
    ) -> Result<ReadySetSnapshot, ExecutionGraphError> {
        let mut wake_by_task = BTreeMap::<&str, &WakeWitness>::new();
        for witness in wake_witnesses {
            if witness.witness_ref.trim().is_empty()
                || witness.task_ref.trim().is_empty()
                || witness.wake_condition_ref.trim().is_empty()
                || !clean_nonempty_set(&witness.evidence_refs)
            {
                return Err(ExecutionGraphError::InvalidWakeWitness);
            }
            if wake_by_task
                .insert(witness.task_ref.as_str(), witness)
                .is_some()
            {
                return Err(ExecutionGraphError::DuplicateWakeWitness);
            }

            let Some(node) = self.node(&witness.task_ref) else {
                return Err(ExecutionGraphError::WakeWitnessForUnknownTask);
            };
            if self.state(&witness.task_ref)? != TaskRuntimeState::Waiting {
                return Err(ExecutionGraphError::WakeWitnessForNonWaitingTask);
            }
            if witness.graph_revision != self.graph.revision
                || witness.wait_epoch != self.wait_epoch(&witness.task_ref)?
                || node.wake_condition_ref.as_deref() != Some(witness.wake_condition_ref.as_str())
            {
                return Err(ExecutionGraphError::WakeWitnessMismatch);
            }
        }

        let ready_task_refs = self
            .dependency_blockers()
            .into_iter()
            .filter_map(|(task_ref, blocked)| {
                if blocked != 0 {
                    return None;
                }
                match self.states.get(task_ref)? {
                    TaskRuntimeState::Planned | TaskRuntimeState::Ready => {
                        Some(task_ref.to_owned())
                    }
                    TaskRuntimeState::Waiting if wake_by_task.contains_key(task_ref) => {
                        Some(task_ref.to_owned())
                    }
                    _ => None,
                }
            })
            .collect();

        Ok(ReadySetSnapshot {
            snapshot_ref: format!(
                "ready:{}@{}:runtime@{}",
                self.graph.graph_id, self.graph.revision, self.runtime_revision
            ),
            graph_id: self.graph.graph_id.clone(),
            graph_revision: self.graph.revision,
            runtime_revision: self.runtime_revision,
            ready_task_refs,
        })
    }

    pub fn apply_scheduler_decision(
        &mut self,
        snapshot: &ReadySetSnapshot,
        decision: &SchedulerDecision,
    ) -> Result<(), ExecutionGraphError> {
        if snapshot.graph_id != self.graph.graph_id
            || snapshot.graph_revision != self.graph.revision
        {
            return Err(ExecutionGraphError::ReadySnapshotGraphMismatch);
        }
        if snapshot.runtime_revision != self.runtime_revision {
            return Err(ExecutionGraphError::ReadySnapshotStale);
        }
        if decision.ready_set_revision_ref != snapshot.snapshot_ref {
            return Err(ExecutionGraphError::SchedulerReadySetMismatch);
        }
        if decision.policy.policy_ref.trim().is_empty()
            || decision.policy.version.trim().is_empty()
            || !clean_nonempty_set(&decision.policy.qualification_evidence_refs)
            || !clean_nonempty_set(&decision.decision_evidence_refs)
        {
            return Err(ExecutionGraphError::SchedulerEvidenceMissing);
        }
        if !decision
            .admitted_task_refs
            .is_subset(&snapshot.ready_task_refs)
        {
            return Err(ExecutionGraphError::SchedulerAdmitsUnknownOrNotReadyTask);
        }

        let conflicts = protected_conflict_pairs(&self.graph);
        if conflicts.iter().any(|(left, right)| {
            decision.admitted_task_refs.contains(left)
                && decision.admitted_task_refs.contains(right)
        }) {
            return Err(ExecutionGraphError::SchedulerCreatesProtectedConflict);
        }

        let changes_state = decision.admitted_task_refs.iter().any(|task_ref| {
            self.states.get(task_ref).is_some_and(|state| {
                matches!(state, TaskRuntimeState::Planned | TaskRuntimeState::Waiting)
            })
        });
        let next_runtime_revision = if changes_state {
            Some(self.next_runtime_revision()?)
        } else {
            None
        };

        for task_ref in &decision.admitted_task_refs {
            match self.state(task_ref)? {
                TaskRuntimeState::Planned | TaskRuntimeState::Waiting | TaskRuntimeState::Ready => {
                }
                _ => return Err(ExecutionGraphError::InvalidTransition),
            }
        }
        for task_ref in &decision.admitted_task_refs {
            if matches!(
                self.state(task_ref)?,
                TaskRuntimeState::Planned | TaskRuntimeState::Waiting
            ) {
                self.states
                    .insert(task_ref.clone(), TaskRuntimeState::Ready);
            }
        }
        if let Some(revision) = next_runtime_revision {
            self.runtime_revision = revision;
        }
        Ok(())
    }

    fn node(&self, task_ref: &str) -> Option<&crate::TaskNode> {
        self.graph
            .nodes
            .iter()
            .find(|node| node.task_ref == task_ref)
    }

    fn next_runtime_revision(&self) -> Result<u64, ExecutionGraphError> {
        self.runtime_revision
            .checked_add(1)
            .ok_or(ExecutionGraphError::RuntimeRevisionOverflow)
    }

    fn dependency_blockers(&self) -> BTreeMap<&str, usize> {
        let mut blockers = BTreeMap::<&str, usize>::new();
        for node in &self.graph.nodes {
            blockers.insert(node.task_ref.as_str(), 0);
        }
        for edge in &self.graph.edges {
            if !matches!(edge.kind, TaskEdgeKind::Dependency | TaskEdgeKind::Ordering) {
                continue;
            }
            // `Completed` is reachable only through `CompletionWitness`, so
            // dependency satisfaction is proof-backed rather than a naked flag.
            let predecessor_completed = self
                .states
                .get(&edge.from_task_ref)
                .is_some_and(|state| *state == TaskRuntimeState::Completed);
            if !predecessor_completed
                && let Some(count) = blockers.get_mut(edge.to_task_ref.as_str())
            {
                *count += 1;
            }
        }
        blockers
    }
}

fn generic_transition_allowed(current: TaskRuntimeState, next: TaskRuntimeState) -> bool {
    matches!(
        (current, next),
        (TaskRuntimeState::Ready, TaskRuntimeState::Running)
            | (TaskRuntimeState::Running, TaskRuntimeState::Waiting)
            | (TaskRuntimeState::Running, TaskRuntimeState::Paused)
            | (TaskRuntimeState::Running, TaskRuntimeState::CancelRequested)
            | (TaskRuntimeState::Running, TaskRuntimeState::Reconciling)
            | (TaskRuntimeState::Running, TaskRuntimeState::Failed)
            | (TaskRuntimeState::Waiting, TaskRuntimeState::Paused)
            | (TaskRuntimeState::Waiting, TaskRuntimeState::CancelRequested)
            | (TaskRuntimeState::Waiting, TaskRuntimeState::Failed)
            | (TaskRuntimeState::Ready, TaskRuntimeState::Paused)
            | (TaskRuntimeState::Ready, TaskRuntimeState::CancelRequested)
            | (TaskRuntimeState::Planned, TaskRuntimeState::CancelRequested)
            | (TaskRuntimeState::Paused, TaskRuntimeState::CancelRequested)
            | (
                TaskRuntimeState::CancelRequested,
                TaskRuntimeState::Reconciling
            )
            | (TaskRuntimeState::Reconciling, TaskRuntimeState::Failed)
            | (TaskRuntimeState::Planned, TaskRuntimeState::Superseded)
            | (TaskRuntimeState::Ready, TaskRuntimeState::Superseded)
            | (TaskRuntimeState::Waiting, TaskRuntimeState::Superseded)
            | (TaskRuntimeState::Paused, TaskRuntimeState::Superseded)
    )
}

fn validate_transition_evidence_shape(
    evidence: &TaskTransitionEvidence,
) -> Result<(), ExecutionGraphError> {
    if evidence.transition_ref.trim().is_empty()
        || evidence.task_ref.trim().is_empty()
        || !clean_nonempty_set(&evidence.evidence_refs)
    {
        return Err(ExecutionGraphError::InvalidTransitionEvidence);
    }
    Ok(())
}

fn validate_effect_witness_shape(
    witness: &EffectMilestoneWitness,
) -> Result<(), ExecutionGraphError> {
    if witness.witness_ref.trim().is_empty()
        || witness.task_ref.trim().is_empty()
        || witness.effect_ref.trim().is_empty()
        || !clean_nonempty_set(&witness.evidence_refs)
    {
        return Err(ExecutionGraphError::InvalidEffectWitness);
    }
    Ok(())
}

fn validate_effect_milestone_order(
    current: &TaskConsequenceProjection,
    witness: &EffectMilestoneWitness,
) -> Result<(), ExecutionGraphError> {
    let valid = match witness.milestone {
        EffectMilestone::Planned => true,
        EffectMilestone::Attempted => current.planned_effect_refs.contains(&witness.effect_ref),
        EffectMilestone::Accepted => current.attempted_effect_refs.contains(&witness.effect_ref),
        EffectMilestone::Observed => current.accepted_effect_refs.contains(&witness.effect_ref),
    };
    if valid {
        Ok(())
    } else {
        Err(ExecutionGraphError::EffectMilestoneOutOfOrder)
    }
}

fn validate_completion_witness_shape(
    witness: &CompletionWitness,
) -> Result<(), ExecutionGraphError> {
    if witness.witness_ref.trim().is_empty()
        || witness.task_ref.trim().is_empty()
        || witness.completion_test_ref.trim().is_empty()
        || !clean_nonempty_set(&witness.evidence_refs)
    {
        return Err(ExecutionGraphError::InvalidCompletionWitness);
    }
    Ok(())
}

fn validate_cancellation_witness_shape(
    witness: &CancellationWitness,
) -> Result<(), ExecutionGraphError> {
    if witness.witness_ref.trim().is_empty()
        || witness.task_ref.trim().is_empty()
        || witness
            .cancellation_scope_ref
            .as_deref()
            .is_some_and(|reference| reference.trim().is_empty())
        || witness
            .resolved_effect_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        || !clean_nonempty_set(&witness.evidence_refs)
    {
        return Err(ExecutionGraphError::InvalidCancellationWitness);
    }
    Ok(())
}

fn clean_nonempty_set(values: &BTreeSet<String>) -> bool {
    !values.is_empty() && values.iter().all(|value| !value.trim().is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrajectoryLedgerError {
    EmptyCheckpointId,
    DuplicateCheckpoint,
    StaleGoalRevision,
    GoalIdentityChanged,
    GoalRevisionRegressed,
    OriginalGoalChanged,
    MissingEvaluatorEvidence,
    ContinueWithoutNextStep,
    InvalidEffectCausality,
    CumulativeEffectHistoryRegressed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryLedger {
    current_goal: VersionedRef,
    original_goal: Option<VersionedRef>,
    checkpoint_ids: BTreeSet<String>,
    checkpoints: VecDeque<TrajectoryCheckpoint>,
}

impl TrajectoryLedger {
    pub fn new(current_goal: VersionedRef) -> Self {
        Self {
            current_goal,
            original_goal: None,
            checkpoint_ids: BTreeSet::new(),
            checkpoints: VecDeque::new(),
        }
    }

    pub fn update_current_goal(
        &mut self,
        current_goal: VersionedRef,
    ) -> Result<(), TrajectoryLedgerError> {
        if current_goal.reference != self.current_goal.reference {
            return Err(TrajectoryLedgerError::GoalIdentityChanged);
        }
        if current_goal.version < self.current_goal.version {
            return Err(TrajectoryLedgerError::GoalRevisionRegressed);
        }
        self.current_goal = current_goal;
        Ok(())
    }

    pub fn append(
        &mut self,
        checkpoint: TrajectoryCheckpoint,
    ) -> Result<(), TrajectoryLedgerError> {
        if checkpoint.checkpoint_id.trim().is_empty() {
            return Err(TrajectoryLedgerError::EmptyCheckpointId);
        }
        if self.checkpoint_ids.contains(&checkpoint.checkpoint_id) {
            return Err(TrajectoryLedgerError::DuplicateCheckpoint);
        }
        if checkpoint.current_goal_revision != self.current_goal {
            return Err(TrajectoryLedgerError::StaleGoalRevision);
        }
        if checkpoint.original_goal_revision.reference != self.current_goal.reference {
            return Err(TrajectoryLedgerError::OriginalGoalChanged);
        }
        if let Some(original) = &self.original_goal
            && checkpoint.original_goal_revision != *original
        {
            return Err(TrajectoryLedgerError::OriginalGoalChanged);
        }
        if checkpoint.evaluator_policy.policy_ref.trim().is_empty()
            || checkpoint.evaluator_policy.version.trim().is_empty()
            || !clean_nonempty_set(&checkpoint.evaluator_policy.qualification_evidence_refs)
        {
            return Err(TrajectoryLedgerError::MissingEvaluatorEvidence);
        }
        if checkpoint.verdict == TrajectoryVerdict::Continue
            && checkpoint
                .next_permitted_step_ref
                .as_deref()
                .is_none_or(|reference| reference.trim().is_empty())
        {
            return Err(TrajectoryLedgerError::ContinueWithoutNextStep);
        }
        if !checkpoint
            .attempted_effect_refs
            .is_subset(&checkpoint.planned_effect_refs)
            || !checkpoint
                .accepted_effect_refs
                .is_subset(&checkpoint.attempted_effect_refs)
            || !checkpoint
                .observed_effect_refs
                .is_subset(&checkpoint.accepted_effect_refs)
        {
            return Err(TrajectoryLedgerError::InvalidEffectCausality);
        }

        if let Some(previous) = self.checkpoints.back()
            && (!previous
                .planned_effect_refs
                .is_subset(&checkpoint.planned_effect_refs)
                || !previous
                    .attempted_effect_refs
                    .is_subset(&checkpoint.attempted_effect_refs)
                || !previous
                    .accepted_effect_refs
                    .is_subset(&checkpoint.accepted_effect_refs)
                || !previous
                    .observed_effect_refs
                    .is_subset(&checkpoint.observed_effect_refs))
        {
            return Err(TrajectoryLedgerError::CumulativeEffectHistoryRegressed);
        }

        let bind_original = self.original_goal.is_none();
        if bind_original {
            self.original_goal = Some(checkpoint.original_goal_revision.clone());
        }
        self.checkpoint_ids.insert(checkpoint.checkpoint_id.clone());
        self.checkpoints.push_back(checkpoint);
        Ok(())
    }

    pub fn latest(&self) -> Option<&TrajectoryCheckpoint> {
        self.checkpoints.back()
    }

    pub fn len(&self) -> usize {
        self.checkpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }
}
