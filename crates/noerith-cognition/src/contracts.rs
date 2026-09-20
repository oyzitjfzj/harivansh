use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionedRef {
    pub reference: String,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptivePolicyRef {
    pub policy_ref: String,
    pub version: String,
    pub qualification_evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContextItemKind {
    ExactSourceSpan,
    StructuredFact,
    DerivedView,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContextItemIdentity {
    pub tenant_ref: String,
    pub purpose_ref: String,
    pub item_ref: String,
    pub kind: ContextItemKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextBoundaryLabels {
    pub trust_label_ref: String,
    pub data_use_label_ref: String,
    pub lifecycle_label_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSourceProjection {
    pub identity: ContextItemIdentity,
    pub source_ref: String,
    pub source_version: u64,
    pub span_ref: String,
    pub content_digest: String,
    pub lineage_ref: String,
    pub boundary: ContextBoundaryLabels,
    pub validity_dependency_refs: BTreeSet<String>,
}

/// Canonical structured fact/decision materialized by an owning subsystem.
/// The record is not free-form authority: provenance and lifecycle remain
/// explicit, and any protected-field use must bind fact ref/version/digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredFactProjection {
    pub identity: ContextItemIdentity,
    pub fact_ref: String,
    pub fact_version: u64,
    pub content_digest: String,
    pub provenance_refs: BTreeSet<String>,
    pub boundary: ContextBoundaryLabels,
    pub validity_dependency_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedContextProjection {
    pub identity: ContextItemIdentity,
    pub content_digest: String,
    pub parent_item_refs: BTreeSet<String>,
    pub provenance_ref: String,
    pub transform_policy: AdaptivePolicyRef,
    pub boundary: ContextBoundaryLabels,
    pub validity_dependency_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextCandidateDescriptor {
    Exact(ExactSourceProjection),
    Structured(StructuredFactProjection),
    Derived(DerivedContextProjection),
}

impl ContextCandidateDescriptor {
    pub fn identity(&self) -> &ContextItemIdentity {
        match self {
            Self::Exact(item) => &item.identity,
            Self::Structured(item) => &item.identity,
            Self::Derived(item) => &item.identity,
        }
    }

    pub fn boundary(&self) -> &ContextBoundaryLabels {
        match self {
            Self::Exact(item) => &item.boundary,
            Self::Structured(item) => &item.boundary,
            Self::Derived(item) => &item.boundary,
        }
    }

    pub fn content_digest(&self) -> &str {
        match self {
            Self::Exact(item) => &item.content_digest,
            Self::Structured(item) => &item.content_digest,
            Self::Derived(item) => &item.content_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtectedEvidenceLocator {
    SourceSpan {
        source_ref: String,
        source_version: u64,
        span_ref: String,
        content_digest: String,
    },
    StructuredFact {
        fact_ref: String,
        fact_version: u64,
        fact_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedEvidenceRef {
    pub field_ref: String,
    pub exact_value_digest: String,
    pub proving_evidence: BTreeSet<ProtectedEvidenceLocator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextValidityFrontier {
    pub goal: VersionedRef,
    pub work: VersionedRef,
    pub correction_frontier_ref: String,
    pub policy_authority_epoch_ref: String,
    pub dependency_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverContextProfileRef {
    pub receiver_ref: String,
    pub receiver_version: String,
    pub context_profile_ref: String,
    pub qualification_evidence_refs: BTreeSet<String>,
}

/// Exact request frontier covered by one adaptive context-selection proposal.
/// It is intentionally separate from the generic total selection receipt so
/// structural receipt validation remains reusable while the compiler can bind
/// selection to principal/purpose/frontier/receiver state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSelectionBinding {
    pub tenant_ref: String,
    pub principal_context_ref: String,
    pub purpose_ref: String,
    pub candidate_set_revision_ref: String,
    pub validity_frontier: ContextValidityFrontier,
    pub receiver_profile: ReceiverContextProfileRef,
    pub selector_policy: AdaptivePolicyRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextSelectionDisposition {
    Selected {
        item_ref: String,
        policy_evidence_refs: BTreeSet<String>,
    },
    Excluded {
        item_ref: String,
        reason_refs: BTreeSet<String>,
        policy_evidence_refs: BTreeSet<String>,
    },
}

impl ContextSelectionDisposition {
    pub fn item_ref(&self) -> &str {
        match self {
            Self::Selected { item_ref, .. } | Self::Excluded { item_ref, .. } => item_ref,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSelectionReceipt {
    pub receipt_id: String,
    pub candidate_set_revision_ref: String,
    pub selector_policy: AdaptivePolicyRef,
    pub dispositions: Vec<ContextSelectionDisposition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalPatchRelation {
    Add,
    Clarify,
    Correct,
    Supersede,
    Independent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalPatch {
    pub patch_id: String,
    pub base_goal_revision: VersionedRef,
    pub relation: GoalPatchRelation,
    pub proposed_delta_ref: String,
    pub exact_source_refs: BTreeSet<String>,
    pub affected_work_refs: BTreeSet<String>,
    pub affected_plan_refs: BTreeSet<String>,
    pub affected_context_refs: BTreeSet<String>,
    pub acceptance_evidence_refs: BTreeSet<String>,
    pub resulting_goal_revision: Option<VersionedRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSemantics {
    CivilTime,
    ElapsedDuration,
    EventBased,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimingConstraint {
    pub semantics: TimeSemantics,
    pub schedule_ref: Option<String>,
    pub timezone_ref: Option<String>,
    pub recurrence_revision_ref: Option<String>,
    pub tolerated_window_ref: Option<String>,
    pub time_source_confidence_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEnvelope {
    pub resource_refs: BTreeSet<String>,
    pub placement_constraints: BTreeSet<String>,
    pub externally_calibrated_budget_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskNode {
    pub task_ref: String,
    pub goal: VersionedRef,
    pub work: VersionedRef,
    pub semantic_operation_ref: String,
    pub required_capability_refs: BTreeSet<String>,
    pub required_evidence_refs: BTreeSet<String>,
    pub state_class_ref: String,
    pub protected_aggregate_refs: BTreeSet<String>,
    pub resource_envelope: ResourceEnvelope,
    pub timing: Option<TimingConstraint>,
    pub waiting_condition_ref: Option<String>,
    pub wake_condition_ref: Option<String>,
    pub permission_requirement_ref: Option<String>,
    pub blocker_refs: BTreeSet<String>,
    pub completion_test_ref: String,
    pub trajectory_checkpoint_ref: Option<String>,
    pub interrupt_scope_ref: Option<String>,
    pub cancellation_scope_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskEdgeKind {
    Dependency,
    Ordering,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEdge {
    pub from_task_ref: String,
    pub to_task_ref: String,
    pub kind: TaskEdgeKind,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskGraph {
    pub graph_id: String,
    pub revision: u64,
    pub nodes: Vec<TaskNode>,
    pub edges: Vec<TaskEdge>,
    pub promise_refs: BTreeSet<String>,
    pub recurrence_revision_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanProposal {
    pub proposal_id: String,
    pub goal_revision: VersionedRef,
    pub source_evidence_refs: BTreeSet<String>,
    pub assumption_refs: BTreeSet<String>,
    pub unresolved_question_refs: BTreeSet<String>,
    pub candidate_path_refs: BTreeSet<String>,
    pub task_graph: TaskGraph,
    pub selection_reason_evidence_refs: BTreeSet<String>,
    pub consequence_estimate_refs: BTreeSet<String>,
    pub quality_requirement_refs: BTreeSet<String>,
    pub stop_condition_refs: BTreeSet<String>,
    pub trajectory_policy: AdaptivePolicyRef,
    pub resource_estimate_ref: String,
    pub planner_policy: AdaptivePolicyRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressKind {
    ArtifactProduced,
    MilestoneVerified,
    ExternalObservation,
    BlockedDependency,
    Uncertainty,
    Repetition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressEvidence {
    pub evidence_ref: String,
    pub task_ref: String,
    pub kind: ProgressKind,
    pub source_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrajectoryVerdict {
    Continue,
    Retrieve,
    Replan,
    PauseAffected,
    Ask,
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryCheckpoint {
    pub checkpoint_id: String,
    pub original_goal_revision: VersionedRef,
    pub current_goal_revision: VersionedRef,
    pub correction_refs: BTreeSet<String>,
    pub policy_revision_refs: BTreeSet<String>,
    pub authority_revision_refs: BTreeSet<String>,
    pub planned_effect_refs: BTreeSet<String>,
    pub attempted_effect_refs: BTreeSet<String>,
    pub accepted_effect_refs: BTreeSet<String>,
    pub observed_effect_refs: BTreeSet<String>,
    pub obligation_refs: BTreeSet<String>,
    pub unresolved_assumption_refs: BTreeSet<String>,
    pub progress_evidence: Vec<ProgressEvidence>,
    pub divergence_evidence_refs: BTreeSet<String>,
    pub affected_scope_refs: BTreeSet<String>,
    pub verdict: TrajectoryVerdict,
    pub next_permitted_step_ref: Option<String>,
    pub evaluator_policy: AdaptivePolicyRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerCandidate {
    pub task_ref: String,
    pub semantic_priority_evidence_refs: BTreeSet<String>,
    pub commitment_refs: BTreeSet<String>,
    pub deadline_refs: BTreeSet<String>,
    pub risk_refs: BTreeSet<String>,
    pub resource_pressure_refs: BTreeSet<String>,
    pub preemption_cost_refs: BTreeSet<String>,
    pub fairness_evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerDecision {
    pub decision_id: String,
    pub ready_set_revision_ref: String,
    pub admitted_task_refs: BTreeSet<String>,
    pub deferred_task_refs: BTreeSet<String>,
    pub preempted_task_refs: BTreeSet<String>,
    pub resource_reservation_refs: BTreeSet<String>,
    pub placement_reservation_refs: BTreeSet<String>,
    pub protected_conflict_evidence_refs: BTreeSet<String>,
    pub fairness_observation_refs: BTreeSet<String>,
    pub policy: AdaptivePolicyRef,
    pub decision_evidence_refs: BTreeSet<String>,
    pub reevaluation_trigger_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelQualificationProfile {
    pub model_ref: String,
    pub provider_ref: String,
    pub model_version: String,
    pub adapter_version: String,
    pub regime_evidence_refs: BTreeSet<String>,
    pub domain_evidence_refs: BTreeSet<String>,
    pub heldout_distribution_refs: BTreeSet<String>,
    pub structured_output_evidence_refs: BTreeSet<String>,
    pub tool_reliability_evidence_refs: BTreeSet<String>,
    pub modality_refs: BTreeSet<String>,
    pub context_behavior_evidence_refs: BTreeSet<String>,
    pub privacy_policy_refs: BTreeSet<String>,
    pub data_residency_refs: BTreeSet<String>,
    pub retention_policy_refs: BTreeSet<String>,
    pub provenance_ref: String,
    pub health_ref: String,
    pub calibration_validity_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRequest {
    pub request_id: String,
    pub regime_refs: BTreeSet<String>,
    pub domain_refs: BTreeSet<String>,
    pub quality_floor_ref: String,
    pub privacy_constraint_refs: BTreeSet<String>,
    pub data_constraint_refs: BTreeSet<String>,
    pub required_modalities: BTreeSet<String>,
    pub structured_output_requirement_ref: Option<String>,
    pub tool_requirement_refs: BTreeSet<String>,
    pub context_requirement_ref: String,
    pub deadline_resource_envelope_ref: Option<String>,
    pub verification_plan_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRejection {
    pub candidate_ref: String,
    pub reason_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRoutingReceipt {
    pub receipt_id: String,
    pub request_ref: String,
    pub eligible_candidate_refs: BTreeSet<String>,
    pub rejected_candidates: Vec<ModelRejection>,
    pub selected_candidate_ref: Option<String>,
    pub selected_model_version: Option<String>,
    pub qualification_profile_refs: BTreeSet<String>,
    pub evaluation_version_refs: BTreeSet<String>,
    pub constraint_refs: BTreeSet<String>,
    pub optimization_policy: AdaptivePolicyRef,
    pub fallback_behavior_ref: String,
}
