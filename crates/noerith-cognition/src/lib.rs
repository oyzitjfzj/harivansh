#![forbid(unsafe_code)]

//! NOERITH S04 cognition public capability membrane.
//!
//! Implementation modules are intentionally private. External code must use
//! the audited crate-root surface below rather than depending on file layout.
//!
//! ```compile_fail
//! use noerith_cognition::context::ContextCompilation;
//! ```

mod clarification;
mod context;
mod contracts;
mod delivery;
mod executive;
mod fidelity;
mod goal;
mod graph;
mod influence;
mod interfaces;
mod validators;

pub use clarification::{
    AmbiguityBinding, AmbiguityClaim, ClarificationAnswerEvidence, ClarificationError,
    ClarificationGate, ClarificationQuestion, GroundingAssumption, GroundingBinding,
    GroundingDisposition, GroundingPolicy, GroundingProposal, GroundingRequest,
    ProtectedResolutionRequirement, ResolutionRequirementBinding, VerifiedGroundingProposal,
    validate_clarification_answer, verified_grounding_has_no_effect_commit_authority,
};
pub use context::{
    ContextCompilation, ContextCompileError, ContextCompileInput, ContextCompiler,
    patch_invalidates_existing_context,
};
pub use contracts::{
    AdaptivePolicyRef, ContextBoundaryLabels, ContextCandidateDescriptor, ContextItemIdentity,
    ContextItemKind, ContextSelectionBinding, ContextSelectionDisposition,
    ContextSelectionReceipt, ContextValidityFrontier, DerivedContextProjection,
    ExactSourceProjection, GoalPatch, GoalPatchRelation, ModelQualificationProfile, ModelRejection,
    ModelRequest, ModelRoutingReceipt, PlanProposal, ProgressEvidence, ProgressKind,
    ProtectedEvidenceLocator, ProtectedEvidenceRef, ReceiverContextProfileRef, ResourceEnvelope,
    SchedulerCandidate, SchedulerDecision, StructuredFactProjection, TaskEdge, TaskEdgeKind,
    TaskGraph, TaskNode, TimeSemantics, TimingConstraint, TrajectoryCheckpoint,
    TrajectoryVerdict, VersionedRef,
};
pub use delivery::{
    ContextDeliveryBoundary, ContextDeliveryError, ContextDeliveryLabelSnapshot,
    ContextInformationClass, ContextLabelTransitionEvidence, validate_context_delivery_boundaries,
};
pub use executive::{
    ExecutiveError, ModelCandidate, ModelFabric, PlannerController, ProgressController,
    SchedulerController, plan_contains_no_direct_effect_commit_authority,
};
pub use fidelity::{
    ContextFidelityBinding, ContextFidelityGuard, ContextFidelityReport, ContextFidelityRequest,
    ContextFidelityVerdict, ContextFrontierAuthority, ContextFrontierError,
    ContextItemFidelityBinding, ContextItemOriginBinding, ContextSelectionDispositionBinding,
    FidelityFinding, FidelityFindingKind, FidelityGuardError, IndependentFidelityVerifier,
    ProtectedClaimFidelityBinding, ProtectedFidelityCheck, VerifiedContextFidelity,
    protected_evidence_for_fidelity, verified_fidelity_has_no_effect_commit_authority,
};
pub use goal::{
    DependencyIndex, DependencyRecord, DependencyRegistrationError, GoalAmendmentAuthorization,
    GoalAmendmentCandidate, GoalCommitDisposition, GoalCommitError, GoalConstitution,
    GoalConstitutionField, GoalConstitutionSnapshot, GoalDependencyBinding, GoalDependencyScope,
    GoalRevisionCommit, IndependentGoalDisposition, IndependentGoalHandoff,
};
pub use graph::{
    CancellationWitness, CompletionWitness, EffectMilestone, EffectMilestoneWitness,
    ExecutionGraph, ExecutionGraphError, ReadySetSnapshot, TaskConsequenceProjection,
    TaskRuntimeState, TaskTransitionEvidence, TrajectoryLedger, TrajectoryLedgerError, WakeWitness,
};
pub use influence::{
    ContextControlBinding, ContextInfluenceRecord, InfluenceError, InfluenceRole, InputInfluence,
    ValidatedContextInfluence, validate_context_influence_record,
    validated_influence_has_no_effect_commit_authority,
};
pub use interfaces::{
    AdaptivePolicyError, AdaptiveProposalProtocolError, BoundContextRerankProposal,
    BoundContextSelectionReceipt, BoundGoalPatchProposalDisposition, BoundTrajectoryCheckpoint,
    ContextRerankBinding, ContextRerankProposal, ContextRerankRequest, ContextReranker,
    ContextSelectionRequest, ContextSelector, GoalPatchEvaluationBinding,
    GoalPatchEvaluationRequest, GoalPatchEvaluator, GoalPatchProposalDisposition,
    ModelRouter, ModelRoutingRequest, PlanningPolicy, PlanningRequest, ProgressEvaluation,
    ProgressEvaluationRequest, ProgressEvaluator, QualifiedModelRoutingCandidate,
    SchedulerPolicy, SchedulerRequest, TrajectoryEvaluationBinding, TrajectoryEvaluationRequest,
    TrajectoryEvaluator,
};
pub use validators::{
    CognitionContractError, ModelEligibilityProof, protected_conflict_pairs,
    validate_context_candidate_set, validate_context_selection_receipt,
    validate_context_validity_frontier, validate_model_eligibility,
    validate_protected_evidence_against_candidates, validate_receiver_context_profile,
    validate_task_graph,
};
