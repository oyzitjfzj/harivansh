#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use core::fmt;

mod availability;
mod candidate_configuration;
mod catalog;
mod evaluation_corpus;
mod execution_environment;
mod grader;
mod integrity;
mod manifest;
mod qualification;
mod qualification_plan;
mod qualification_population;
mod quality_analysis;
mod quality_comparison;
mod quality_evidence;
mod quality_floor;
mod quality_result;
mod quality_trial;
mod quality_trial_configuration;
mod regime;
mod regime_capability;
mod regime_evidence;
mod regime_verification;
mod stage_qualification;

pub use availability::{
    AvailabilityError, AvailabilitySnapshot, DependencyAvailability, OperationAvailability,
    ReadinessState, RevocationObservation, RevocationState, VerifiedCapabilityAvailability,
};
pub use candidate_configuration::{
    CANDIDATE_CONFIGURATION_CANONICAL_PROFILE, CANDIDATE_CONFIGURATION_MANIFEST_CANONICAL_PROFILE,
    CandidateConfiguration, CandidateConfigurationError, CandidateConfigurationManifest,
    CandidateModelBinding, VerifiedCandidateConfiguration, VerifiedCandidateConfigurationManifest,
    canonical_candidate_configuration_manifest_transcript,
    canonical_candidate_configuration_transcript, compute_candidate_configuration_digest,
    compute_candidate_configuration_manifest_digest, verify_candidate_configuration,
    verify_candidate_configuration_manifest,
};
pub use catalog::{
    CapabilityCatalogEntry, CapabilityCatalogSnapshot, CatalogError, VerifiedCapabilityCatalog,
};
pub use evaluation_corpus::{
    EVALUATION_CORPUS_CANONICAL_PROFILE, EvaluationCorpusDefinition, EvaluationCorpusError,
    EvaluationExposureClass, EvaluationPartition, EvaluationTaskDefinition,
    VerifiedEvaluationCorpus, VerifiedEvaluationTask, canonical_evaluation_corpus_transcript,
    compute_evaluation_corpus_digest, verify_evaluation_corpus,
};
pub use execution_environment::{
    AmbientAuthorityMode, ArtifactBoundaryContract, AttestationContract, CleanupContract,
    EXECUTION_ENVIRONMENT_PLAN_CANONICAL_PROFILE, EXECUTION_ENVIRONMENT_PROFILE_CANONICAL_PROFILE,
    ExecutionEnvironmentError, ExecutionEnvironmentEvidenceRecord, ExecutionEnvironmentProfile,
    ExecutionEnvironmentProfileIdentity, ExecutionEnvironmentQualificationPlan,
    ExecutionEnvironmentQualificationPlanIdentity, IsolationContract, ReproducibilityContract,
    ResourceAccessContract, ResourceControlContract, SecretDeliveryContract, SupplyChainContract,
    VerifiedExecutionEnvironment, VerifiedExecutionEnvironmentProfile, WorkspaceLifecycleContract,
    WorkspacePersistenceMode, canonical_execution_environment_plan_transcript,
    canonical_execution_environment_profile_transcript, compute_execution_environment_plan_digest,
    compute_execution_environment_profile_digest, qualify_execution_environment,
    verify_execution_environment_profile_integrity,
};
pub use grader::{
    CriterionGrade, EvidenceGraderPlan, EvidenceGraderPlanIdentity, GRADER_PLAN_CANONICAL_PROFILE,
    GradeRecord, GradeRequest, GradeSubject, GraderError, GraderIdentity,
    GraderQualificationEvidenceRecord, VerifiedEvidenceGrader, VerifiedGradeRecord,
    canonical_grader_plan_transcript, compute_evidence_grader_plan_digest, qualify_evidence_grader,
    verify_grade_record,
};
pub use integrity::{
    IntegrityError, MANIFEST_CANONICAL_PROFILE, SHA256_ALGORITHM_REF, VerifiedManifestIntegrity,
    canonical_manifest_transcript, compute_manifest_digest, verify_manifest_integrity,
};
pub use manifest::{
    CapabilityDependency, CapabilityFieldRole, CapabilityManifest, CapabilityOperation,
    ContentDigest, EffectClaim, EnvironmentRequirements, ExternalStateChange,
    FailureRecoveryContract, FreshnessRequirements, IdempotencyClaim, ManifestError, OpaqueVersion,
    OperationConditions, OperationRiskContract, OperationSchema, OutboundDisclosure,
    OutcomeObservationContract, Reference, ResourceCostContract, ReversibilityClaim,
    SchemaExtensionPolicy, SchemaField, SupportClaim, TargetBindingRequirements, validate_manifest,
};
pub use qualification::{
    EvidenceStatus, OperatingCeiling, QualificationError, QualificationEvidenceRecord,
    QualificationPlan, QualificationPlanIdentity, QualificationSubject,
    VerifiedCapabilityQualification,
};
pub use qualification_plan::{
    QUALIFICATION_PLAN_CANONICAL_PROFILE, QualificationPlanIntegrityError,
    VerifiedQualificationPlan, canonical_qualification_plan_transcript,
    compute_qualification_plan_digest, verify_qualification_plan,
};
pub use qualification_population::{
    QUALIFICATION_PLAN_POPULATION_CANONICAL_PROFILE, QualificationPlanMemberIdentity,
    QualificationPlanPopulation, QualificationPlanPopulationError,
    QualificationPlanPopulationIdentity, QualificationPlanPopulationPurpose,
    VerifiedQualificationPlanPopulation, canonical_qualification_plan_population_transcript,
    compute_qualification_plan_population_digest, verify_evidence_grader_qualification_population,
    verify_execution_environment_qualification_population,
};
pub use quality_analysis::{
    QUALITY_ANALYSIS_CANONICAL_PROFILE, QUALITY_PROFILE_MEASUREMENT_CANONICAL_PROFILE,
    QualityAnalysisError, QualityAnalysisEvidenceBundle, QualityCriterionAnalysisRecord,
    QualityProfileMeasurementRecord, VerifiedQualityAnalysisEvidence,
    canonical_quality_criterion_analysis_transcript,
    canonical_quality_profile_measurement_transcript, compute_quality_criterion_analysis_digest,
    compute_quality_profile_measurement_digest, verify_quality_analysis_evidence,
};
pub use quality_comparison::{
    Q07_COMPARISON_ANALYSIS_CANONICAL_PROFILE, Q07ComparisonAnalysisError,
    Q07ComparisonAnalysisRecord, VerifiedQ07ComparisonAnalysisEvidence,
    canonical_q07_comparison_analysis_transcript, compute_q07_comparison_analysis_digest,
    verify_q07_comparison_analysis_evidence,
};
pub use quality_evidence::{
    QUALITY_EVIDENCE_CANONICAL_PROFILE, QualityCorpusEvidence, QualityEvidenceBundle,
    QualityEvidenceError, QualityTrialEvidenceBindingError, VerifiedQualityEvidenceBundle,
    VerifiedQualityEvidenceWithTrials, quality_trial_evidence_ref, verify_quality_evidence_bundle,
    verify_quality_evidence_with_trials,
};
pub use quality_floor::{
    Q06CoverageContract, Q07ComparisonAxis, Q07CoverageContract,
    QUALITY_FLOOR_PLAN_CANONICAL_PROFILE, QualityCriterionKind, QualityFloorCriterion,
    QualityFloorError, QualityFloorPlan, QualityGateCoverage, QualityGateId, QualityProfileMetric,
    QualityProfileMetricRole, VerifiedQualityFloorPlan, canonical_quality_floor_plan_transcript,
    compute_quality_floor_plan_digest, verify_quality_floor_plan,
};
pub use quality_result::{
    QUALITY_FLOOR_RESULT_CANONICAL_PROFILE, QualityCoverageItem, QualityCoverageResult,
    QualityCriterionResult, QualityExperimentBinding, QualityFloorResultSet, QualityProfileResult,
    QualityResultError, VerifiedQualityFloorResult, canonical_quality_floor_result_transcript,
    compute_quality_floor_result_digest, verify_quality_floor_result,
};
pub use quality_trial::{
    QUALITY_TRIAL_SET_CANONICAL_PROFILE, QualityTrialError, QualityTrialRecord, QualityTrialSet,
    QualityTrialVerificationEvidence, VerifiedQualityTrialSet,
    canonical_quality_trial_set_transcript, compute_quality_trial_set_digest,
    verify_quality_trial_set,
};
pub use quality_trial_configuration::{
    QualityTrialConfigurationError, VerifiedQualityTrialConfigurationBinding,
    verify_q07_trial_configuration_binding,
};
pub use regime::{
    REGIME_PIPELINE_CANONICAL_PROFILE, RegimeCapabilityRequirement, RegimeEvaluationCorpus,
    RegimeGradingContract, RegimePipelinePlan, RegimePlanError, RegimeReliabilityProtocol,
    SIX_REGIME_PLAN_CANONICAL_PROFILE, SixRegimeQualificationPlan, SpecialistRegime,
    canonical_regime_pipeline_transcript, canonical_six_regime_qualification_plan_transcript,
    compute_regime_pipeline_digest, compute_six_regime_qualification_plan_digest,
    validate_six_regime_qualification_plan,
};
pub use regime_capability::{
    REGIME_CAPABILITY_BINDING_CANONICAL_PROFILE, RegimeCapabilityBindingRecord,
    RegimeCapabilityError, VerifiedRegimeCapabilityConformance,
    canonical_regime_capability_binding_transcript, compute_regime_capability_binding_digest,
    verify_regime_capability_conformance,
};
pub use regime_evidence::{
    REGIME_EVIDENCE_CANONICAL_PROFILE, RegimeEvidenceError, RegimeEvidenceKind,
    RegimeExecutionEvidenceBundle, RegimeObservedEvidenceRecord, VerifiedRegimeExecutionEvidence,
    canonical_regime_observed_evidence_transcript, compute_regime_observed_evidence_digest,
    verify_regime_execution_evidence,
};
pub use regime_verification::{
    VerifiedRegimePipelineIdentity, VerifiedSixRegimeQualificationPlan,
    verify_six_regime_qualification_plan,
};
pub use stage_qualification::{
    S05_STAGE_QUALIFICATION_CANONICAL_PROFILE, S05StageQualificationError,
    S05StageQualificationRequest, VerifiedS05DomainCapabilities, verify_s05_stage_qualification,
};

/// Failure at the public capability-admission membrane. The inner modules keep
/// structural concerns separate, while this root gate makes content identity a
/// mandatory precondition instead of an optional caller habit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityGateError {
    Integrity(IntegrityError),
    IntegrityBindingMismatch,
    QualificationPlanIntegrity(QualificationPlanIntegrityError),
    Qualification(QualificationError),
    Availability(AvailabilityError),
    Catalog(CatalogError),
}

impl fmt::Display for CapabilityGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability gate rejected: {self:?}")
    }
}

/// Qualify an exact capability only after recomputing both the manifest and the
/// predeclared qualification-plan identities. The private raw qualification
/// routine is intentionally not re-exported.
pub fn qualify_capability(
    manifest: &CapabilityManifest,
    verified_integrity: &VerifiedManifestIntegrity,
    subject: &QualificationSubject,
    plan: &QualificationPlan,
    evidence: &[QualificationEvidenceRecord],
) -> Result<VerifiedCapabilityQualification, CapabilityGateError> {
    require_current_integrity(manifest, verified_integrity)?;
    qualification_plan::verify_qualification_plan(plan)
        .map_err(CapabilityGateError::QualificationPlanIntegrity)?;
    qualification::qualify_capability(manifest, subject, plan, evidence)
        .map_err(CapabilityGateError::Qualification)
}

/// Validate current operational availability only for the exact manifest whose
/// content identity is still recomputable now. This prevents a raw manifest
/// mutated after qualification from riding on an older verified subject.
pub fn verify_availability_snapshot(
    manifest: &CapabilityManifest,
    verified_integrity: &VerifiedManifestIntegrity,
    qualification: &VerifiedCapabilityQualification,
    snapshot: AvailabilitySnapshot,
) -> Result<VerifiedCapabilityAvailability, CapabilityGateError> {
    require_current_integrity(manifest, verified_integrity)?;
    availability::verify_availability_snapshot(manifest, qualification, snapshot)
        .map_err(CapabilityGateError::Availability)
}

/// Build a catalog only after every raw manifest assertion has been
/// independently recomputed. Qualified/available wrappers then remain exact
/// subject evidence rather than a way to bless an arbitrary digest string.
pub fn verify_catalog_snapshot(
    snapshot: CapabilityCatalogSnapshot,
) -> Result<VerifiedCapabilityCatalog, CapabilityGateError> {
    for entry in &snapshot.entries {
        integrity::verify_manifest_integrity(&entry.manifest)
            .map_err(CapabilityGateError::Integrity)?;
    }
    catalog::verify_catalog_snapshot(snapshot).map_err(CapabilityGateError::Catalog)
}

fn require_current_integrity(
    manifest: &CapabilityManifest,
    expected: &VerifiedManifestIntegrity,
) -> Result<(), CapabilityGateError> {
    let current =
        integrity::verify_manifest_integrity(manifest).map_err(CapabilityGateError::Integrity)?;
    if &current != expected {
        return Err(CapabilityGateError::IntegrityBindingMismatch);
    }
    Ok(())
}
